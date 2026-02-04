package runner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

// ScanHistory tracks previously scanned targets
type ScanHistory struct {
	mutex        sync.RWMutex
	filePath     string
	format       string
	scope        string
	ttl          time.Duration
	entries      map[string]*ScanEntry
	existUnsaved bool
}

// ScanEntry represents a single scan record
type ScanEntry struct {
	Target    string    `json:"target"`
	IP        string    `json:"ip,omitempty"`
	FirstScan time.Time `json:"first_scan"`
	LastScan  time.Time `json:"last_scan"`
	ScanCount int       `json:"scan_count"`
}

// NewScanHistory creates a new scan history tracker
func NewScanHistory(filePath, format, scope string, ttl time.Duration) (*ScanHistory, error) {
	sh := &ScanHistory{
		filePath: filePath,
		format:   format,
		scope:    scope,
		ttl:      ttl,
		entries:  make(map[string]*ScanEntry),
	}

	if err := sh.Load(); err != nil {
		return nil, err
	}

	return sh, nil
}

// IsScanned checks if a target was previously scanned
func (sh *ScanHistory) IsScanned(target string) bool {
	sh.mutex.RLock()
	defer sh.mutex.RUnlock()

	entry, exists := sh.entries[target]
	if !exists {
		return false
	}

	// Check TTL
	if sh.ttl > 0 && time.Since(entry.LastScan) > sh.ttl {
		return false // TTL expired, need rescan
	}

	return true
}

// Record adds a target to scan history (without immediate save)
func (sh *ScanHistory) Record(target, ip string) error {
	sh.mutex.Lock()
	defer sh.mutex.Unlock()

	now := time.Now()
	if entry, exists := sh.entries[target]; exists {
		entry.LastScan = now
		entry.ScanCount++
	} else {
		sh.entries[target] = &ScanEntry{
			Target:    target,
			IP:        ip,
			FirstScan: now,
			LastScan:  now,
			ScanCount: 1,
		}
	}

	sh.existUnsaved = true
	return nil
}

// Load reads scan history from disk
func (sh *ScanHistory) Load() error {
	if !fileutil.FileExists(sh.filePath) {
		return nil // No history file yet, that's fine
	}

	file, err := os.Open(sh.filePath)
	if err != nil {
		return fmt.Errorf("could not open scan history file: %w", err)
	}
	defer file.Close()

	switch sh.format {
	case "json":
		return sh.loadJSON(file)
	case "txt", "":
		return sh.loadTXT(file)
	default:
		return fmt.Errorf("unsupported format: %s", sh.format)
	}
}

// Save writes scan history to disk
func (sh *ScanHistory) Save() error {
	sh.mutex.Lock()
	defer sh.mutex.Unlock()

	if !sh.existUnsaved {
		return nil // no changes to save
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(sh.filePath)
	if dir != "" && dir != "." && !fileutil.FolderExists(dir) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("could not create directory: %w", err)
		}
	}

	file, err := os.Create(sh.filePath)
	if err != nil {
		return fmt.Errorf("could not create scan history file: %w", err)
	}
	defer file.Close()

	var saveErr error
	switch sh.format {
	case "json":
		saveErr = sh.saveJSON(file)
	case "txt", "":
		saveErr = sh.saveTXT(file)
	default:
		saveErr = fmt.Errorf("unsupported format: %s", sh.format)
	}

	if saveErr == nil {
		sh.existUnsaved = false
	}

	return saveErr
}

// loadJSON reads scan history from JSON format
func (sh *ScanHistory) loadJSON(file *os.File) error {
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&sh.entries); err != nil {
		return fmt.Errorf("could not decode JSON: %w", err)
	}
	return nil
}

// saveJSON writes scan history to JSON format
func (sh *ScanHistory) saveJSON(file *os.File) error {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(sh.entries); err != nil {
		return fmt.Errorf("could not encode JSON: %w", err)
	}
	return nil
}

// loadTXT reads scan history from text format
// Format: target|ip|firstscan|lastscan|scancount
func (sh *ScanHistory) loadTXT(file *os.File) error {
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		parts := strings.Split(line, "|")
		if len(parts) != 5 {
			gologger.Debug().Msgf("Skipping invalid line %d in scan history: %s\n", lineNum, line)
			continue
		}

		firstScan, err := time.Parse(time.RFC3339, parts[2])
		if err != nil {
			gologger.Debug().Msgf("Invalid first scan time on line %d: %s\n", lineNum, err)
			continue
		}

		lastScan, err := time.Parse(time.RFC3339, parts[3])
		if err != nil {
			gologger.Debug().Msgf("Invalid last scan time on line %d: %s\n", lineNum, err)
			continue
		}

		var scanCount int
		if _, err := fmt.Sscanf(parts[4], "%d", &scanCount); err != nil {
			gologger.Debug().Msgf("Invalid scan count on line %d: %s\n", lineNum, err)
			continue
		}

		sh.entries[parts[0]] = &ScanEntry{
			Target:    parts[0],
			IP:        parts[1],
			FirstScan: firstScan,
			LastScan:  lastScan,
			ScanCount: scanCount,
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading scan history: %w", err)
	}

	return nil
}

// saveTXT writes scan history to text format
// Format: target|ip|firstscan|lastscan|scancount
func (sh *ScanHistory) saveTXT(file *os.File) error {
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write header comment
	if _, err := fmt.Fprintf(writer, "# Naabu Scan History\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "# Format: target|ip|firstscan|lastscan|scancount\n"); err != nil {
		return err
	}

	for _, entry := range sh.entries {
		line := fmt.Sprintf("%s|%s|%s|%s|%d\n",
			entry.Target,
			entry.IP,
			entry.FirstScan.Format(time.RFC3339),
			entry.LastScan.Format(time.RFC3339),
			entry.ScanCount,
		)
		if _, err := writer.WriteString(line); err != nil {
			return fmt.Errorf("could not write entry: %w", err)
		}
	}

	return nil
}
