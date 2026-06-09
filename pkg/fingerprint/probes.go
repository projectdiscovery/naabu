package fingerprint

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	probeFileName = "nmap-service-probes"

	// DefaultProbeUpdateURL is the upstream source used to refresh the managed
	// local probe cache.
	DefaultProbeUpdateURL = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes"

	// EmbeddedProbeSource is the source label returned when the built-in copy is used.
	EmbeddedProbeSource = "embedded:nmap-service-probes"

	maxProbeDownloadSize = 16 << 20
)

var (
	//go:embed assets/nmap-service-probes.gz
	embeddedNmapServiceProbesGzip []byte

	errProbeDownloadTooLarge = errors.New("probe download exceeded maximum size")
	probeCachePathOverride   string
	probeUpdateURLOverride   string
)

// ParseProbeSource parses a custom nmap-service-probes path when one is
// supplied. With an empty path it falls back to the managed cache, the embedded
// database, and finally any local nmap installation discovered on disk.
func ParseProbeSource(path string) (*ProbeDB, string, error) {
	if path != "" {
		db, err := ParseProbeFile(path)
		return db, path, err
	}
	return ParseDefaultProbeDB()
}

// ParseDefaultProbeDB parses the best available default probe database.
func ParseDefaultProbeDB() (*ProbeDB, string, error) {
	if cachePath, err := DefaultProbeCachePath(); err == nil {
		if _, statErr := os.Stat(cachePath); statErr == nil {
			if db, parseErr := ParseProbeFile(cachePath); parseErr == nil {
				return db, cachePath, nil
			}
		}
	}

	if db, err := ParseEmbeddedProbes(); err == nil {
		return db, EmbeddedProbeSource, nil
	}

	return nil, "", errors.New("no usable nmap-service-probes database found")
}

// EmbeddedProbeData returns the decompressed built-in nmap-service-probes data.
func EmbeddedProbeData() ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(embeddedNmapServiceProbesGzip))
	if err != nil {
		return nil, err
	}
	defer zr.Close() //nolint:errcheck

	data, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ParseEmbeddedProbes parses the built-in nmap-service-probes database.
func ParseEmbeddedProbes() (*ProbeDB, error) {
	data, err := EmbeddedProbeData()
	if err != nil {
		return nil, err
	}
	return ParseProbes(bytes.NewReader(data))
}

// DefaultProbeCachePath returns the managed user-writable cache path used for
// downloaded service probes.
func DefaultProbeCachePath() (string, error) {
	if probeCachePathOverride != "" {
		return probeCachePathOverride, nil
	}
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "naabu", probeFileName), nil
}

// UpdateDefaultProbes refreshes the managed probe cache. Downloaded content is
// parsed before being committed so a bad upstream response cannot poison future
// service detection runs. The returned boolean is true when the cache was
// actually replaced.
func UpdateDefaultProbes(ctx context.Context) (string, bool, error) {
	cachePath, err := DefaultProbeCachePath()
	if err != nil {
		return "", false, err
	}

	updateURL := DefaultProbeUpdateURL
	if probeUpdateURLOverride != "" {
		updateURL = probeUpdateURLOverride
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, updateURL, nil)
	if err != nil {
		return "", false, err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("download service probes: unexpected status %s", resp.Status)
	}

	limited := io.LimitReader(resp.Body, maxProbeDownloadSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", false, err
	}
	if len(data) > maxProbeDownloadSize {
		return "", false, errProbeDownloadTooLarge
	}
	db, err := ParseProbes(bytes.NewReader(data))
	if err != nil {
		return "", false, fmt.Errorf("downloaded service probes failed validation: %w", err)
	}
	if !validProbeDB(db) {
		return "", false, errors.New("downloaded service probes failed validation: no usable probes found")
	}

	if err := os.MkdirAll(filepath.Dir(cachePath), 0700); err != nil {
		return "", false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(cachePath), probeFileName+".*.tmp")
	if err != nil {
		return "", false, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) //nolint:errcheck

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", false, err
	}
	if err := tmp.Close(); err != nil {
		return "", false, err
	}
	if err := os.Rename(tmpPath, cachePath); err != nil {
		return "", false, err
	}

	return cachePath, true, nil
}

func validProbeDB(db *ProbeDB) bool {
	if db == nil || len(db.Probes) == 0 {
		return false
	}
	for _, probe := range db.Probes {
		if probe != nil && probe.Name == "NULL" {
			return true
		}
	}
	return false
}
