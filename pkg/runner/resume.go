package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	permissionutil "github.com/projectdiscovery/utils/permission"
)

// Default resume file
const defaultResumeFileName = "resume.cfg"

// DefaultResumeFolderPath returns the default resume folder path
func DefaultResumeFolderPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return defaultResumeFileName
	}
	return filepath.Join(home, ".config", "naabu")
}

// DefaultResumeFilePath returns the default resume file full path
func DefaultResumeFilePath() string {
	return filepath.Join(DefaultResumeFolderPath(), defaultResumeFileName)
}

// ResumeCfg contains the scan progression
type ResumeCfg struct {
	sync.RWMutex
	Retry int   `json:"retry"`
	Seed  int64 `json:"seed"`
	Index int64 `json:"index"`
}

// NewResumeCfg creates a new scan progression structure
func NewResumeCfg() *ResumeCfg {
	return &ResumeCfg{}
}

// SaveResumeConfig to file
func (resumeCfg *ResumeCfg) SaveResumeConfig() error {
	resumeCfg.RLock()
	defer resumeCfg.RUnlock()

	data, err := json.MarshalIndent(resumeCfg, "", "\t")
	if err != nil {
		return err
	}
	resumeFolderPath := DefaultResumeFolderPath()
	if !fileutil.FolderExists(resumeFolderPath) {
		_ = fileutil.CreateFolder(DefaultResumeFolderPath())
	}

	return os.WriteFile(DefaultResumeFilePath(), data, permissionutil.ConfigFilePermission)
}

// ConfigureResume read the resume config file
func (resumeCfg *ResumeCfg) ConfigureResume() error {
	resumeCfg.RLock()
	defer resumeCfg.RUnlock()

	gologger.Info().Msg("Resuming from save checkpoint")
	file, err := os.ReadFile(DefaultResumeFilePath())
	if err != nil {
		return err
	}
	err = json.Unmarshal([]byte(file), &resumeCfg)
	if err != nil {
		return err
	}
	return nil
}

// ShouldSaveResume file
func (resumeCfg *ResumeCfg) ShouldSaveResume() bool {
	return true
}

// CleanupResumeConfig cleaning up the config file
func (resumeCfg *ResumeCfg) CleanupResumeConfig() {
	if fileutil.FileExists(DefaultResumeFilePath()) {
		os.Remove(DefaultResumeFilePath())
	}
}
