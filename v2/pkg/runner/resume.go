package runner

import (
	"encoding/json"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
)

// Default resume file
const defaultResumeFileName = "resume.cfg"

func DefaultResumeFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return defaultResumeFileName
	}
	return filepath.Join(home, ".config", "naabu", defaultResumeFileName)
}

// ResumeCfg contains the scan progression
type ResumeCfg struct {
	sync.RWMutex
	ResumeFrom map[string]*ResumeInfo `json:"resumeFrom"`
	Current    map[string]*ResumeInfo `json:"-"`
}

// InFlightResume
type InFlightResume struct {
	Completed bool `json:"completed"`
}

// ResumeInfo
type ResumeInfo struct {
	sync.RWMutex
	InFlight map[uint32]InFlightResume `json:"inFlight"`
}

// NewResumeCfg creates a new scan progression structure
func NewResumeCfg() *ResumeCfg {
	return &ResumeCfg{
		ResumeFrom: make(map[string]*ResumeInfo),
		Current:    make(map[string]*ResumeInfo),
	}
}

// SaveResumeConfig to file
func (resumeCfg *ResumeCfg) SaveResumeConfig() error {
	newresumeCfg := NewResumeCfg()
	newresumeCfg.ResumeFrom = resumeCfg.Current
	data, _ := json.MarshalIndent(newresumeCfg, "", "\t")
	return os.WriteFile(DefaultResumeFilePath(), data, os.ModePerm)
}

// ConfigureResume read the resume config file
func (resumeCfg *ResumeCfg) ConfigureResume() error {
	gologger.Info().Msg("Resuming from save checkpoint")
	file, err := ioutil.ReadFile(DefaultResumeFilePath())
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
