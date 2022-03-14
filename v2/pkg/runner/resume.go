package runner

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
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
// type ResumeCfg struct {
// 	sync.RWMutex
// 	Retry int   `json:"retry"`
// 	Seed  int64 `json:"seed"`
// 	Index int64 `json:"index"`
// }
type ResumeCfg struct {
	sync.RWMutex
	InFlight map[string]InFlight
}
type InFlight struct {
	Retry int   `json:"retry"`
	Seed  int64 `json:"seed"`
	Index int64 `json:"index"`
}

func (r *ResumeCfg) GetInFlightItem(key string) InFlight {
	item := InFlight{}
	var found bool
	if item, found = r.InFlight[key]; found {
		return item
	}
	r.InFlight[key] = item
	return item
}

// NewResumeCfg creates a new scan progression structure
func NewResumeCfg() *ResumeCfg {
	return &ResumeCfg{}
}

// SaveResumeConfig to file
func (resumeCfg *ResumeCfg) SaveResumeConfig() error {
	data, _ := json.MarshalIndent(resumeCfg, "", "\t")
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
