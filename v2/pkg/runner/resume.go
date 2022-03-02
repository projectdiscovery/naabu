package runner

import (
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"os"
	"path/filepath"
	"sync"
)

// Default resume file
const defaultResumeFileName = "resume-cfg"

func DefaultResumeFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return defaultResumeFileName
	}
	return filepath.Join(home, ".config", "naabu", defaultResumeFileName)
}

// ResumeCfg contains the scan progression
type ResumeCfg struct {
	hm *hybrid.HybridMap
	sync.RWMutex
}

// NewResumeCfg creates a new scan progression structure
func NewResumeCfg() *ResumeCfg {
	cfg := &ResumeCfg{}
	var err error
	opts := hybrid.DefaultDiskOptions
	opts.Path = DefaultResumeFilePath()
	opts.Cleanup = false
	cfg.hm, err = hybrid.New(opts)
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}
	return cfg
}

// CleanupResumeConfig cleaning up the config file
func (resumeCfg *ResumeCfg) CleanupResumeConfig() {
	if fileutil.FolderExists(DefaultResumeFilePath()) {
		resumeCfg.hm.Close()
		os.RemoveAll(DefaultResumeFilePath())
	}
}
