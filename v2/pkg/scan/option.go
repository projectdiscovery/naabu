package scan

import (
	"time"
)

// Options of the scan
type Options struct {
	Timeout     time.Duration
	Retries     int
	Rate        int
	Debug       bool
	ExcludeCdn  bool
	ExcludedIps []string
	Proxy       string
	Stream      bool
}
