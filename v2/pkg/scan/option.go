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
	OutputCdn   bool
	ExcludedIps []string
	Proxy       string
	ProxyAuth   string
	Stream      bool
}
