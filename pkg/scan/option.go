package scan

import "time"

type Options struct {
	Timeout time.Duration
	Retries int
	Rate    int
	Debug   bool
}
