package timeout

import "time"

func WithProxy(timeout time.Duration) time.Duration {
	return timeout * 2
}
