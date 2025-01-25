package limits

import "time"

func TimeoutWithProxy(timeout time.Duration) time.Duration {
	return timeout * 2
}
