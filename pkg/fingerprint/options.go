package fingerprint

import "time"

const (
	DefaultWorkers        = 25
	DefaultTimeout        = 5 * time.Second
	DefaultConnectTimeout = 3 * time.Second
)

// Option configures the Engine.
type Option func(*Engine)

func WithWorkers(n int) Option {
	return func(e *Engine) {
		if n > 0 {
			e.workers = n
		}
	}
}

func WithTimeout(d time.Duration) Option {
	return func(e *Engine) {
		if d > 0 {
			e.timeout = d
		}
	}
}

func WithFastMode(fast bool) Option {
	return func(e *Engine) {
		e.fastMode = fast
	}
}

// WithDialer sets a custom dialer for TCP connections (e.g. SOCKS5 proxy).
func WithDialer(d DialFunc) Option {
	return func(e *Engine) {
		e.dialer = d
	}
}

// WithIntensity sets the maximum probe rarity to use (1-9, default 7).
func WithIntensity(level int) Option {
	return func(e *Engine) {
		if level >= 1 && level <= 9 {
			e.intensityMax = level
		}
	}
}
