package runner

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectConcurrency(t *testing.T) {
	tests := []struct {
		name string
		rate int
		soft uint64
		want int
	}{
		{"unknown limit keeps rate", 1500, 0, 1500},
		{"limit well above rate keeps rate", 1500, 1048576, 1500},
		{"typical 1024 ulimit caps below rate", 1500, 1024, 1024 - fdLimitReserve},
		{"rate below available keeps rate", 200, 1024, 200},
		{"tiny limit floors at one", 1500, fdLimitReserve, 1},
		{"limit smaller than reserve floors at one", 1500, 16, 1},
		{"rate equal to available keeps rate", 1024 - fdLimitReserve, 1024, 1024 - fdLimitReserve},
		{"zero rate normalised to one", 0, 0, 1},
		{"huge limit never overflows", 1000, 1 << 62, 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, connectConcurrency(tt.rate, tt.soft))
		})
	}
}

func TestRaiseOpenFileLimitDoesNotLower(t *testing.T) {
	if runtime.GOOS == "windows" {
		require.Equal(t, uint64(0), raiseOpenFileLimit())
		return
	}
	before := raiseOpenFileLimit()
	require.Greater(t, before, uint64(0), "soft limit should be readable on unix")
	// Idempotent: a second call must not reduce the limit.
	after := raiseOpenFileLimit()
	require.GreaterOrEqual(t, after, before)
}
