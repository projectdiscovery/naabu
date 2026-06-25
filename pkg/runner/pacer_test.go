package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestPacerUnlimited ensures a non-positive rate never blocks.
func TestPacerUnlimited(t *testing.T) {
	p := newPacer(0)
	start := time.Now()
	for i := 0; i < 100000; i++ {
		p.wait()
	}
	require.Less(t, time.Since(start), 50*time.Millisecond, "unlimited pacer must not block")
}

// TestPacerHonorsRate ensures the average send rate tracks the configured pps:
// sending rate/2 packets at rate pps should take roughly half a second, and not
// finish near-instantly (which would mean the limiter is a no-op).
func TestPacerHonorsRate(t *testing.T) {
	const rate = 2000
	p := newPacer(rate)

	start := time.Now()
	for i := 0; i < rate/2; i++ {
		p.wait()
	}
	elapsed := time.Since(start)

	require.GreaterOrEqual(t, elapsed, 400*time.Millisecond, "pacer must throttle to near the configured rate")
	require.Less(t, elapsed, 900*time.Millisecond, "pacer must not be drastically slower than the configured rate")
}

// TestPacerExactRateViaWindow verifies the average rate is preserved even when
// rate/100 truncates (the window compensates).
func TestPacerExactRateViaWindow(t *testing.T) {
	p := newPacer(199)
	require.EqualValues(t, 1, p.batch)
	// window == batch/rate seconds, so batch/window == rate exactly
	got := float64(p.batch) / p.window.Seconds()
	require.InDelta(t, 199, got, 1.0, "effective rate must match configured rate")
}
