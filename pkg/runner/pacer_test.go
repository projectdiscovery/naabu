package runner

import (
	"syscall"
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

// TestPacerCongestionHalvesRate ensures a congestion signal multiplicatively
// reduces the effective rate down to but not below the floor.
func TestPacerCongestionHalvesRate(t *testing.T) {
	p := newPacer(100000)
	require.EqualValues(t, 100000, p.rate)

	// Each backoff must wait out a window; force the debounce open between calls.
	for want := int64(50000); want >= p.minRate; want /= 2 {
		p.lastAdjust = time.Time{}
		p.onCongestion()
		require.EqualValues(t, want, p.rate)
		if want == p.minRate {
			break
		}
	}

	// Further backoffs clamp at the floor, never zero/negative.
	p.lastAdjust = time.Time{}
	p.onCongestion()
	require.GreaterOrEqual(t, p.rate, p.minRate)
	require.Equal(t, p.minRate, p.rate)
}

// TestPacerCongestionDebounced ensures a burst of congestion signals inside one
// window only backs off once.
func TestPacerCongestionDebounced(t *testing.T) {
	p := newPacer(100000)
	p.onCongestion()
	first := p.rate
	require.EqualValues(t, 50000, first)
	// Immediate repeats within the same window are ignored.
	p.onCongestion()
	p.onCongestion()
	require.EqualValues(t, first, p.rate)
}

// TestPacerRecoversToCeiling ensures the rate climbs back to the configured
// ceiling after backoff once recovery intervals elapse.
func TestPacerRecoversToCeiling(t *testing.T) {
	p := newPacer(10000)
	p.setRate(1000)
	require.EqualValues(t, 1000, p.rate)

	// Drive many windows; each wait that crosses a recovery interval nudges the
	// rate up by maxRate/10. Backdate lastAdjust so recovery is eligible.
	for i := 0; i < 100 && p.rate < p.maxRate; i++ {
		p.lastAdjust = time.Now().Add(-pacerRecoverEvery)
		p.budget = 0
		p.next = time.Time{}
		p.wait()
	}
	require.EqualValues(t, p.maxRate, p.rate, "rate must recover to the configured ceiling")
}

// TestPacerCongestionNoopUnlimited ensures congestion handling is inert for an
// unlimited pacer.
func TestPacerCongestionNoopUnlimited(t *testing.T) {
	p := newPacer(0)
	p.onCongestion()
	require.EqualValues(t, 0, p.rate)
	p.wait() // must remain a no-op
}

func TestIsCongestion(t *testing.T) {
	require.True(t, isCongestion(syscall.ENOBUFS))
	require.True(t, isCongestion(syscall.EAGAIN))
	require.False(t, isCongestion(syscall.ECONNREFUSED))
	require.False(t, isCongestion(nil))
}
