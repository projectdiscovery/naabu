package runner

import (
	"context"
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
		p.wait(context.Background())
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
		p.wait(context.Background())
	}
	elapsed := time.Since(start)

	require.GreaterOrEqual(t, elapsed, 400*time.Millisecond, "pacer must throttle to near the configured rate")
	require.Less(t, elapsed, 900*time.Millisecond, "pacer must not be drastically slower than the configured rate")
}

// TestPacerFlushesEachWindow ensures packets queued in a sendmmsg batch leave
// at every window boundary. Without it a low rate filled the 1024-packet batch
// for seconds and then sent it as one line-rate burst that small queues drop.
func TestPacerFlushesEachWindow(t *testing.T) {
	const rate = 1000 // batch of 10 per 10ms window
	p := newPacer(rate)
	queued, maxQueued, flushes := 0, 0, 0
	p.flush = func() (int, error) {
		flushes++
		queued = 0
		return 0, nil
	}
	for i := 0; i < 100; i++ {
		p.wait(context.Background())
		queued++
		maxQueued = max(maxQueued, queued)
	}
	require.LessOrEqual(t, maxQueued, 10, "a burst must not exceed one window's budget")
	require.GreaterOrEqual(t, flushes, 9)
}

// TestPacerFlushCongestionBacksOff ensures a full TX buffer reported by the
// window flush halves the rate like a failed send does.
func TestPacerFlushCongestionBacksOff(t *testing.T) {
	p := newPacer(10000)
	p.flush = func() (int, error) { return 0, syscall.ENOBUFS }
	for i := 0; i < 300; i++ {
		p.wait(context.Background())
	}
	require.Less(t, p.rate, int64(10000))
}

// TestPacerChargesRetainedPackets ensures packets a failed flush kept queued
// count against the next window, so a retry does not send them on top of a
// full new budget.
func TestPacerChargesRetainedPackets(t *testing.T) {
	p := newPacer(1000) // batch of 10 per window
	queued, failed, maxSent := 0, false, 0
	p.flush = func() (int, error) {
		if queued >= 10 && !failed {
			failed = true
			return queued, syscall.ENOBUFS
		}
		maxSent = max(maxSent, queued)
		queued = 0
		return 0, nil
	}
	for i := 0; i < 60; i++ {
		p.wait(context.Background())
		queued++
	}
	require.True(t, failed)
	// The 10 retained packets plus the one admitted while they were pending.
	require.LessOrEqual(t, maxSent, 11)
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
		p.wait(context.Background())
	}
	require.EqualValues(t, p.maxRate, p.rate, "rate must recover to the configured ceiling")
}

// TestPacerCongestionNoopUnlimited ensures congestion handling is inert for an
// unlimited pacer.
func TestPacerCongestionNoopUnlimited(t *testing.T) {
	p := newPacer(0)
	p.onCongestion()
	require.EqualValues(t, 0, p.rate)
	p.wait(context.Background()) // must remain a no-op
}

func TestPacerWaitStopsWhenContextCancelled(t *testing.T) {
	p := newPacer(1) // the second wait sleeps for about a second
	require.True(t, p.wait(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() {
		done <- p.wait(ctx)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case ok := <-done:
		require.False(t, ok, "a cancelled context must not admit another packet")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("wait must return when the context is cancelled")
	}
}

func TestIsCongestion(t *testing.T) {
	require.True(t, isCongestion(syscall.ENOBUFS))
	require.True(t, isCongestion(syscall.EAGAIN))
	require.False(t, isCongestion(syscall.ECONNREFUSED))
	require.False(t, isCongestion(nil))
}

// IPv6 and UDP probes in the fast scan must spend the SYN pacer's budget.
// Falling back to the general limiter gives them a second, independent rate.
func TestRawWaitSharesTheFastPacer(t *testing.T) {
	p := newPacer(1000)
	p.budget = 3

	ctx := context.Background()
	require.True(t, rawWait(p, func(context.Context) bool { t.Fatal("raw probe used the limiter"); return false })(ctx))
	require.Equal(t, int64(2), p.budget)

	called := false
	require.True(t, rawWait(nil, func(context.Context) bool { called = true; return true })(ctx))
	require.True(t, called)
}
