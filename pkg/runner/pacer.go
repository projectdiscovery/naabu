package runner

import "time"

// pacer is a low-overhead, single-goroutine rate limiter for the hot SYN send
// path. The shared ratelimit.Limiter delivers one token per packet over a
// channel served by a background goroutine, so every packet pays a goroutine
// handoff and the budget is released in a burst on each interval tick. On the
// fast sender that channel round-trip dominates once the rate climbs past a few
// tens of thousands of packets per second.
//
// pacer instead hands out a local integer budget: the per-packet cost is a
// single decrement, and the clock is consulted (and the goroutine possibly
// parked) only once per window. Windows are ~10ms so bursts stay within ~1% of
// the configured rate while keeping syscalls/sleeps rare.
//
// Not safe for concurrent use; it is owned by the single goroutine driving the
// fast sender.
type pacer struct {
	rate   int64
	batch  int64
	window time.Duration
	budget int64
	next   time.Time
}

// newPacer returns a pacer limited to rate packets per second. A rate <= 0
// produces an unlimited pacer whose wait is a no-op.
func newPacer(rate int) *pacer {
	if rate <= 0 {
		return &pacer{}
	}
	// ~100 windows per second: batch*window == 1s/rate, so the average rate is
	// exact regardless of the integer division below.
	batch := int64(rate) / 100
	if batch < 1 {
		batch = 1
	}
	window := time.Duration(float64(batch) / float64(rate) * float64(time.Second))
	return &pacer{rate: int64(rate), batch: batch, window: window}
}

// wait blocks as needed to keep the average send rate at or below the
// configured packets per second.
func (p *pacer) wait() {
	if p.rate <= 0 {
		return
	}
	if p.budget > 0 {
		p.budget--
		return
	}
	now := time.Now()
	if p.next.IsZero() {
		p.next = now
	}
	if now.Before(p.next) {
		time.Sleep(p.next.Sub(now))
		now = p.next
	}
	p.next = now.Add(p.window)
	p.budget = p.batch - 1
}
