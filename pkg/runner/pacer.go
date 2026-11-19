package runner

import (
	"context"
	"errors"
	"syscall"
	"time"
)

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
// pacer is also loss-aware. When the send path reports kernel TX-buffer
// exhaustion (ENOBUFS/EAGAIN) the caller invokes onCongestion, which multiplicatively
// halves the effective rate so we stop overflowing the qdisc and dropping probes
// at the source. The rate then recovers additively back toward the configured
// ceiling, an AIMD loop similar to masscan/zmap rate adaptation.
//
// Not safe for concurrent use; it is owned by the single goroutine driving the
// fast sender.
type pacer struct {
	maxRate    int64
	minRate    int64
	rate       int64
	batch      int64
	window     time.Duration
	budget     int64
	next       time.Time
	lastAdjust time.Time
	// flush, when set, sends the packets queued in the caller's sendmmsg batch
	// at each window boundary, so they leave as one window's budget instead of
	// piling up into a 1024-packet line-rate burst at low rates. It returns
	// how many packets are still queued after a failed send.
	flush func() (pending int, err error)
}

// pacerRecoverEvery is how long the pacer waits between additive-increase steps
// while climbing back toward the configured rate after a backoff.
const pacerRecoverEvery = 250 * time.Millisecond

// newPacer returns a pacer limited to rate packets per second. A rate <= 0
// produces an unlimited pacer whose wait is a no-op.
func newPacer(rate int) *pacer {
	if rate <= 0 {
		return &pacer{}
	}
	p := &pacer{maxRate: int64(rate)}
	p.minRate = p.maxRate / 100
	if p.minRate < 1 {
		p.minRate = 1
	}
	p.setRate(p.maxRate)
	return p
}

// setRate recomputes the window/batch for a new effective rate and resets the
// in-window budget so the next wait re-paces against the new schedule.
func (p *pacer) setRate(rate int64) {
	if rate < 1 {
		rate = 1
	}
	p.rate = rate
	// ~100 windows per second: batch*window == 1s/rate, so the average rate is
	// exact regardless of the integer division below.
	p.batch = rate / 100
	if p.batch < 1 {
		p.batch = 1
	}
	p.window = time.Duration(float64(p.batch) / float64(rate) * float64(time.Second))
	p.budget = 0
}

// wait blocks as needed to keep the average send rate at or below the current
// effective packets per second, nudging the rate back up toward the configured
// ceiling once a recovery interval has elapsed since the last backoff.
// It returns false when ctx is cancelled, without admitting another packet.
func (p *pacer) wait(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	if p.maxRate <= 0 {
		return true
	}
	if p.budget > 0 {
		p.budget--
		return true
	}
	var pending int64
	if p.flush != nil {
		n, err := p.flush()
		if isCongestion(err) {
			p.onCongestion()
		}
		pending = int64(n)
	}
	now := time.Now()
	if p.next.IsZero() {
		p.next = now
	}
	if now.Before(p.next) {
		timer := time.NewTimer(p.next.Sub(now))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return false
		case <-timer.C:
		}
		now = p.next
	}
	if p.rate < p.maxRate && now.Sub(p.lastAdjust) >= pacerRecoverEvery {
		step := p.maxRate / 10
		if step < 1 {
			step = 1
		}
		nr := p.rate + step
		if nr > p.maxRate {
			nr = p.maxRate
		}
		p.lastAdjust = now
		p.setRate(nr)
	}
	p.next = now.Add(p.window)
	// Packets a failed flush kept queued go out with the next flush, so they
	// count against this window. When that count exceeds the batch the budget
	// goes negative, and the next wait retries the flush instead of granting
	// another full window on top of them.
	p.budget = p.batch - 1 - pending
	return ctx.Err() == nil
}

// onCongestion halves the effective rate after the kernel signals a full TX
// buffer. Backoffs are debounced to one per window so a burst of ENOBUFS from a
// single overfull batch does not collapse the rate to the floor.
func (p *pacer) onCongestion() {
	if p.maxRate <= 0 {
		return
	}
	now := time.Now()
	if !p.lastAdjust.IsZero() && now.Sub(p.lastAdjust) < p.window {
		return
	}
	nr := p.rate / 2
	if nr < p.minRate {
		nr = p.minRate
	}
	p.lastAdjust = now
	p.setRate(nr)
}

// isCongestion reports whether a send error means the kernel TX buffer/qdisc is
// full, i.e. we are sending faster than the host can drain and probes are being
// dropped at the source.
func isCongestion(err error) bool {
	return errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.EAGAIN)
}
