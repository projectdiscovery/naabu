package runner

import (
	"sync"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint"
)

// fpQueue is an unbounded, drop-free hand-off between the scan hot path and the
// (slower) service-detection workers.
//
// The previous design fed a fixed buffered channel with a non-blocking send and
// a default: drop, so when discovery outpaced the fingerprint workers - exactly
// what the fast SYN path causes - open ports were silently dropped and -sV
// missed them. push never blocks the scan and never drops; a single forwarder
// goroutine drains into the engine, blocking only itself.
type fpQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []fingerprint.Target
	closed bool
}

func newFpQueue() *fpQueue {
	q := &fpQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// push appends a target. It returns immediately and is safe to call from the
// scan hot path. Pushes after close are ignored.
func (q *fpQueue) push(t fingerprint.Target) {
	q.mu.Lock()
	if !q.closed {
		q.items = append(q.items, t)
		q.cond.Signal()
	}
	q.mu.Unlock()
}

// close marks the queue done. pop will return the remaining items and then
// report ok=false once drained.
func (q *fpQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
}

// pop blocks until an item is available, or returns ok=false when the queue is
// closed and fully drained.
func (q *fpQueue) pop() (fingerprint.Target, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		return fingerprint.Target{}, false
	}
	t := q.items[0]
	q.items[0] = fingerprint.Target{}
	q.items = q.items[1:]
	return t, true
}
