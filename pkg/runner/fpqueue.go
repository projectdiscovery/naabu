package runner

import (
	"sync"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint"
)

// fpQueueMaxItems caps the in-memory backlog of pending service-detection
// targets. At ~hundreds of bytes per target this bounds the queue to a few tens
// of MB even on huge, high-yield scans. push applies backpressure at this
// ceiling instead of growing without limit.
const fpQueueMaxItems = 100_000

// fpQueue is a bounded, drop-free hand-off between the scan hot path and the
// (slower) service-detection workers.
//
// The original design fed a fixed buffered channel with a non-blocking send and
// a default: drop, so when discovery outpaced the fingerprint workers - exactly
// what the fast SYN path causes - open ports were silently dropped and -sV
// missed them. This queue never drops: a single forwarder goroutine drains into
// the engine. To avoid an unbounded backlog (and eventual OOM) when discovery
// sustainably outruns detection, push blocks once the backlog reaches
// maxItems and resumes as the forwarder drains, propagating backpressure to the
// scan instead of buffering everything in memory.
type fpQueue struct {
	mu       sync.Mutex
	notEmpty *sync.Cond
	notFull  *sync.Cond
	items    []fingerprint.Target
	maxItems int
	closed   bool
}

func newFpQueue() *fpQueue {
	q := &fpQueue{maxItems: fpQueueMaxItems}
	q.notEmpty = sync.NewCond(&q.mu)
	q.notFull = sync.NewCond(&q.mu)
	return q
}

// push appends a target, blocking only while the backlog is at the memory
// ceiling so nothing is ever dropped. Pushes after close are ignored.
func (q *fpQueue) push(t fingerprint.Target) {
	q.mu.Lock()
	for !q.closed && q.maxItems > 0 && len(q.items) >= q.maxItems {
		q.notFull.Wait()
	}
	if !q.closed {
		q.items = append(q.items, t)
		q.notEmpty.Signal()
	}
	q.mu.Unlock()
}

// close marks the queue done. pop will return the remaining items and then
// report ok=false once drained. Any pusher blocked on backpressure is released.
func (q *fpQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.notEmpty.Broadcast()
	q.notFull.Broadcast()
	q.mu.Unlock()
}

// pop blocks until an item is available, or returns ok=false when the queue is
// closed and fully drained.
func (q *fpQueue) pop() (fingerprint.Target, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.notEmpty.Wait()
	}
	if len(q.items) == 0 {
		return fingerprint.Target{}, false
	}
	t := q.items[0]
	q.items[0] = fingerprint.Target{}
	q.items = q.items[1:]
	q.notFull.Signal()
	return t, true
}
