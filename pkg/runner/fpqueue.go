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

// fpQueue is a bounded, drop-free hand-off between the scan result path and the
// (slower) service-detection workers.
//
// The original design fed a fixed buffered channel with a non-blocking send and
// a default: drop, so when discovery outpaced the fingerprint workers - exactly
// what the fast SYN path causes - open ports were silently dropped and -sV
// missed them. This queue never drops: a single forwarder goroutine drains into
// the engine. To avoid an unbounded backlog (and eventual OOM) when discovery
// sustainably outruns detection, push blocks once the backlog reaches
// maxItems and resumes as the forwarder drains, propagating backpressure to the
// caller (typically TCPResultWorker via onReceive) instead of buffering
// everything in memory.
type fpQueue struct {
	mu       sync.Mutex
	notEmpty *sync.Cond
	notFull  *sync.Cond
	items    []fingerprint.Target
	head     int
	maxItems int
	closed   bool
}

func newFpQueue() *fpQueue {
	q := &fpQueue{maxItems: fpQueueMaxItems}
	q.notEmpty = sync.NewCond(&q.mu)
	q.notFull = sync.NewCond(&q.mu)
	return q
}

func (q *fpQueue) lenLocked() int {
	return len(q.items) - q.head
}

// push appends a target, blocking only while the backlog is at the memory
// ceiling so nothing is ever dropped. Pushes after close are ignored.
func (q *fpQueue) push(t fingerprint.Target) {
	q.mu.Lock()
	for !q.closed && q.maxItems > 0 && q.lenLocked() >= q.maxItems {
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
// closed and fully drained. Uses a head offset so pops are O(1); the underlying
// slice is compacted when half of it is drained.
func (q *fpQueue) pop() (fingerprint.Target, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.lenLocked() == 0 && !q.closed {
		q.notEmpty.Wait()
	}
	if q.lenLocked() == 0 {
		return fingerprint.Target{}, false
	}
	t := q.items[q.head]
	q.items[q.head] = fingerprint.Target{}
	q.head++
	if q.head > 1024 && q.head*2 >= len(q.items) {
		q.items = append([]fingerprint.Target(nil), q.items[q.head:]...)
		q.head = 0
	}
	q.notFull.Signal()
	return t, true
}
