package runner

import (
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint"
	"github.com/stretchr/testify/require"
)

// TestFpQueueNoDropPreservesOrder is the regression guard for the silent -sV
// drop: every pushed target must come back out, in FIFO order, even though the
// previous design dropped under load.
func TestFpQueueNoDropPreservesOrder(t *testing.T) {
	q := newFpQueue()
	const n = 10000

	var got []int
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			tgt, ok := q.pop()
			if !ok {
				return
			}
			got = append(got, tgt.Port)
		}
	}()

	for i := 0; i < n; i++ {
		q.push(fingerprint.Target{Port: i})
	}
	q.close()
	<-done

	require.Len(t, got, n, "no target may be dropped")
	for i := 0; i < n; i++ {
		require.Equal(t, i, got[i], "FIFO order must be preserved")
	}
}

// TestFpQueueConcurrentPushNoDrop mirrors real usage: onReceive can be called
// from many scan goroutines at once. Run with -race.
func TestFpQueueConcurrentPushNoDrop(t *testing.T) {
	q := newFpQueue()
	const producers = 8
	const perProducer = 2000

	total := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, ok := q.pop(); !ok {
				return
			}
			total++
		}
	}()

	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				q.push(fingerprint.Target{Port: i})
			}
		}()
	}
	wg.Wait()
	q.close()
	<-done

	require.Equal(t, producers*perProducer, total, "all concurrent pushes must be delivered")
}

// TestFpQueuePushAfterCloseIgnored ensures a late push cannot panic or wake a
// finished consumer.
func TestFpQueuePushAfterCloseIgnored(t *testing.T) {
	q := newFpQueue()
	q.close()
	q.push(fingerprint.Target{Port: 1})
	_, ok := q.pop()
	require.False(t, ok, "closed-and-empty queue must report drained")
}

// TestFpQueueBackpressureBounded verifies the backlog never exceeds the cap
// while a slow consumer drains, yet every item is still delivered (no drop).
func TestFpQueueBackpressureBounded(t *testing.T) {
	q := newFpQueue()
	q.maxItems = 8
	const n = 200

	var maxLen int
	got := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			q.mu.Lock()
			if l := len(q.items); l > maxLen {
				maxLen = l
			}
			q.mu.Unlock()
			tgt, ok := q.pop()
			if !ok {
				return
			}
			_ = tgt
			got++
			time.Sleep(time.Millisecond)
		}
	}()

	for i := 0; i < n; i++ {
		q.push(fingerprint.Target{Port: i})
	}
	q.close()
	<-done

	require.Equal(t, n, got, "every pushed target must be delivered")
	require.LessOrEqual(t, maxLen, q.maxItems, "backlog must stay within the cap")
}
