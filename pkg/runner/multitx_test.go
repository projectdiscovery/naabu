package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestForEachWorkerIndexCoversSpaceOnce verifies the strided worker partition
// visits every index in [0,rng) exactly once across all workers.
func TestForEachWorkerIndexCoversSpaceOnce(t *testing.T) {
	for _, workers := range []int{1, 2, 3, 4, 7} {
		for _, rng := range []int64{0, 1, 5, 100, 1001} {
			seen := make([]int, rng)
			for w := 0; w < workers; w++ {
				forEachWorkerIndex(w, workers, rng, func(i int64) bool {
					seen[i]++
					return true
				})
			}
			for i := int64(0); i < rng; i++ {
				require.Equalf(t, 1, seen[i], "workers=%d rng=%d index=%d", workers, rng, i)
			}
		}
	}
}

func TestForEachWorkerIndexClampsWorkers(t *testing.T) {
	var count int
	forEachWorkerIndex(0, 0, 10, func(int64) bool {
		count++
		return true
	})
	require.Equal(t, 10, count, "workers<1 must be treated as a single worker")
}

func TestForEachWorkerIndexEarlyStop(t *testing.T) {
	var count int
	forEachWorkerIndex(0, 1, 100, func(int64) bool {
		count++
		return count < 5
	})
	require.Equal(t, 5, count, "returning false must stop the walk")
}

func TestRateForWorkerPreservesGlobalRate(t *testing.T) {
	for _, tc := range []struct {
		rate, workers int
	}{
		{1, 1},
		{10, 3},
		{10001, 4},
	} {
		total := 0
		for worker := 0; worker < tc.workers; worker++ {
			workerRate := rateForWorker(tc.rate, tc.workers, worker)
			require.GreaterOrEqual(t, workerRate, 1)
			total += workerRate
		}
		require.Equal(t, tc.rate, total)
	}
	require.Zero(t, rateForWorker(0, 4, 0), "unlimited rate must remain unlimited")
}

func TestEffectiveTxWorkers(t *testing.T) {
	require.Equal(t, 1, effectiveTxWorkers(0, 100, 10000, true))
	require.Equal(t, 2, effectiveTxWorkers(8, 2, 10000, true), "rate must cap workers")
	require.Equal(t, 1, effectiveTxWorkers(8, 10000, synBatchSize, true), "one batch needs one worker")
	require.Equal(t, 2, effectiveTxWorkers(8, 10000, synBatchSize+1, true))
	require.Equal(t, 3, effectiveTxWorkers(8, 10000, 3, false), "non-batched workers are capped by probes")
	require.Equal(t, 8, effectiveTxWorkers(8, 10000, 0, true), "empty range preserves validated configuration")
}

// TestTxWorkersShardComposition confirms multi-worker striping composes with
// distributed sharding: union of (worker stripe ∩ shard) equals the shard slice,
// disjointly.
func TestTxWorkersShardComposition(t *testing.T) {
	const workers, total, shard = 3, 2, 1
	const rng = int64(600)

	o := &Options{Shard: shard, ShardTotal: total}
	seen := make([]int, rng)
	for w := 0; w < workers; w++ {
		forEachWorkerIndex(w, workers, rng, func(i int64) bool {
			if o.inShard(i) {
				seen[i]++
			}
			return true
		})
	}
	for i := int64(0); i < rng; i++ {
		want := 0
		if o.inShard(i) {
			want = 1
		}
		require.Equalf(t, want, seen[i], "index %d", i)
	}
}
