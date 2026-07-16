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
