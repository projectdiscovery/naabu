package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseShard(t *testing.T) {
	idx, total, err := parseShard("2/4")
	require.NoError(t, err)
	require.Equal(t, 2, idx)
	require.Equal(t, 4, total)

	idx, total, err = parseShard(" 1 / 3 ")
	require.NoError(t, err)
	require.Equal(t, 1, idx)
	require.Equal(t, 3, total)
}

func TestParseShardErrors(t *testing.T) {
	for _, s := range []string{"", "4", "1/0", "0/4", "5/4", "a/4", "1/b", "-1/4"} {
		_, _, err := parseShard(s)
		require.Error(t, err, "expected error for %q", s)
	}
}

// TestInShardPartitionsCompletelyAndDisjointly verifies every index in the
// space is claimed by exactly one shard, with no gaps or overlaps.
func TestInShardPartitionsCompletelyAndDisjointly(t *testing.T) {
	const total = 4
	const space = int64(1000)

	claims := make([]int, space)
	for shard := 1; shard <= total; shard++ {
		o := &Options{Shard: shard, ShardTotal: total}
		for i := int64(0); i < space; i++ {
			if o.inShard(i) {
				claims[i]++
			}
		}
	}
	for i := int64(0); i < space; i++ {
		require.Equal(t, 1, claims[i], "index %d must be claimed exactly once", i)
	}
}

func TestInShardDisabled(t *testing.T) {
	o := &Options{} // ShardTotal == 0
	for i := int64(0); i < 100; i++ {
		require.True(t, o.inShard(i))
	}
	o = &Options{Shard: 1, ShardTotal: 1}
	for i := int64(0); i < 100; i++ {
		require.True(t, o.inShard(i))
	}
}

func TestShardSeed(t *testing.T) {
	// Explicit seed always wins.
	o := &Options{Seed: 42, ShardTotal: 4, Shard: 1}
	require.EqualValues(t, 42, o.shardSeed(999))

	// Sharding without explicit seed uses the fixed shared seed.
	o = &Options{ShardTotal: 4, Shard: 1}
	require.Equal(t, shardDefaultSeed, o.shardSeed(999))

	// No sharding, no explicit seed: random seed passes through.
	o = &Options{}
	require.EqualValues(t, 999, o.shardSeed(999))
}
