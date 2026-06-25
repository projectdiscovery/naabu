package runner

import (
	"fmt"
	"strconv"
	"strings"
)

// shardDefaultSeed is the fixed blackrock seed used when sharding is enabled but
// the user did not pass an explicit -seed. All nodes must agree on the seed for
// their slices to be disjoint and jointly complete, so a constant is the safe
// default.
const shardDefaultSeed = int64(0x6e6161627520)

// parseShard parses a masscan-style "index/total" shard descriptor (1-based).
func parseShard(s string) (index, total int, err error) {
	parts := strings.SplitN(strings.TrimSpace(s), "/", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid shard %q (want index/total, e.g. 1/4)", s)
	}
	index, err = strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid shard index %q: %w", parts[0], err)
	}
	total, err = strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid shard total %q: %w", parts[1], err)
	}
	if total < 1 || index < 1 || index > total {
		return 0, 0, fmt.Errorf("invalid shard %d/%d (require 1 <= index <= total)", index, total)
	}
	return index, total, nil
}

// inShard reports whether a 0-based position in the scan space belongs to this
// node's shard. When sharding is disabled (ShardTotal <= 1) everything is in.
func (options *Options) inShard(pos int64) bool {
	if options.ShardTotal <= 1 {
		return true
	}
	return int(pos%int64(options.ShardTotal)) == options.Shard-1
}

// shardSeed returns the blackrock seed to use, preferring an explicit -seed,
// then the fixed shard seed when sharding, then the supplied random seed.
func (options *Options) shardSeed(randomSeed int64) int64 {
	if options.Seed != 0 {
		return options.Seed
	}
	if options.ShardTotal > 1 {
		return shardDefaultSeed
	}
	return randomSeed
}
