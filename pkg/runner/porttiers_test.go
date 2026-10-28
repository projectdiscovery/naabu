package runner

import (
	"fmt"
	"testing"

	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func portsFrom(numbers []int) []*port.Port {
	out := make([]*port.Port, 0, len(numbers))
	for _, n := range numbers {
		out = append(out, &port.Port{Port: n, Protocol: protocol.TCP})
	}
	return out
}

func fullRangePorts(t *testing.T) []*port.Port {
	t.Helper()
	numbers := make([]int, 0, 65535)
	for p := 1; p <= 65535; p++ {
		numbers = append(numbers, p)
	}
	return portsFrom(numbers)
}

// simulateTierOrder walks the tier plan exactly as the scan loop does and
// returns, for each (ipIndex, portNumber) probe, the order in which it was
// issued. It mirrors runner.go: one Blackrock permutation per tier over
// hosts*tierPorts, with a contiguous global index across tiers.
func simulateTierOrder(ports []*port.Port, tiers portTiers, hosts int64, seed int64) []struct {
	IPIndex int64
	Port    int
} {
	var out []struct {
		IPIndex int64
		Port    int
	}
	for _, tierPortIdx := range tiers {
		tierPortsCount := int64(len(tierPortIdx))
		if tierPortsCount == 0 {
			continue
		}
		tierRange := hosts * tierPortsCount
		b := blackrock.New(tierRange, seed)
		for local := int64(0); local < tierRange; local++ {
			xxx := b.Shuffle(local)
			ipIndex := xxx / tierPortsCount
			portIndex := tierPortIdx[int(xxx%tierPortsCount)]
			out = append(out, struct {
				IPIndex int64
				Port    int
			}{ipIndex, ports[portIndex].Port})
		}
	}
	return out
}

func TestBuildPortTiersPlan(t *testing.T) {
	t.Run("disabled yields a single identity tier", func(t *testing.T) {
		ports := fullRangePorts(t)
		tiers := buildPortTiers(ports, false)
		require.Equal(t, 1, tiers.totalTiers())
		require.Len(t, tiers[0], len(ports))
		for i := range ports {
			require.Equal(t, i, tiers[0][i], "must be the identity permutation")
		}
	})

	t.Run("top-100 collapses to a single tier", func(t *testing.T) {
		ports := portsFrom(expandPortListOrdered(NmapTop100))
		tiers := buildPortTiers(ports, true)
		require.Equal(t, 1, tiers.totalTiers(),
			"a range entirely inside one tier must not be split, keeping ordering identical to before")
	})

	t.Run("top-1000 splits into two tiers", func(t *testing.T) {
		ports := portsFrom(expandPortListOrdered(NmapTop1000))
		tiers := buildPortTiers(ports, true)
		require.Equal(t, 2, tiers.totalTiers())
		require.Len(t, tiers[0], len(expandPortListOrdered(NmapTop100)))
	})

	t.Run("full range splits into three tiers", func(t *testing.T) {
		ports := fullRangePorts(t)
		tiers := buildPortTiers(ports, true)
		require.Equal(t, 3, tiers.totalTiers())
		require.Len(t, tiers[0], 100, "tier 0 is the nmap top-100")
		require.Len(t, tiers[1], 900, "tier 1 is the remaining top-1000")
		require.Len(t, tiers[2], 65535-1000)
	})

	t.Run("tiers partition the port list exactly", func(t *testing.T) {
		for _, spec := range []struct {
			name  string
			ports []*port.Port
		}{
			{"full", fullRangePorts(t)},
			{"top1000", portsFrom(expandPortListOrdered(NmapTop1000))},
			{"sparse", portsFrom([]int{22, 80, 443, 9999, 40000, 65535})},
		} {
			t.Run(spec.name, func(t *testing.T) {
				tiers := buildPortTiers(spec.ports, true)
				seen := make(map[int]int, len(spec.ports))
				for _, tier := range tiers {
					for _, idx := range tier {
						seen[idx]++
					}
				}
				require.Len(t, seen, len(spec.ports), "every port index must appear")
				for idx, n := range seen {
					require.Equal(t, 1, n, "port index %d appears %d times", idx, n)
				}
			})
		}
	})
}

// The scan must still probe every (host, port) pair exactly once. A tiering bug
// here would silently drop ports, which is the failure mode this whole change is
// meant to avoid.
func TestTieredOrderCoversEveryHostPortExactlyOnce(t *testing.T) {
	ports := portsFrom(expandPortListOrdered(NmapTop1000))
	const hosts = int64(3)
	tiers := buildPortTiers(ports, true)
	require.Greater(t, tiers.totalTiers(), 1, "need a multi-tier plan to be meaningful")

	order := simulateTierOrder(ports, tiers, hosts, 42)
	require.Len(t, order, len(ports)*int(hosts), "probe count must equal hosts*ports")

	seen := make(map[[2]int64]int, len(order))
	for _, probe := range order {
		seen[[2]int64{probe.IPIndex, int64(probe.Port)}]++
	}
	require.Len(t, seen, len(ports)*int(hosts), "every (host, port) pair must be probed")
	for key, n := range seen {
		require.Equal(t, 1, n, "pair host=%d port=%d probed %d times", key[0], key[1], n)
	}
}

// Sharding decides membership on the global index, so shards must remain
// disjoint and jointly complete across tier boundaries.
func TestTieredShardingStaysDisjointAndComplete(t *testing.T) {
	ports := portsFrom(expandPortListOrdered(NmapTop1000))
	const hosts = int64(2)
	tiers := buildPortTiers(ports, true)

	total := int64(len(ports)) * hosts
	const shardTotal = 4

	covered := make(map[int64]int, total)
	for shard := 1; shard <= shardTotal; shard++ {
		opts := &Options{Shard: shard, ShardTotal: shardTotal}
		var indexBase int64
		for _, tierPortIdx := range tiers {
			tierRange := hosts * int64(len(tierPortIdx))
			for local := int64(0); local < tierRange; local++ {
				if opts.inShard(indexBase + local) {
					covered[indexBase+local]++
				}
			}
			indexBase += tierRange
		}
	}

	require.Equal(t, int(total), len(covered), "shards must jointly cover the whole index space")
	for idx, n := range covered {
		require.Equal(t, 1, n, "global index %d claimed by %d shards", idx, n)
	}
}

// The point of the change: a wide range must no longer postpone likely-open
// ports.
func TestTieringKeepsCommonPortsEarlyOnWideRanges(t *testing.T) {
	ports := fullRangePorts(t)
	const hosts = int64(2)
	const seed = int64(12345)

	firstProbeOf := func(tiers portTiers, target int) int {
		order := simulateTierOrder(ports, tiers, hosts, seed)
		for i, probe := range order {
			if probe.Port == target {
				return i
			}
		}
		return -1
	}

	untiered := buildPortTiers(ports, false)
	tiered := buildPortTiers(ports, true)

	total := len(ports) * int(hosts)
	for _, target := range []int{80, 443, 22, 3389} {
		before := firstProbeOf(untiered, target)
		after := firstProbeOf(tiered, target)
		require.Positive(t, before)
		require.Positive(t, after)

		// tier 0 is 100 ports * hosts probes, so anything in it must land inside
		// that prefix rather than somewhere in the full 131k-probe space.
		require.Less(t, after, 100*int(hosts),
			"port %d should be probed within the first tier", target)
		require.Less(t, after, before,
			"port %d should be reached earlier when tiered (was %d, now %d)", target, before, after)

		fmt.Printf("  port %-5d untiered=#%-7d tiered=#%-5d (%.0fx earlier, of %d probes)\n",
			target, before, after, float64(before)/float64(max(after, 1)), total)
	}
}

// Randomisation within a tier is what keeps the scan from walking a host's ports
// in order, so it must survive tiering.
func TestTierInternalOrderStaysRandomised(t *testing.T) {
	ports := portsFrom(expandPortListOrdered(NmapTop1000))
	tiers := buildPortTiers(ports, true)
	order := simulateTierOrder(ports, tiers, 2, 7)

	// Within the first tier, consecutive probes should not be ascending ports on
	// the same host; an ordered walk would show a long ascending run.
	ascending := 0
	longest := 0
	for i := 1; i < len(order) && i < 200; i++ {
		if order[i].IPIndex == order[i-1].IPIndex && order[i].Port > order[i-1].Port {
			ascending++
			if ascending > longest {
				longest = ascending
			}
		} else {
			ascending = 0
		}
	}
	require.Less(t, longest, 10, "probes within a tier must not walk ports in order")
}
