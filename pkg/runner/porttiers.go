package runner

import (
	"github.com/projectdiscovery/naabu/v2/pkg/port"
)

// Tiered scan ordering.
//
// The scan space is a permutation of (host, port) pairs produced by Blackrock.
// A single permutation over the whole space is uniform by construction, so the
// position of any given port scales with the size of the port range: scanning
// 1-65535 pushes port 80 roughly 65x further into the scan than scanning
// top-1000 does, even though it is the port most likely to be open.
//
// Splitting the space into priority tiers and permuting *within* each tier fixes
// that without giving up what the permutation is for. Blackrock exists to spread
// probes across hosts and ports rather than walking them in order, which keeps a
// scan from hammering one host's sequential ports - the pattern rate limiters and
// fail2ban-style blocking react to. Tiering preserves that: order inside a tier
// is still fully randomised, only the tier boundaries are ordered.
//
// Tiers are membership-based, which is why intra-tier order does not matter:
//
//	tier 0 - nmap top-100 ports
//	tier 1 - nmap top-1000 ports not already in tier 0
//	tier 2 - everything else
//
// A scan whose ports all land in one tier (top-100, top-1000, an explicit -p
// list of common ports) produces a single tier covering the whole range, and the
// identity ordering below makes that byte-for-byte identical to the untiered
// behaviour.

// portTiers groups indices into Runner.scanner.Ports by scan priority, most
// likely to be open first. Each element is a list of port indices forming one
// tier; tiers are scanned in order and permuted independently.
type portTiers [][]int

// totalTiers reports how many non-empty tiers the plan has.
func (t portTiers) totalTiers() int { return len(t) }

// buildPortTiers produces the tier plan for the given port list.
//
// When priority ordering is disabled, or when every port falls in the same tier,
// the result is a single tier holding the identity permutation - which makes the
// scan loop behave exactly as it did before tiering existed.
func buildPortTiers(ports []*port.Port, prioritize bool) portTiers {
	identity := func() portTiers {
		all := make([]int, len(ports))
		for i := range ports {
			all[i] = i
		}
		return portTiers{all}
	}

	if !prioritize || len(ports) == 0 {
		return identity()
	}

	top100 := portSet(NmapTop100)
	top1000 := portSet(NmapTop1000)

	const tierCount = 3
	buckets := make([][]int, tierCount)
	for idx, p := range ports {
		if p == nil {
			continue
		}
		tier := 2
		if _, ok := top100[p.Port]; ok {
			tier = 0
		} else if _, ok := top1000[p.Port]; ok {
			tier = 1
		}
		buckets[tier] = append(buckets[tier], idx)
	}

	tiers := make(portTiers, 0, tierCount)
	for _, bucket := range buckets {
		if len(bucket) > 0 {
			tiers = append(tiers, bucket)
		}
	}

	// Nothing to gain from tiering a range that lands entirely in one tier, and
	// falling back to identity keeps the ordering bit-identical to the untiered
	// path for the common top-100 / top-1000 presets.
	if len(tiers) <= 1 {
		return identity()
	}
	return tiers
}

// portSet expands a comma/range port list into a membership set.
func portSet(list string) map[int]struct{} {
	expanded := expandPortListOrdered(list)
	set := make(map[int]struct{}, len(expanded))
	for _, p := range expanded {
		set[p] = struct{}{}
	}
	return set
}
