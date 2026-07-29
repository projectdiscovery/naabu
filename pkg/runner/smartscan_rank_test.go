package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// buildPopularityRank feeds priority = 1/rank, so a lower rank must mean a port
// that is genuinely more often open. Before this was tiered, the rank came from
// walking the numerically sorted NmapTop1000 string, which made it a port-number
// rank: port 1 ranked first and HTTPS ranked 75th.
func TestBuildPopularityRankOrdersByFrequencyNotPortNumber(t *testing.T) {
	rank := buildPopularityRank()

	t.Run("most common ports hold the head of the ranking", func(t *testing.T) {
		for i, p := range mostCommonOpenPorts {
			require.Equal(t, i+1, rank[p], "port %d should hold rank %d", p, i+1)
		}
	})

	t.Run("common services outrank obscure low ports", func(t *testing.T) {
		// port 1 (tcpmux) and 3 (compressnet) are in the top-1000 set by
		// membership but are effectively never open.
		for _, obscure := range []int{1, 3, 4, 6, 7, 9, 13, 17} {
			for _, common := range []int{80, 443, 22, 3389, 8080, 3306} {
				require.Less(t, rank[common], rank[obscure],
					"port %d must outrank obscure port %d", common, obscure)
			}
		}
	})

	t.Run("top-100 members outrank top-1000-only members", func(t *testing.T) {
		top100 := make(map[int]struct{})
		for _, p := range expandPortListOrdered(NmapTop100) {
			top100[p] = struct{}{}
		}
		worstTop100, bestTop1000Only := 0, 1<<30
		for p := range top100 {
			if rank[p] > worstTop100 {
				worstTop100 = rank[p]
			}
		}
		for _, p := range expandPortListOrdered(NmapTop1000) {
			if _, ok := top100[p]; ok {
				continue
			}
			if rank[p] < bestTop1000Only {
				bestTop1000Only = rank[p]
			}
		}
		require.Less(t, worstTop100, bestTop1000Only,
			"every top-100 port must rank ahead of every top-1000-only port")
	})

	t.Run("ranks are dense and unique", func(t *testing.T) {
		seen := make(map[int]int, len(rank))
		for p, r := range rank {
			require.NotContains(t, seen, r, "rank %d assigned to both %d and %d", r, seen[r], p)
			seen[r] = p
		}
		require.Len(t, rank, len(expandPortListOrdered(NmapTop1000)),
			"tiering must not add or drop ports relative to the top-1000 set")
	})
}

func TestExpandPortListOrdered(t *testing.T) {
	require.Equal(t, []int{80, 443, 8080}, expandPortListOrdered("80,443,8080"))
	require.Equal(t, []int{20, 21, 22, 443}, expandPortListOrdered("20-22,443"))
	require.Equal(t, []int{80}, expandPortListOrdered(" 80 , , bogus "))
	require.Empty(t, expandPortListOrdered("500-400"), "reversed ranges are ignored")
}
