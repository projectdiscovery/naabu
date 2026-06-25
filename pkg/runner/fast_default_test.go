package runner

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFastSenderIPMatchesPickIP guards the invariant the default SYN scan loop
// relies on: the zero-alloc fast IP generator must produce the same address as
// the big.Int-based PickIP for every index, so swapping it into the default
// path does not change which hosts get scanned.
func TestFastSenderIPMatchesPickIP(t *testing.T) {
	var targets []*net.IPNet
	for _, c := range []string{"10.0.0.0/30", "192.168.1.0/29", "172.16.5.0/28"} {
		_, ipnet, err := net.ParseCIDR(c)
		require.NoError(t, err)
		targets = append(targets, ipnet)
	}

	r := &Runner{}
	idx := buildTargetIndex(targets)
	require.Greater(t, idx.total, int64(0))

	for i := int64(0); i < idx.total; i++ {
		dstIP, fastIP, _, isV4 := idx.pickIPv4(i)
		require.True(t, isV4, "index %d should be IPv4", i)
		require.Equal(t, r.PickIP(targets, i), fastIP, "string IP mismatch at index %d", i)
		require.Equal(t, fastIP, net.IPv4(dstIP[0], dstIP[1], dstIP[2], dstIP[3]).To4().String(), "byte IP mismatch at index %d", i)
	}
}
