package runner

import (
	"net"
	"testing"

	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/stretchr/testify/require"
)

// TestCalculateDeadHostsStreamsTargets verifies dead host detection is computed
// by re-streaming the target CIDRs (bounded memory) rather than holding every
// probed ip, and that responsive hosts are correctly excluded.
func TestCalculateDeadHostsStreamsTargets(t *testing.T) {
	r := &Runner{
		scanner: &scan.Scanner{HostDiscoveryResults: result.NewResult()},
	}

	const cidr = "10.0.0.0/29"
	r.scanner.HostDiscoveryResults.AddIp("10.0.0.1")
	r.scanner.HostDiscoveryResults.AddIp("10.0.0.3")

	var total int
	stream, _ := mapcidr.IPAddressesAsStream(cidr)
	for range stream {
		total++
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	require.NoError(t, err)

	r.calculateDeadHosts([]*net.IPNet{ipnet}, nil)

	dead := r.scanner.HostDiscoveryResults.GetDeadHosts()
	require.Len(t, dead, total-2, "dead hosts must be all streamed targets minus the responsive ones")

	deadSet := make(map[string]struct{}, len(dead))
	for _, d := range dead {
		deadSet[d] = struct{}{}
	}
	require.NotContains(t, deadSet, "10.0.0.1", "responsive host must not be reported dead")
	require.NotContains(t, deadSet, "10.0.0.3", "responsive host must not be reported dead")
	require.Contains(t, deadSet, "10.0.0.5", "unresponsive host must be reported dead")
}
