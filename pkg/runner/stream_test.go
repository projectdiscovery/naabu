package runner

import (
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/stretchr/testify/require"
)

// TestStreamModeExcludesHosts verifies that stream mode honors excluded hosts (-eh / -ef)
// and never probes or processes excluded IPs.
func TestStreamModeExcludesHosts(t *testing.T) {
	np, err := networkpolicy.New(networkpolicy.Options{
		DenyList: []string{"192.168.1.2", "192.168.1.3"},
	})
	require.NoError(t, err)

	scanner, err := scan.NewScanner(&scan.Options{
		Rate:     100,
		Retries:  1,
		ScanType: ConnectScan,
	})
	require.NoError(t, err)

	r := &Runner{
		options: &Options{
			Stream:   true,
			Rate:     100,
			ScanType: ConnectScan,
		},
		scanner:        scanner,
		excludedIpsNP:  np,
		streamChannel:  make(chan Target, 10),
	}
	r.scanner.Ports = []*port.Port{{Port: 80, Protocol: protocol.TCP}}

	var mu sync.Mutex
	var processedIPs []string

	// Stream a CIDR containing 192.168.1.0 to 192.168.1.3
	r.streamChannel <- Target{Cidr: "192.168.1.0/30"}
	close(r.streamChannel)

	for target := range r.streamChannel {
		if ipStream, err := mapcidr.IPAddressesAsStream(target.Cidr); err == nil {
			for ip := range ipStream {
				if r.excludedIpsNP != nil && !r.excludedIpsNP.ValidateAddress(ip) {
					continue
				}
				mu.Lock()
				processedIPs = append(processedIPs, ip)
				mu.Unlock()
			}
		}
	}

	require.Contains(t, processedIPs, "192.168.1.0")
	require.Contains(t, processedIPs, "192.168.1.1")
	require.NotContains(t, processedIPs, "192.168.1.2", "excluded IP 192.168.1.2 must not be processed in stream mode")
	require.NotContains(t, processedIPs, "192.168.1.3", "excluded IP 192.168.1.3 must not be processed in stream mode")
	require.Len(t, processedIPs, 2)
}

func TestNewRunnerInitializesExcludedIPsInStreamMode(t *testing.T) {
	options := &Options{
		Host:       []string{"127.0.0.1"},
		Ports:      "80",
		Timeout:    time.Second,
		Retries:    1,
		Rate:       100,
		ScanType:   ConnectScan,
		Stream:     true,
		ExcludeIps: "127.0.0.5,10.0.0.0/8",
	}

	runner, err := NewRunner(options)
	require.NoError(t, err)
	defer runner.Close()

	require.NotNil(t, runner.excludedIpsNP, "excludedIpsNP must be initialized when ExcludeIps is provided")
	require.False(t, runner.excludedIpsNP.ValidateAddress("127.0.0.5"), "127.0.0.5 must be denied by policy")
	require.False(t, runner.excludedIpsNP.ValidateAddress("10.1.2.3"), "10.1.2.3 in 10.0.0.0/8 must be denied by policy")
	require.True(t, runner.excludedIpsNP.ValidateAddress("127.0.0.1"), "127.0.0.1 must be allowed by policy")
}
