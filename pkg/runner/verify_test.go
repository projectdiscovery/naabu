package runner

import (
	"net"
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/stretchr/testify/require"
)

// TestConnectVerificationBoundedAndVerifies ensures the verification pass keeps
// verifying open ports correctly after switching to a bounded sizedwaitgroup
// (so concurrent dials are capped at the scan rate instead of one goroutine per
// host).
func TestConnectVerificationBoundedAndVerifies(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// grab a port and immediately release it so dials are refused
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	require.NoError(t, closedLn.Close())

	scanner, err := scan.NewScanner(&scan.Options{})
	require.NoError(t, err)

	openP := &port.Port{Port: openPort, Protocol: protocol.TCP}
	closedP := &port.Port{Port: closedPort, Protocol: protocol.TCP}
	scanner.ScanResults.AddPort("127.0.0.1", openP)
	scanner.ScanResults.AddPort("127.0.0.1", closedP)

	r := &Runner{scanner: scanner, options: &Options{Rate: 10}}
	r.ConnectVerification()

	require.True(t, scanner.ScanResults.IPHasPort("127.0.0.1", openP), "open port must survive verification")
	require.False(t, scanner.ScanResults.IPHasPort("127.0.0.1", closedP), "closed port must be dropped by verification")
}
