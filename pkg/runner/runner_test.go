package runner

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewRunner tests the creation of a new Runner instance
func TestNewRunner(t *testing.T) {
	tests := []struct {
		name        string
		options     *Options
		wantErr     bool
		errContains string
	}{
		{
			name: "valid options",
			options: &Options{
				Host:     []string{"example.com"},
				Ports:    "80,443",
				Timeout:  30 * time.Second,
				Retries:  3,
				Rate:     1000,
				ScanType: ConnectScan,
			},
			wantErr: false,
		},
		{
			name: "invalid port",
			options: &Options{
				Host:     []string{"example.com"},
				Ports:    "99999", // Invalid port
				Timeout:  30 * time.Second,
				Retries:  3,
				Rate:     1000,
				ScanType: ConnectScan,
			},
			wantErr:     true,
			errContains: "invalid port",
		},
		{
			name: "no hosts",
			options: &Options{
				Host:     []string{},
				Ports:    "80",
				Timeout:  30 * time.Second,
				Retries:  3,
				Rate:     1000,
				ScanType: ConnectScan,
			},
			wantErr:     true,
			errContains: "no targets provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, err := NewRunner(tt.options)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, runner)
			require.NotNil(t, runner.scanner)
			require.NotNil(t, runner.options)
		})
	}
}

// TestRunnerClose tests the cleanup of resources
func TestRunnerClose(t *testing.T) {
	options := &Options{
		Host:     []string{"example.com"},
		Ports:    "80",
		Timeout:  30 * time.Second,
		Retries:  3,
		Rate:     1000,
		ScanType: ConnectScan,
	}

	runner, err := NewRunner(options)
	require.NoError(t, err)
	require.NotNil(t, runner)

	// Create a temporary file to test cleanup
	tmpfile, err := os.CreateTemp("", "naabu-test")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	runner.targetsFile = tmpfile.Name()
	runner.Close()

	// Verify the temporary file was removed
	_, err = os.Stat(tmpfile.Name())
	assert.True(t, os.IsNotExist(err))
}

// TestRunnerOnReceive tests the result handling callback
func TestRunnerOnReceive(t *testing.T) {
	options := &Options{
		Host:     []string{"example.com"},
		Ports:    "80",
		Timeout:  30 * time.Second,
		Retries:  3,
		Rate:     1000,
		ScanType: ConnectScan,
	}

	runner, err := NewRunner(options)
	require.NoError(t, err)

	resultsChan := make(chan *result.HostResult, 1)
	options.OnResult = func(hr *result.HostResult) {
		resultsChan <- hr
	}

	// Simulate receiving a result
	hostResult := &result.HostResult{
		IP: "192.168.1.1",
		Ports: []*port.Port{
			{Port: 80, Protocol: protocol.TCP},
		},
	}

	go runner.onReceive(hostResult)

	select {
	case result := <-resultsChan:
		assert.Equal(t, "192.168.1.1", result.IP)
		assert.Len(t, result.Ports, 1)
		assert.Equal(t, 80, result.Ports[0].Port)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for result")
	}
}

// TestRunnerPickIP tests the IP selection from CIDR ranges
func TestRunnerPickIP(t *testing.T) {
	tests := []struct {
		name     string
		targets  []*net.IPNet
		index    int64
		expected string
	}{
		{
			name: "first ip in range",
			targets: []*net.IPNet{
				mustParseCIDR(t, "192.168.1.0/24"),
			},
			index:    0,
			expected: "192.168.1.0",
		},
		{
			name: "last ip in range",
			targets: []*net.IPNet{
				mustParseCIDR(t, "192.168.1.0/24"),
			},
			index:    255,
			expected: "192.168.1.255",
		},
		{
			name: "middle ip in range",
			targets: []*net.IPNet{
				mustParseCIDR(t, "192.168.1.0/24"),
			},
			index:    128,
			expected: "192.168.1.128",
		},
	}

	options := &Options{
		Host:     []string{"192.168.1.0/24"},
		Ports:    "80",
		Timeout:  30 * time.Second,
		Retries:  3,
		Rate:     1000,
		ScanType: ConnectScan,
	}

	runner, err := NewRunner(options)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runner.PickIP(tt.targets, tt.index)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to parse CIDR
func mustParseCIDR(t *testing.T, s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	require.NoError(t, err)
	return ipnet
}

// TestRunnerSetSourceIP tests setting source IP for scans
func TestRunnerSetSourceIP(t *testing.T) {
	tests := []struct {
		name      string
		sourceIP  string
		wantErr   bool
		errString string
	}{
		{
			name:     "valid ipv4",
			sourceIP: "192.168.1.1",
			wantErr:  false,
		},
		{
			name:     "valid ipv6",
			sourceIP: "2001:db8::1",
			wantErr:  false,
		},
		{
			name:      "invalid ip",
			sourceIP:  "invalid-ip",
			wantErr:   true,
			errString: "invalid source ip",
		},
	}

	options := &Options{
		Host:     []string{"example.com"},
		Ports:    "80",
		Timeout:  30 * time.Second,
		Retries:  3,
		Rate:     1000,
		ScanType: ConnectScan,
	}

	runner, err := NewRunner(options)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runner.SetSourceIP(tt.sourceIP)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestRunnerSetSourcePort tests setting source port for scans
func TestRunnerSetSourcePort(t *testing.T) {
	tests := []struct {
		name       string
		sourcePort string
		wantErr    bool
		errString  string
	}{
		{
			name:       "valid port",
			sourcePort: "1234",
			wantErr:    false,
		},
		{
			name:       "invalid port - too high",
			sourcePort: "65536",
			wantErr:    true,
			errString:  "invalid source port",
		},
		{
			name:       "invalid port - negative",
			sourcePort: "-1",
			wantErr:    true,
			errString:  "invalid source port",
		},
		{
			name:       "invalid port - not a number",
			sourcePort: "abc",
			wantErr:    true,
			errString:  "invalid source port",
		},
	}

	options := &Options{
		Host:     []string{"example.com"},
		Ports:    "80",
		Timeout:  30 * time.Second,
		Retries:  3,
		Rate:     1000,
		ScanType: ConnectScan,
	}

	runner, err := NewRunner(options)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runner.SetSourcePort(tt.sourcePort)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, runner.scanner.ListenHandler.Port, mustParsePort(t, tt.sourcePort))
		})
	}
}

// Helper function to parse port
func mustParsePort(t *testing.T, s string) int {
	port, err := net.LookupPort("tcp", s)
	require.NoError(t, err)
	return port
}

// TestRunnerCanIScanIfCDN tests CDN scanning restrictions
func TestRunnerCanIScanIfCDN(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		port       *port.Port
		excludeCDN bool
		expected   bool
	}{
		{
			name:       "cdn excluded - port 80",
			host:       "cdn.example.com",
			port:       &port.Port{Port: 80},
			excludeCDN: true,
			expected:   true,
		},
		{
			name:       "cdn excluded - port 443",
			host:       "cdn.example.com",
			port:       &port.Port{Port: 443},
			excludeCDN: true,
			expected:   true,
		},
		{
			name:       "cdn excluded - other port",
			host:       "cdn.example.com",
			port:       &port.Port{Port: 8080},
			excludeCDN: true,
			expected:   false,
		},
		{
			name:       "cdn not excluded",
			host:       "cdn.example.com",
			port:       &port.Port{Port: 8080},
			excludeCDN: false,
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &Options{
				Host:       []string{"example.com"},
				Ports:      "80",
				Timeout:    30 * time.Second,
				Retries:    3,
				Rate:       1000,
				ScanType:   ConnectScan,
				ExcludeCDN: tt.excludeCDN,
			}

			// Create a mock scanner with a mock CDN check function
			mockScanner, err := scan.NewScanner(&scan.Options{
				ExcludeCdn: tt.excludeCDN,
			})
			require.NoError(t, err)

			runner := &Runner{
				options: options,
				scanner: mockScanner,
			}

			result := runner.canIScanIfCDN(tt.host, tt.port)
			assert.Equal(t, tt.expected, result)
		})
	}
}
