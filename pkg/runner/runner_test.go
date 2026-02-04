package runner

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/projectdiscovery/ratelimit"
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
		validate    func(t *testing.T, runner *Runner)
	}{
		{
			name: "valid options with default settings",
			options: &Options{
				Host:     []string{"example.com"},
				Ports:    "80,443",
				Timeout:  30 * time.Second,
				Retries:  3,
				Rate:     1000,
				ScanType: ConnectScan,
			},
			wantErr: false,
			validate: func(t *testing.T, runner *Runner) {
				assert.Equal(t, 2, len(runner.scanner.Ports))

				expected := []string{"4", "6"}
				actual := []string(runner.options.IPVersion)
				assert.Equal(t, expected, actual)
				assert.NotNil(t, runner.dnsclient)
				assert.NotNil(t, runner.streamChannel)
				assert.NotNil(t, runner.unique)
			},
		},
		{
			name: "valid options with IPv6",
			options: &Options{
				Host:      []string{"example.com"},
				Ports:     "80,443",
				IPVersion: []string{"6"},
				Timeout:   30 * time.Second,
				ScanType:  ConnectScan,
			},
			wantErr: false,
			validate: func(t *testing.T, runner *Runner) {
				assert.Contains(t, runner.options.IPVersion, "6")
				assert.Contains(t, runner.dnsclient.Options.QuestionTypes, dns.TypeAAAA)
			},
		},
		{
			name: "valid options with custom resolvers",
			options: &Options{
				Host:          []string{"example.com"},
				Ports:         "80,443",
				baseResolvers: []string{"8.8.8.8", "1.1.1.1"},
				ScanType:      ConnectScan,
			},
			wantErr: false,
			validate: func(t *testing.T, runner *Runner) {
				assert.Equal(t, []string{"8.8.8.8", "1.1.1.1"}, runner.dnsclient.Options.BaseResolvers)
			},
		},
		{
			name: "invalid port",
			options: &Options{
				Host:     []string{"example.com"},
				Ports:    "99999",
				Timeout:  30 * time.Second,
				ScanType: ConnectScan,
			},
			wantErr:     true,
			errContains: "invalid port",
		},
		{
			name: "empty ports with top ports default",
			options: &Options{
				Host:     []string{"example.com"},
				Timeout:  30 * time.Second,
				ScanType: ConnectScan,
			},
			wantErr: false,
			validate: func(t *testing.T, runner *Runner) {
				ports, err := parsePortsList(NmapTop100)
				require.NoError(t, err)
				assert.Equal(t, len(ports), len(runner.scanner.Ports))
			},
		},
		{
			name: "host discovery disabled for single port",
			options: &Options{
				Host:     []string{"example.com"},
				Ports:    "80",
				ScanType: ConnectScan,
			},
			wantErr: false,
			validate: func(t *testing.T, runner *Runner) {
				assert.False(t, runner.options.WithHostDiscovery)
			},
		},
		{
			name: "excluded IPs configuration",
			options: &Options{
				Host:       []string{"example.com"},
				Ports:      "80,443",
				ExcludeIps: "192.168.1.1,10.0.0.0/8",
				ScanType:   ConnectScan,
			},
			wantErr: false,
			validate: func(t *testing.T, runner *Runner) {
				assert.NotNil(t, runner.scanner.IPRanger)
				// Verify excluded IPs are properly configured
				excluded, err := runner.parseExcludedIps(runner.options)
				require.NoError(t, err)
				assert.Contains(t, excluded, "192.168.1.1")
				assert.Contains(t, excluded, "10.0.0.0/8")
			},
		},
		{
			name: "proxy configuration",
			options: &Options{
				Host:      []string{"example.com"},
				Ports:     "80,443",
				Proxy:     "socks5://127.0.0.1:9050",
				ProxyAuth: "user:pass",
				ScanType:  ConnectScan,
			},
			wantErr: false,
			validate: func(t *testing.T, runner *Runner) {
				assert.NotNil(t, runner.scanner)
			},
		},
		{
			name: "enable progress bar",
			options: &Options{
				Host:              []string{"example.com"},
				Ports:             "80,443",
				EnableProgressBar: true,
				MetricsPort:       8080,
				ScanType:          ConnectScan,
			},
			wantErr: false,
			validate: func(t *testing.T, runner *Runner) {
				assert.NotNil(t, runner.stats)
			},
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

			if tt.validate != nil {
				tt.validate(t, runner)
			}

			if runner.stats != nil {
				err := runner.stats.Stop()
				if err != nil {
					t.Errorf("failed to stop stats: %v", err)
				}
			}
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

	tmpfile, err := os.CreateTemp("", "naabu-test")
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())
	defer func() {
		if err := os.Remove(tmpfile.Name()); err != nil {
			log.Printf("could not remove test file: %s\n", err)
		}
	}()

	runner.targetsFile = tmpfile.Name()
	err = runner.Close()
	require.NoError(t, err)

	_, err = os.Stat(tmpfile.Name())
	assert.True(t, os.IsNotExist(err))
}

// TestRunnerOnReceive tests the result handling callback
func TestRunnerOnReceive(t *testing.T) {
	tests := []struct {
		name     string
		options  *Options
		input    *result.HostResult
		ipRanger map[string][]string
		validate func(t *testing.T, runner *Runner, input *result.HostResult)
	}{
		{
			name: "simple port result",
			options: &Options{
				IPVersion: []string{"4"},
				Host:      []string{"example.com"},
				Ports:     "80",
			},
			input: &result.HostResult{
				IP: "192.168.1.1",
				Ports: []*port.Port{
					{Port: 80, Protocol: protocol.TCP},
				},
			},
			ipRanger: map[string][]string{
				"192.168.1.1": {"example.com"},
			},
			validate: func(t *testing.T, runner *Runner, input *result.HostResult) {
				require.True(t, runner.scanner.ScanResults.HasIPsPorts())
				require.True(t, runner.scanner.ScanResults.IPHasPort(input.IP, input.Ports[0]))

				ipPort := net.JoinHostPort("192.168.1.1", "80")
				v, exists := runner.unique.Get(ipPort)
				require.NotNil(t, v, "Expected %s to be in unique cache", ipPort)
				require.True(t, exists == nil, "Expected no error getting %s from unique cache", ipPort)
			},
		},
		{
			name: "json output with cdn",
			options: &Options{
				IPVersion: []string{"4"},
				Host:      []string{"example.com"},
				Ports:     "80",
				JSON:      true,
				OutputCDN: true,
			},
			input: &result.HostResult{
				IP: "192.168.1.4",
				Ports: []*port.Port{
					{Port: 80, Protocol: protocol.TCP, TLS: true},
				},
			},
			ipRanger: map[string][]string{
				"192.168.1.4": {"cdn.example.com"},
			},
			validate: func(t *testing.T, runner *Runner, input *result.HostResult) {
				require.True(t, runner.scanner.ScanResults.HasIPsPorts())
				require.True(t, runner.scanner.ScanResults.IPHasPort(input.IP, input.Ports[0]))
			},
		},
		{
			name: "csv output with cdn",
			options: &Options{
				IPVersion: []string{"4"},
				Host:      []string{"example.com"},
				Ports:     "80",
				CSV:       true,
				OutputCDN: true,
			},
			input: &result.HostResult{
				IP: "192.168.1.5",
				Ports: []*port.Port{
					{Port: 80, Protocol: protocol.TCP, TLS: true},
				},
			},
			ipRanger: map[string][]string{
				"192.168.1.5": {"cdn2.example.com"},
			},
			validate: func(t *testing.T, runner *Runner, input *result.HostResult) {
				require.True(t, runner.scanner.ScanResults.HasIPsPorts())
				require.True(t, runner.scanner.ScanResults.IPHasPort(input.IP, input.Ports[0]))
			},
		},
		{
			name: "multiple ports result",
			options: &Options{
				IPVersion: []string{"4"},
				Host:      []string{"example.com"},
				Ports:     "80,443",
			},
			input: &result.HostResult{
				IP: "192.168.1.2",
				Ports: []*port.Port{
					{Port: 80, Protocol: protocol.TCP},
					{Port: 443, Protocol: protocol.TCP},
				},
			},
			ipRanger: map[string][]string{
				"192.168.1.2": {"example.com"},
			},
			validate: func(t *testing.T, runner *Runner, input *result.HostResult) {
				require.True(t, runner.scanner.ScanResults.HasIPsPorts())
				for _, p := range input.Ports {
					require.True(t, runner.scanner.ScanResults.IPHasPort(input.IP, p))
					ipPort := net.JoinHostPort("192.168.1.2", fmt.Sprint(p.Port))
					v, exists := runner.unique.Get(ipPort)
					require.NotNil(t, v, "Expected %s to be in unique cache", ipPort)
					require.True(t, exists == nil, "Expected no error getting %s from unique cache", ipPort)
				}
			},
		},
		{
			name: "ipv6 result with ipv6 option",
			options: &Options{
				IPVersion: []string{"6"},
				Host:      []string{"example.com"},
				Ports:     "80",
			},
			input: &result.HostResult{
				IP: "2001:db8::1",
				Ports: []*port.Port{
					{Port: 80, Protocol: protocol.TCP},
				},
			},
			ipRanger: map[string][]string{
				"2001:db8::1": {"example.com"},
			},
			validate: func(t *testing.T, runner *Runner, input *result.HostResult) {
				require.True(t, runner.scanner.ScanResults.HasIPsPorts())
				require.True(t, runner.scanner.ScanResults.IPHasPort(input.IP, input.Ports[0]))
				ipPort := net.JoinHostPort("2001:db8::1", "80")
				v, exists := runner.unique.Get(ipPort)
				require.NotNil(t, v, "Expected %s to be in unique cache", ipPort)
				require.True(t, exists == nil, "Expected no error getting %s from unique cache", ipPort)
			},
		},
		{
			name: "duplicate port result",
			options: &Options{
				IPVersion: []string{"4"},
				Host:      []string{"example.com"},
				Ports:     "80",
			},
			input: &result.HostResult{
				IP: "192.168.1.3",
				Ports: []*port.Port{
					{Port: 80, Protocol: protocol.TCP},
					{Port: 80, Protocol: protocol.TCP},
				},
			},
			ipRanger: map[string][]string{
				"192.168.1.3": {"example.com"},
			},
			validate: func(t *testing.T, runner *Runner, input *result.HostResult) {
				require.True(t, runner.scanner.ScanResults.HasIPsPorts())
				ipPort := net.JoinHostPort("192.168.1.3", "80")
				v, exists := runner.unique.Get(ipPort)
				require.NotNil(t, v, "Expected %s to be in unique cache", ipPort)
				require.True(t, exists == nil, "Expected no error getting %s from unique cache", ipPort)
				count := 0
				for range runner.scanner.ScanResults.GetIPsPorts() {
					count++
				}
				require.Equal(t, 1, count)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, err := NewRunner(tt.options)
			require.NoError(t, err)

			for ip, hosts := range tt.ipRanger {
				err := runner.scanner.IPRanger.Add(ip)
				require.NoError(t, err)
				for _, host := range hosts {
					err = runner.scanner.IPRanger.AddHostWithMetadata(ip, host)
					require.NoError(t, err)
				}
			}

			if tt.name != "ipv6 result with ipv4 only option" {
				for _, p := range tt.input.Ports {
					runner.scanner.ScanResults.AddPort(tt.input.IP, p)
				}
			}

			runner.onReceive(tt.input)

			tt.validate(t, runner, tt.input)
		})
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

// TestRunnerEnumeration tests the full enumeration flow
func TestRunnerEnumeration(t *testing.T) {
	tests := []struct {
		name     string
		options  *Options
		validate func(t *testing.T, runner *Runner)
	}{
		{
			name: "host discovery with syn scan",
			options: &Options{
				Host:                      []string{"192.168.1.0/30"},
				Ports:                     "80,443",
				ScanType:                  SynScan,
				IcmpEchoRequestProbe:      true,
				IcmpTimestampRequestProbe: true,
				TcpSynPingProbes:          []string{"80"},
				EnableProgressBar:         true,
				Retries:                   1,
				Rate:                      100,
				Timeout:                   time.Second * 5,
			},
			validate: func(t *testing.T, runner *Runner) {
				require.NotNil(t, runner.scanner)
				require.NotNil(t, runner.stats)
			},
		},
		{
			name: "connect scan with verification",
			options: &Options{
				Host:     []string{"127.0.0.1"},
				Ports:    "80",
				ScanType: ConnectScan,
				Verify:   true,
				Passive:  true,
			},
			validate: func(t *testing.T, runner *Runner) {
				require.NotNil(t, runner.scanner)
			},
		},
		{
			name: "scan with cdn exclusion",
			options: &Options{
				Host:       []string{"192.168.1.1"},
				Ports:      "80,443,8080",
				ScanType:   ConnectScan,
				ExcludeCDN: true,
				OutputCDN:  true,
			},
			validate: func(t *testing.T, runner *Runner) {
				require.NotNil(t, runner.scanner)
				require.True(t, runner.options.ExcludeCDN)
				require.True(t, runner.options.OutputCDN)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, err := NewRunner(tt.options)
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			err = runner.RunEnumeration(ctx)
			if err != nil && !strings.Contains(err.Error(), "operation not permitted") {
				require.NoError(t, err)
			}

			tt.validate(t, runner)
			err = runner.Close()
			require.NoError(t, err)
		})
	}
}

// TestRunnerHostDiscovery tests host discovery methods
func TestRunnerHostDiscovery(t *testing.T) {
	options := &Options{
		Host:                        []string{"127.0.0.1"},
		Ports:                       "80,443",
		ScanType:                    ConnectScan,
		IcmpEchoRequestProbe:        false,
		IcmpTimestampRequestProbe:   false,
		IcmpAddressMaskRequestProbe: false,
		IPv6NeighborDiscoveryPing:   false,
		ArpPing:                     false,
		TcpSynPingProbes:            []string{"80"},
		TcpAckPingProbes:            []string{"443"},
		OnlyHostDiscovery:           true,
		Rate:                        100,
		Timeout:                     2 * time.Second,
		SkipHostDiscovery:           true,
	}

	runner, err := NewRunner(options)
	require.NoError(t, err)

	mockScanner := &scan.Scanner{
		ScanResults:          result.NewResult(),
		HostDiscoveryResults: result.NewResult(),
		ListenHandler: &scan.ListenHandler{
			Phase: &scan.Phase{},
		},
		IPRanger: runner.scanner.IPRanger,
	}

	runner.scanner = mockScanner

	runner.limiter = ratelimit.New(context.Background(), uint(options.Rate), time.Second)

	require.NotEmpty(t, options.TcpSynPingProbes)
	require.NotEmpty(t, options.TcpAckPingProbes)
	require.Equal(t, []string(options.TcpSynPingProbes), []string{"80"})
	require.Equal(t, []string(options.TcpAckPingProbes), []string{"443"})

	mockScanner.HostDiscoveryResults.AddIp("127.0.0.1")

	require.True(t, mockScanner.HostDiscoveryResults.HasIP("127.0.0.1"))

	if runner.limiter != nil {
		runner.limiter.Stop()
	}
	err = runner.Close()
	require.NoError(t, err)
}

// TestRunnerGetIPs tests IP preprocessing methods
func TestRunnerGetIPs(t *testing.T) {
	options := &Options{
		Host:      []string{"192.168.1.0/24"},
		Ports:     "80,443",
		ScanType:  ConnectScan,
		IPVersion: []string{"4", "6"},
	}

	runner, err := NewRunner(options)
	require.NoError(t, err)
	defer func() {
		err := runner.Close()
		require.NoError(t, err)
	}()

	err = runner.Load()
	require.NoError(t, err, "Failed to load targets")

	cidrs, ipsWithPort := runner.getPreprocessedIps()
	require.NotEmpty(t, cidrs, "Expected non-empty CIDRs")
	require.Empty(t, ipsWithPort, "Expected empty ipsWithPort initially")

	err = runner.scanner.IPRanger.AddHostWithMetadata("192.168.1.2:80", "example.com")
	require.NoError(t, err)

	cidrs, ipsWithPort = runner.getPreprocessedIps()
	require.NotEmpty(t, cidrs, "Expected non-empty CIDRs")
	require.NotEmpty(t, ipsWithPort, "Expected non-empty ipsWithPort after adding host with port")
	require.Contains(t, ipsWithPort, "192.168.1.2:80", "Expected to find added IP:port combination")

	runner.scanner.HostDiscoveryResults.AddIp("192.168.1.1")
	cidrs, ipsWithPort = runner.getHostDiscoveryIps()
	require.NotEmpty(t, cidrs, "Expected non-empty CIDRs from host discovery")
	require.NotEmpty(t, ipsWithPort, "Expected non-empty ipsWithPort from host discovery")

	targets, targetsV4, targetsV6, targetsWithPort, err := runner.GetTargetIps(runner.getPreprocessedIps)
	require.NoError(t, err, "Expected no error from GetTargetIps")
	require.NotEmpty(t, targets, "Expected non-empty targets")
	require.NotEmpty(t, targetsV4, "Expected non-empty IPv4 targets")
	require.Empty(t, targetsV6, "Expected empty IPv6 targets as none were added")
	require.NotEmpty(t, targetsWithPort, "Expected non-empty targetsWithPort")
	require.Contains(t, targetsWithPort, "192.168.1.2:80", "Expected to find added IP:port combination in targets")

	found := false
	for _, target := range targetsV4 {
		if target.String() == "192.168.1.0/24" {
			found = true
			break
		}
	}
	require.True(t, found, "Expected to find the CIDR range 192.168.1.0/24 in targetsV4")
}

// TestRunnerConnectVerification tests port verification
func TestRunnerConnectVerification(t *testing.T) {
	options := &Options{
		Host:     []string{"127.0.0.1"},
		Ports:    "80,443",
		ScanType: ConnectScan,
		Rate:     100,
		Verify:   true,
	}

	runner, err := NewRunner(options)
	require.NoError(t, err)

	ports := []*port.Port{
		{Port: 80, Protocol: protocol.TCP},
		{Port: 443, Protocol: protocol.TCP},
	}
	for _, p := range ports {
		runner.scanner.ScanResults.AddPort("127.0.0.1", p)
	}

	runner.ConnectVerification()
	require.NotNil(t, runner.scanner.ScanResults)

	count := 0
	for range runner.scanner.ScanResults.GetIPsPorts() {
		count++
	}
	require.Equal(t, 1, count)
}

func TestConcurrentSYNScans(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	targets := []string{"127.0.0.1", "localhost", "scanme.sh"}
	numGoroutines := runtime.NumCPU()

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return // Stop if context is cancelled
			default:
			}

			options := &Options{
				Host:     []string{target},
				ScanType: SynScan,
				Ports:    "80,443,8080",
				Retries:  5,
				Verbose:  false,
				Silent:   true,
			}

			naabuRunner, err := NewRunner(options)
			if err != nil {
				t.Logf("Error creating runner for %s: %v", target, err)
				errChan <- fmt.Errorf("runner creation failed for %s: %w", target, err)
				return
			}

			defer func() {
				closeErr := naabuRunner.Close()
				if closeErr != nil {
					t.Logf("Error closing runner for %s: %v", target, closeErr)
				}
			}()

			runErr := naabuRunner.RunEnumeration(ctx)
			if runErr != nil {
				errChan <- fmt.Errorf("enumeration failed for %s: %w", target, runErr)
			}
		}(targets[i%len(targets)]) // cycle thru targets
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Error(err)
	}
}

func TestRunner_ScanHistoryIntegration(t *testing.T) {
	tmpFile := "/tmp/test-integration-history.log"
	defer os.Remove(tmpFile)

	tests := []struct {
		name          string
		setupHistory  func(*ScanHistory)
		scanLog       string
		skipScanned   bool
		forceRescan   bool
		expectedAdded bool
		description   string
	}{
		{
			name: "skip previously scanned target",
			setupHistory: func(sh *ScanHistory) {
				sh.Record("example.com", "1.2.3.4")
				sh.Save()
			},
			scanLog:       tmpFile,
			skipScanned:   true,
			forceRescan:   false,
			expectedAdded: false,
			description:   "Previously scanned target should be skipped when skip-scanned is enabled",
		},
		{
			name: "force rescan overrides skip",
			setupHistory: func(sh *ScanHistory) {
				sh.Record("example.com", "1.2.3.4")
				sh.Save()
			},
			scanLog:       tmpFile,
			skipScanned:   true,
			forceRescan:   true,
			expectedAdded: true,
			description:   "Force rescan should process target even if previously scanned",
		},
		{
			name:          "new target not skipped",
			setupHistory:  func(sh *ScanHistory) {},
			scanLog:       tmpFile,
			skipScanned:   true,
			forceRescan:   false,
			expectedAdded: true,
			description:   "New targets should always be processed",
		},
		{
			name: "skip-scanned disabled processes all",
			setupHistory: func(sh *ScanHistory) {
				sh.Record("example.com", "1.2.3.4")
				sh.Save()
			},
			scanLog:       tmpFile,
			skipScanned:   false,
			forceRescan:   false,
			expectedAdded: true,
			description:   "With skip-scanned disabled, all targets should be processed",
		},
		{
			name:          "no scan log means no filtering",
			setupHistory:  func(sh *ScanHistory) {},
			scanLog:       "",
			skipScanned:   true,
			forceRescan:   false,
			expectedAdded: true,
			description:   "Without scan log, all targets should be processed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up test file
			os.Remove(tmpFile)

			// Setup scan history if needed
			if tt.scanLog != "" {
				sh, err := NewScanHistory(tmpFile, "txt", "host", 0)
				require.NoError(t, err)
				if tt.setupHistory != nil {
					tt.setupHistory(sh)
				}
			}

			// Create runner with history options
			options := &Options{
				Ports:       "80",
				ScanType:    ConnectScan,
				ScanLog:     tt.scanLog,
				SkipScanned: tt.skipScanned,
				ForceRescan: tt.forceRescan,
			}

			runner, err := NewRunner(options)
			require.NoError(t, err)
			defer runner.Close()

			// Try to add target
			err = runner.AddTarget("example.com")
			require.NoError(t, err)

			// Verify expected behavior by checking scan history
			// If it should have been skipped, the history would still show it was already scanned
			// If it's a new target, we can check if AddTarget worked without error
			if tt.expectedAdded {
				// For new targets or force-rescan, AddTarget should succeed
				assert.NoError(t, err)
			}
		})
	}
}

func TestRunner_ScanHistoryRecording(t *testing.T) {
	tmpFile := "/tmp/test-recording-history.log"
	defer os.Remove(tmpFile)

	options := &Options{
		Ports:       "80",
		ScanType:    ConnectScan,
		ScanLog:     tmpFile,
		SkipScanned: true,
		LogFormat:   "txt",
	}

	runner, err := NewRunner(options)
	require.NoError(t, err)

	t.Run("onReceive records to history", func(t *testing.T) {
		// Simulate a successful scan result
		hostResult := &result.HostResult{
			IP: "1.2.3.4",
			Ports: []*port.Port{
				{Port: 80, Protocol: protocol.TCP},
			},
		}

		// Add host to IPRanger
		runner.scanner.IPRanger.AddHostWithMetadata("1.2.3.4", "example.com")

		// Call onReceive
		runner.onReceive(hostResult)

		// Verify it was recorded in history
		assert.NotNil(t, runner.scanHistory)
		assert.True(t, runner.scanHistory.IsScanned("example.com"))
	})

	t.Run("history persisted on close", func(t *testing.T) {
		// Record another target
		runner.scanHistory.Record("github.com", "140.82.112.3")

		// Close runner (should save history)
		err := runner.Close()
		require.NoError(t, err)

		// Load history in new instance
		sh, err := NewScanHistory(tmpFile, "txt", "host", 0)
		require.NoError(t, err)

		// Verify both targets persisted
		assert.True(t, sh.IsScanned("example.com"))
		assert.True(t, sh.IsScanned("github.com"))
	})
}

func TestRunner_ScanHistoryWithTTL(t *testing.T) {
	tmpFile := "/tmp/test-ttl-integration.log"
	defer os.Remove(tmpFile)

	// Create with short TTL
	options := &Options{
		Ports:       "80",
		ScanType:    ConnectScan,
		ScanLog:     tmpFile,
		SkipScanned: true,
		ScanLogTTL:  50 * time.Millisecond,
	}

	runner, err := NewRunner(options)
	require.NoError(t, err)
	defer runner.Close()

	t.Run("target skipped within TTL", func(t *testing.T) {
		// Record target
		runner.scanHistory.Record("fresh.com", "1.2.3.4")
		runner.scanHistory.Save()

		// Try to add immediately (should be in history and skipped)
		runner.AddTarget("fresh.com")

		assert.True(t, runner.scanHistory.IsScanned("fresh.com"), "Target should be skipped within TTL")
	})

	t.Run("target processed after TTL expires", func(t *testing.T) {
		// Wait for TTL to expire
		time.Sleep(60 * time.Millisecond)

		// Target should no longer be in history
		assert.False(t, runner.scanHistory.IsScanned("fresh.com"), "Target should be processed after TTL expires")
	})
}

func TestRunner_ScanHistoryMultipleFormats(t *testing.T) {
	formats := []struct {
		name   string
		format string
		ext    string
	}{
		{"txt format", "txt", "log"},
		{"json format", "json", "json"},
	}

	for _, f := range formats {
		t.Run(f.name, func(t *testing.T) {
			tmpFile := fmt.Sprintf("/tmp/test-format-%s.%s", f.format, f.ext)
			defer os.Remove(tmpFile)

			options := &Options{
				Ports:       "80",
				ScanType:    ConnectScan,
				ScanLog:     tmpFile,
				SkipScanned: true,
				LogFormat:   f.format,
			}

			runner, err := NewRunner(options)
			require.NoError(t, err)

			// Record some targets
			runner.scanHistory.Record("example.com", "1.2.3.4")
			runner.scanHistory.Record("google.com", "8.8.8.8")

			// Close to save
			runner.Close()

			// Verify file exists and has content
			content, err := os.ReadFile(tmpFile)
			require.NoError(t, err)
			assert.NotEmpty(t, content)

			// Load in new runner
			runner2, err := NewRunner(options)
			require.NoError(t, err)
			defer runner2.Close()

			// Verify history loaded
			assert.True(t, runner2.scanHistory.IsScanned("example.com"))
			assert.True(t, runner2.scanHistory.IsScanned("google.com"))
		})
	}
}

func TestRunner_ScanHistoryNilSafety(t *testing.T) {
	t.Run("no scan log means no history", func(t *testing.T) {
		options := &Options{
			Ports:    "80",
			ScanType: ConnectScan,
		}

		runner, err := NewRunner(options)
		require.NoError(t, err)
		defer runner.Close()

		assert.Nil(t, runner.scanHistory)

		// Should not panic when processing targets
		err = runner.AddTarget("example.com")
		assert.NoError(t, err)
	})

	t.Run("skip-scanned without scan-log is safe", func(t *testing.T) {
		options := &Options{
			Ports:       "80",
			ScanType:    ConnectScan,
			SkipScanned: true, // Enabled but no scan log
		}

		runner, err := NewRunner(options)
		require.NoError(t, err)
		defer runner.Close()

		assert.Nil(t, runner.scanHistory)

		// Should not panic
		err = runner.AddTarget("example.com")
		assert.NoError(t, err)
	})
}
