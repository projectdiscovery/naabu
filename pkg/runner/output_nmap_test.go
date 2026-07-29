package runner

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/stretchr/testify/require"
)

func sampleHosts() []nmapHostData {
	return []nmapHostData{
		{
			ip:       "93.184.216.34",
			hostname: "example.com",
			ports: []*port.Port{
				{Port: 80, Protocol: protocol.TCP},
				{Port: 443, Protocol: protocol.TCP, Service: &port.Service{Name: "https", Product: "nginx", Version: "1.25"}},
			},
		},
		{ip: "10.0.0.1"}, // alive host, no ports (discovery)
	}
}

func TestWriteNmapXMLIsValidAndComplete(t *testing.T) {
	var buf bytes.Buffer
	start := time.Unix(1_700_000_000, 0)
	end := start.Add(2 * time.Second)
	require.NoError(t, writeNmapXML(&buf, sampleHosts(), SynScan, start, end))

	out := buf.String()
	require.True(t, strings.HasPrefix(out, xml.Header), "must start with xml header")
	require.Contains(t, out, "<!DOCTYPE nmaprun>")

	// Round-trips back into the schema.
	var run xmlRun
	require.NoError(t, xml.Unmarshal([]byte(out), &run))
	require.Equal(t, "naabu", run.Scanner)
	require.Equal(t, "syn", run.ScanInfo.Type)
	require.Len(t, run.Hosts, 2)
	require.Equal(t, 2, run.RunStats.Hosts.Up)

	// First host: hostname + two ports, second port has service.
	h0 := run.Hosts[0]
	require.Equal(t, "93.184.216.34", h0.Addresses[0].Addr)
	require.Equal(t, "ipv4", h0.Addresses[0].AddrType)
	require.NotNil(t, h0.Hostnames)
	require.Equal(t, "example.com", h0.Hostnames.Hostnames[0].Name)
	require.NotNil(t, h0.Ports)
	require.Len(t, h0.Ports.Ports, 2)
	require.Equal(t, "open", h0.Ports.Ports[0].State.State)
	require.NotNil(t, h0.Ports.Ports[1].Service)
	require.Equal(t, "https", h0.Ports.Ports[1].Service.Name)

	// Second host: no ports element.
	require.Nil(t, run.Hosts[1].Ports)
}

func TestWriteGreppable(t *testing.T) {
	var buf bytes.Buffer
	start := time.Unix(1_700_000_000, 0)
	require.NoError(t, writeGreppable(&buf, sampleHosts(), start, start.Add(time.Second)))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.True(t, strings.HasPrefix(lines[0], "# Naabu"))
	require.Contains(t, buf.String(), "Host: 93.184.216.34 (example.com)\tPorts: 80/open/tcp//", "ports line must be present")
	require.Contains(t, buf.String(), "443/open/tcp//https//nginx 1.25/")
	require.Contains(t, buf.String(), "Host: 10.0.0.1 (10.0.0.1)\tStatus: Up")
	require.True(t, strings.HasPrefix(lines[len(lines)-1], "# Naabu done"))
}

func TestGrepSanitizeStripsSeparators(t *testing.T) {
	require.Equal(t, "a|b;c d", grepSanitize("a/b,c\td"))
}

func TestAddrType(t *testing.T) {
	require.Equal(t, "ipv4", addrType("1.2.3.4"))
	require.Equal(t, "ipv6", addrType("2606:2800:220:1:248:1893:25c8:1946"))
}

func newConnectRunner(t *testing.T) *Runner {
	t.Helper()
	options := &Options{
		Host:      []string{"192.168.1.0/24"},
		Ports:     "80",
		ScanType:  ConnectScan,
		IPVersion: []string{"4"},
	}
	runner, err := NewRunner(options)
	require.NoError(t, err)
	t.Cleanup(func() { _ = runner.Close() })
	require.NoError(t, runner.Load())
	return runner
}

func TestCollectNmapHostsPortsBranch(t *testing.T) {
	runner := newConnectRunner(t)

	res := result.NewResult()
	res.AddPort("203.0.113.7", &port.Port{Port: 80, Protocol: protocol.TCP})
	res.AddPort("203.0.113.7", &port.Port{Port: 443, Protocol: protocol.TCP})
	// out-of-version host must be filtered (IPVersion is 4 only).
	res.AddPort("2606:2800:220:1::1", &port.Port{Port: 80, Protocol: protocol.TCP})

	hosts := runner.collectNmapHosts(res)
	require.Len(t, hosts, 1, "ipv6 host must be filtered out")
	require.Equal(t, "203.0.113.7", hosts[0].ip)
	require.Empty(t, hosts[0].hostname, "pure IP scan resolves no hostname")
	require.Len(t, hosts[0].ports, 2)
}

func TestCollectNmapHostsIPsOnlyBranch(t *testing.T) {
	runner := newConnectRunner(t)

	res := result.NewResult()
	res.AddIp("203.0.113.9")

	hosts := runner.collectNmapHosts(res)
	require.Len(t, hosts, 1)
	require.Equal(t, "203.0.113.9", hosts[0].ip)
	require.Empty(t, hosts[0].ports)
}

func TestPrimaryHostname(t *testing.T) {
	runner := newConnectRunner(t)
	// pure IP scan: no hostname store consulted.
	require.Empty(t, runner.primaryHostname("203.0.113.7"))

	runner.hasHostnames.Store(true)
	require.NoError(t, runner.scanner.IPRanger.AddHostWithMetadata("203.0.113.7", "example.com"))
	require.Equal(t, "example.com", runner.primaryHostname("203.0.113.7"))
}

func TestWriteNmapFormatsToFiles(t *testing.T) {
	runner := newConnectRunner(t)
	dir := t.TempDir()
	runner.options.XMLOutput = filepath.Join(dir, "out.xml")
	runner.options.GrepOutput = filepath.Join(dir, "out.grep")

	res := result.NewResult()
	res.AddPort("203.0.113.7", &port.Port{Port: 80, Protocol: protocol.TCP})

	runner.writeNmapFormats(res)

	xmlData, err := os.ReadFile(runner.options.XMLOutput)
	require.NoError(t, err)
	require.Contains(t, string(xmlData), `scanner="naabu"`)
	require.Contains(t, string(xmlData), `portid="80"`)
	var run xmlRun
	require.NoError(t, xml.Unmarshal(xmlData, &run), "written XML must be well-formed")

	grepData, err := os.ReadFile(runner.options.GrepOutput)
	require.NoError(t, err)
	require.Contains(t, string(grepData), "Host: 203.0.113.7")
	require.Contains(t, string(grepData), "80/open/tcp")
}

func TestExpandOutputAll(t *testing.T) {
	opts := &Options{OutputAll: "scan"}
	opts.expandOutputAll()
	require.Equal(t, "scan.json", opts.Output)
	require.True(t, opts.JSON)
	require.Equal(t, "scan.xml", opts.XMLOutput)
	require.Equal(t, "scan.gnmap", opts.GrepOutput)
}

func TestExpandOutputAllRespectsExplicit(t *testing.T) {
	opts := &Options{OutputAll: "scan", Output: "custom.txt", XMLOutput: "custom.xml"}
	opts.expandOutputAll()
	// explicit -o/-oX win, only the unset -oG is derived
	require.Equal(t, "custom.txt", opts.Output)
	require.False(t, opts.JSON)
	require.Equal(t, "custom.xml", opts.XMLOutput)
	require.Equal(t, "scan.gnmap", opts.GrepOutput)
}

func TestExpandOutputAllEmpty(t *testing.T) {
	opts := &Options{}
	opts.expandOutputAll()
	require.Empty(t, opts.Output)
	require.Empty(t, opts.XMLOutput)
	require.Empty(t, opts.GrepOutput)
}

func TestHandleOutputCreatesNestedDir(t *testing.T) {
	runner := newConnectRunner(t)
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c", "out.txt")
	runner.options.Output = nested
	runner.options.DisableStdout = true

	res := result.NewResult()
	res.AddPort("203.0.113.7", &port.Port{Port: 80, Protocol: protocol.TCP})
	runner.handleOutput(res)

	_, err := os.Stat(nested)
	require.NoError(t, err, "output to a non-existent nested path must create the directory")
}

func TestWriteNmapFormatsNoOpWhenUnset(t *testing.T) {
	runner := newConnectRunner(t)
	res := result.NewResult()
	res.AddPort("203.0.113.7", &port.Port{Port: 80, Protocol: protocol.TCP})
	// XMLOutput and GrepOutput are empty: must not panic or create files.
	require.NotPanics(t, func() { runner.writeNmapFormats(res) })
}
