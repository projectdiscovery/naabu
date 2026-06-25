package runner

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
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
