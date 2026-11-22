package runner

import (
	"bytes"
	"encoding/json"
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

func tcpPorts(nums ...int) []*port.Port {
	ports := make([]*port.Port, 0, len(nums))
	for _, n := range nums {
		ports = append(ports, &port.Port{Port: n, Protocol: protocol.TCP})
	}
	return ports
}

func portRange(from, to int) []int {
	var nums []int
	for n := from; n <= to; n++ {
		nums = append(nums, n)
	}
	return nums
}

func TestPortStatesCountsFiltered(t *testing.T) {
	runner := newConnectRunner(t)
	runner.options.PortState = true
	runner.scanner.Ports = append(tcpPorts(22, 80, 443, 8080), &port.Port{Port: 53, Protocol: protocol.UDP})
	runner.enableFilteredCount(nil)

	res := result.NewResult()
	res.AddPort("203.0.113.7", &port.Port{Port: 80, Protocol: protocol.TCP})
	res.AddClosedPort("203.0.113.7", &port.Port{Port: 22, Protocol: protocol.TCP})
	res.AddClosedPort("203.0.113.8", &port.Port{Port: 443, Protocol: protocol.TCP})
	res.AddPort("203.0.113.9", &port.Port{Port: 80, Protocol: protocol.TCP})
	res.AddSkipped("203.0.113.9")

	states := runner.portStates(res)
	require.Len(t, states, 3)
	require.Equal(t, 2, states["203.0.113.7"].filtered, "4 tcp probes, 1 open, 1 closed")
	require.Len(t, states["203.0.113.7"].closed, 1)
	require.Equal(t, 3, states["203.0.113.8"].filtered)
	require.Equal(t, -1, states["203.0.113.9"].filtered, "a -port-threshold host was not fully probed")
}

func TestPortStatesFilteredUnknown(t *testing.T) {
	for name, setup := range map[string]func(r *Runner){
		"smart scan":      func(r *Runner) { r.options.SmartScan = true; r.enableFilteredCount(nil) },
		"ip:port targets": func(r *Runner) { r.enableFilteredCount([]string{"203.0.113.7:80"}) },
	} {
		t.Run(name, func(t *testing.T) {
			runner := newConnectRunner(t)
			runner.options.PortState = true
			setup(runner)

			res := result.NewResult()
			res.AddPort("203.0.113.7", &port.Port{Port: 80, Protocol: protocol.TCP})
			res.AddClosedPort("203.0.113.8", &port.Port{Port: 22, Protocol: protocol.TCP})

			states := runner.portStates(res)
			require.Len(t, states, 1, "only hosts with closed ports are reported")
			require.Equal(t, -1, states["203.0.113.8"].filtered)
		})
	}
}

func TestPortStatesOff(t *testing.T) {
	runner := newConnectRunner(t)
	res := result.NewResult()
	res.AddClosedPort("203.0.113.8", &port.Port{Port: 22, Protocol: protocol.TCP})
	require.Nil(t, runner.portStates(res))
}

func TestWriteNmapXMLPortStates(t *testing.T) {
	hosts := []nmapHostData{
		{ip: "203.0.113.7", ports: tcpPorts(80), closed: tcpPorts(22, 443), filtered: 997},
		{ip: "203.0.113.8", closed: tcpPorts(portRange(1, collapseThreshold+1)...)},
	}
	var buf bytes.Buffer
	start := time.Unix(1_700_000_000, 0)
	require.NoError(t, writeNmapXML(&buf, hosts, SynScan, start, start.Add(time.Second)))

	var run xmlRun
	require.NoError(t, xml.Unmarshal(buf.Bytes(), &run))
	require.Len(t, run.Hosts, 2)

	listed := run.Hosts[0].Ports
	require.Equal(t, []xmlExtraPorts{newXMLExtraPorts("filtered", "no-response", 997)}, listed.Extra)
	require.Len(t, listed.Ports, 3)
	require.Equal(t, xmlPortState{State: "closed", Reason: "reset"}, listed.Ports[0].State, "ports sort by number")
	require.Equal(t, "open", listed.Ports[1].State.State)
	require.Equal(t, "closed", listed.Ports[2].State.State)

	collapsed := run.Hosts[1]
	require.Equal(t, "reset", collapsed.Status.Reason)
	require.Empty(t, collapsed.Ports.Ports)
	require.Equal(t, []xmlExtraPorts{newXMLExtraPorts("closed", "reset", collapseThreshold+1)}, collapsed.Ports.Extra)
}

func TestWriteGreppablePortStates(t *testing.T) {
	hosts := []nmapHostData{
		{ip: "203.0.113.7", ports: tcpPorts(80), closed: tcpPorts(22), filtered: 997},
		{ip: "203.0.113.8", closed: tcpPorts(portRange(1, collapseThreshold+1)...), filtered: 3},
	}
	var buf bytes.Buffer
	start := time.Unix(1_700_000_000, 0)
	require.NoError(t, writeGreppable(&buf, hosts, start, start.Add(time.Second)))

	out := buf.String()
	require.Contains(t, out, "Host: 203.0.113.7 (203.0.113.7)\tPorts: 22/closed/tcp/////, 80/open/tcp/////\tIgnored State: filtered (997)\n")
	require.Contains(t, out, "Host: 203.0.113.8 (203.0.113.8)\tPorts: \tIgnored State: closed (26)\n")
}

func TestOutputPortStatesJSON(t *testing.T) {
	runner := newConnectRunner(t)
	runner.options.PortState = true
	runner.options.JSON = true
	runner.options.DisableStdout = true

	file, err := os.Create(filepath.Join(t.TempDir(), "out.json"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	header := true
	states := map[string]hostPortStates{"203.0.113.8": {closed: tcpPorts(22, 23), filtered: 5}}
	runner.outputPortStates(states, file, &header, &header)

	data, err := os.ReadFile(file.Name())
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 2)
	var record map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &record))
	require.Equal(t, "closed", record["state"])
	require.EqualValues(t, 22, record["port"])
	require.Equal(t, "203.0.113.8", record["ip"])
}
