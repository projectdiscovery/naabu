package runner

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/stretchr/testify/require"
)

func TestCompletedEndpointOutputPrecedesFinalOutput(t *testing.T) {
	for _, format := range []string{"plain", "json", "csv"} {
		t.Run(format, func(t *testing.T) {
			// Given two completed endpoints, including one without a service match.
			r := newConnectRunner(t)
			r.options.ServiceVersion = true
			buf := &bytes.Buffer{}
			gologger.DefaultLogger.SetWriter(captureWriter{buf: buf})
			gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
			t.Cleanup(func() {
				gologger.DefaultLogger.SetWriter(writer.NewCLI())
				gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
			})
			r.options.Output = filepath.Join(t.TempDir(), "results")
			r.options.JSON = format == "json"
			r.options.CSV = format == "csv"
			r.fpOutput = true
			r.fpCSVFileHeader, r.fpCSVStdoutHeader = true, true
			known := &port.Port{Port: 80, Protocol: protocol.TCP, Service: &port.Service{Name: "http"}}
			unknown := &port.Port{Port: 81, Protocol: protocol.TCP}
			all := result.NewResult()
			all.AddPort("192.0.2.1", known)
			all.AddPort("192.0.2.1", unknown)
			callbacks := 0
			r.options.OnResult = func(hr *result.HostResult) { callbacks++; require.Len(t, hr.Ports, 2) }

			// When results complete while enumeration has not reached final output.
			r.writeOutput(nil, &result.HostResult{IP: "192.0.2.1", Ports: []*port.Port{known}})
			first, err := os.ReadFile(r.options.Output)
			require.NoError(t, err)
			require.Contains(t, string(first), "192.0.2.1")
			r.writeOutput(nil, &result.HostResult{IP: "192.0.2.1", Ports: []*port.Port{unknown}})
			early, err := os.ReadFile(r.options.Output)
			require.NoError(t, err)
			require.Zero(t, callbacks)
			earlyStdout := buf.String()
			require.Contains(t, earlyStdout, "192.0.2.1")
			r.handleOutput(all)

			// Then both endpoints remain on disk exactly once after final output.
			final, err := os.ReadFile(r.options.Output)
			require.NoError(t, err)
			require.Equal(t, string(early), string(final))
			require.Equal(t, earlyStdout, buf.String())
			require.Equal(t, 1, callbacks)
			lines := strings.Split(strings.TrimSpace(string(final)), "\n")
			if format == "csv" {
				require.Len(t, lines, 3)
				reader := csv.NewReader(strings.NewReader(string(final)))
				// Header width is tracked separately by upstream issue #1809.
				reader.FieldsPerRecord = -1
				records, err := reader.ReadAll()
				require.NoError(t, err)
				require.Equal(t, "host", records[0][0])
			} else {
				require.Len(t, lines, 2)
			}
			if format == "json" {
				var got []map[string]any
				for _, line := range lines {
					var row map[string]any
					require.NoError(t, json.Unmarshal([]byte(line), &row))
					got = append(got, row)
				}
				require.Equal(t, "http", got[0]["name"])
				require.NotContains(t, got[1], "name")
			}
		})
	}
}

func TestServiceOutputClearsPreviousFileWithoutResults(t *testing.T) {
	// Given a previous output file and no completed endpoints.
	r := newConnectRunner(t)
	r.fpOutput = true
	r.options.Output = filepath.Join(t.TempDir(), "out")
	require.NoError(t, os.WriteFile(r.options.Output, []byte("stale"), 0600))
	// When the empty scan finishes.
	r.handleOutput(result.NewResult())
	// Then stale results are removed.
	data, err := os.ReadFile(r.options.Output)
	require.NoError(t, err)
	require.Empty(t, data)
}

func TestCustomReceiveCallbackKeepsFinalServiceOutput(t *testing.T) {
	// Given an SDK caller replacing the internal receive handler.
	r := newConnectRunner(t)
	r.options.ServiceVersion = true
	r.options.OnReceive = func(*result.HostResult) {}
	r.options.DisableStdout = true
	r.options.Output = filepath.Join(t.TempDir(), "out")
	r.initServiceDetection(context.Background())
	res := result.NewResult()
	res.AddPort("192.0.2.1", &port.Port{Port: 80, Protocol: protocol.TCP})
	r.waitServiceDetection(res)
	// When final output runs without internal fingerprint events.
	r.handleOutput(res)
	// Then discovered ports are still written.
	data, err := os.ReadFile(r.options.Output)
	require.NoError(t, err)
	require.Contains(t, string(data), "192.0.2.1:80")
}

func TestServiceDiscoveryResponseDoesNotBecomeOpenPort(t *testing.T) {
	// Given a TCP host-discovery response that may be a closed-port RST.
	r := newConnectRunner(t)
	r.options.ServiceVersion = true
	r.scanner.ListenHandler.Phase.Set(scan.HostDiscovery)
	r.fpQueue = newFpQueue()
	// When that response reaches the receive handler.
	r.onReceive(&result.HostResult{IP: "192.0.2.1", Ports: []*port.Port{{Port: 80, Protocol: protocol.TCP}}})
	r.fpQueue.close()
	// Then no endpoint is queued for publication.
	_, ok := r.fpQueue.pop()
	require.False(t, ok)
}

func TestFinalServiceOutputKeepsUnfinishedEndpoints(t *testing.T) {
	// Given one exported endpoint and another still awaiting fingerprinting.
	r := newConnectRunner(t)
	r.options.ServiceVersion = true
	r.options.DisableStdout = true
	r.options.JSON = true
	r.options.Output = filepath.Join(t.TempDir(), "out")
	r.fpOutput = true
	first := &port.Port{Port: 80, Protocol: protocol.TCP}
	pending := &port.Port{Port: 81, Protocol: protocol.TCP}
	r.writeOutput(nil, &result.HostResult{IP: "192.0.2.1", Ports: []*port.Port{first}})
	res := result.NewResult()
	res.AddPort("192.0.2.1", first)
	res.AddPort("192.0.2.1", pending)
	// When graceful final output runs after fingerprinting is interrupted.
	r.handleOutput(res)
	// Then both discovered ports are preserved exactly once.
	data, err := os.ReadFile(r.options.Output)
	require.NoError(t, err)
	require.Len(t, strings.Split(strings.TrimSpace(string(data)), "\n"), 2)
	require.Contains(t, string(data), `"port":81`)
}

func TestFinalServiceOutputAppendsDeadHosts(t *testing.T) {
	// Given an exported port and a dead host recorded during discovery.
	r := newConnectRunner(t)
	r.options.ServiceVersion = true
	r.options.DisableStdout = true
	r.options.JSON = true
	r.options.ShowDeadHosts = true
	r.options.Output = filepath.Join(t.TempDir(), "out")
	r.fpOutput = true
	p := &port.Port{Port: 80, Protocol: protocol.TCP}
	r.writeOutput(nil, &result.HostResult{IP: "192.0.2.1", Ports: []*port.Port{p}})
	res := result.NewResult()
	res.AddPort("192.0.2.1", p)
	r.scanner.HostDiscoveryResults.AddDeadHost("192.0.2.2")
	// When final output writes discovery information.
	r.handleOutput(res)
	// Then the file retains the port and includes the dead host.
	data, err := os.ReadFile(r.options.Output)
	require.NoError(t, err)
	require.Contains(t, string(data), `"is_dead_host":true`)
	require.Len(t, strings.Split(strings.TrimSpace(string(data)), "\n"), 2)
}

func TestUnmatchedCompletionPreservesNmapService(t *testing.T) {
	// Given a service already enriched by nmap and an unmatched fingerprint completion.
	r := newConnectRunner(t)
	r.fpServices = make(map[string]*port.Service)
	r.fpDone = make(chan struct{})
	r.fpQueue = newFpQueue()
	res := result.NewResult()
	res.AddPort("192.0.2.1", &port.Port{Port: 80, Protocol: protocol.TCP, Service: &port.Service{Name: "http"}})
	completions := make(chan fingerprint.StreamResult, 1)
	completions <- fingerprint.StreamResult{IP: "192.0.2.1", Port: 80}
	close(completions)
	// When fingerprinting finishes and services are merged.
	r.consumeServiceResults(completions)
	r.waitServiceDetection(res)
	// Then a missing match does not erase the nmap enrichment.
	hr := <-res.GetIPsPorts()
	require.NotNil(t, hr.Ports[0].Service)
	require.Equal(t, "http", hr.Ports[0].Service.Name)
}

func TestFinalServiceOutputRetriesFailedFileOpen(t *testing.T) {
	// Given an output path that is temporarily a directory.
	r := newConnectRunner(t)
	r.options.ServiceVersion = true
	r.options.DisableStdout = true
	r.options.Output = filepath.Join(t.TempDir(), "out")
	require.NoError(t, os.Mkdir(r.options.Output, 0700))
	r.fpOutput = true
	p := &port.Port{Port: 80, Protocol: protocol.TCP}
	r.writeOutput(nil, &result.HostResult{IP: "192.0.2.1", Ports: []*port.Port{p}})
	require.NoError(t, os.Remove(r.options.Output))
	require.NoError(t, os.WriteFile(r.options.Output, []byte("stale"), 0600))
	res := result.NewResult()
	res.AddPort("192.0.2.1", p)
	// When final output retries after the path becomes writable.
	r.handleOutput(res)
	// Then the endpoint is preserved in the file.
	data, err := os.ReadFile(r.options.Output)
	require.NoError(t, err)
	require.Contains(t, string(data), "192.0.2.1:80")
	require.NotContains(t, string(data), "stale")
}
