package fingerprint

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// softmatchEndpoint is a synthetic HTTP endpoint at the dial boundary. NULL
// receives a banner; active probes receive only the configured responses.
func softmatchEndpoint(banner string, responses map[string]string) (DialFunc, func() []string) {
	var mu sync.Mutex
	var sent []string
	first := true
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		client, server := net.Pipe()
		mu.Lock()
		null := first && banner != ""
		first = false
		mu.Unlock()
		go func() {
			defer server.Close() //nolint:errcheck
			if null {
				_, _ = server.Write([]byte(banner))
				return
			}
			payload, err := bufio.NewReader(server).ReadString('\n')
			if err != nil {
				return
			}
			mu.Lock()
			sent = append(sent, payload)
			mu.Unlock()
			if response := responses[payload]; response != "" {
				_, _ = server.Write([]byte(response))
			}
		}()
		return client, nil
	}
	return dial, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), sent...) }
}

func TestSoftmatchSkipsUnrelatedProbesAndKeepsVersionUpgrade(t *testing.T) {
	for _, service := range []string{"http", "ssl/http"} {
		t.Run(service, func(t *testing.T) {
			// Given a soft HTTP banner, an unrelated probe and a version-capable probe.
			db := buildTestDB(fmt.Sprintf(`
Probe TCP NULL q||
softmatch http m|^HTTP/1.1 400|
Probe TCP Unrelated q|OTHER\n|
rarity 1
match smtp m|^220|
Probe TCP Version q|GET\n|
rarity 2
match %s m|^HTTP/1.1 200 Server/(\S+)| p/Synthetic/ v/$1/
`, service))
			dial, sent := softmatchEndpoint("HTTP/1.1 400 Bad Request\r\n", map[string]string{"GET\n": "HTTP/1.1 200 Server/1.2\r\n"})
			engine := New(db, WithDialer(dial), WithTimeout(time.Second))
			// When the endpoint is fingerprinted on an unhinted port.
			got := engine.fingerprintOne(context.Background(), Target{IP: "192.0.2.1", Port: 12345, TLSChecked: true})
			// Then only the relevant probe runs and upgrades the version.
			require.NotNil(t, got)
			require.Equal(t, "1.2", got.Version)
			require.Equal(t, []string{"GET\n"}, sent())
		})
	}
}

func TestSoftmatchKeepsExplicitFallbackMatches(t *testing.T) {
	// Given a probe whose HTTP signatures live in an explicit fallback.
	db := buildTestDB(`
Probe TCP NULL q||
softmatch http m|^HTTP/1.1 400|
Probe TCP Signatures q|SIGNATURES\n|
rarity 9
match http m|^HTTP/1.1 200 Server/(\S+)| p/Synthetic/ v/$1/
Probe TCP Options q|OPTIONS\n|
fallback Signatures
`)
	dial, sent := softmatchEndpoint("HTTP/1.1 400 Bad Request\r\n", map[string]string{"OPTIONS\n": "HTTP/1.1 200 Server/2.0\r\n"})
	engine := New(db, WithDialer(dial), WithTimeout(time.Second))
	// When only the referencing probe is eligible at the current intensity.
	got := engine.fingerprintOne(context.Background(), Target{IP: "192.0.2.1", Port: 12345, TLSChecked: true})
	// Then the fallback signature still supplies the version.
	require.NotNil(t, got)
	require.Equal(t, "2.0", got.Version)
	require.Equal(t, []string{"OPTIONS\n"}, sent())
}

func TestSoftmatchFromFallbackBatchNarrowsLaterBatches(t *testing.T) {
	// Given a softmatch obtained after probing starts, with unrelated later probes.
	probes := `Probe TCP Discover q|DISCOVER\n|
rarity 1
softmatch http m|^HTTP/1.1 400|
`
	for i := 0; i < 7; i++ {
		probes += fmt.Sprintf("Probe TCP Other%d q|OTHER%d\\n|\nrarity 2\nmatch smtp m|^220|\n", i, i)
	}
	dial, sent := softmatchEndpoint("", map[string]string{"DISCOVER\n": "HTTP/1.1 400 Bad Request\r\n"})
	engine := New(buildTestDB(probes), WithDialer(dial), WithTimeout(time.Second))
	// When the first batch produces only a softmatch.
	got := engine.fingerprintOne(context.Background(), Target{IP: "192.0.2.1", Port: 12345, TLSChecked: true})
	// Then the soft result survives, and no second batch is sent.
	require.NotNil(t, got)
	require.Equal(t, "http", got.Name)
	require.Len(t, sent(), 4)
}

func TestWithoutSoftmatchKeepsUnrelatedFallbackProbes(t *testing.T) {
	// Given no initial match, followed by an off-port HTTP signature.
	db := buildTestDB(`Probe TCP First q|OTHER\n|
match smtp m|^220|
Probe TCP HTTP q|GET\n|
match http m|^HTTP/1.1 200| p/Synthetic/
`)
	dial, sent := softmatchEndpoint("", map[string]string{"GET\n": "HTTP/1.1 200 OK\r\n"})
	engine := New(db, WithDialer(dial), WithTimeout(time.Second))
	// When normal fallback probing runs without a softmatch.
	got := engine.fingerprintOne(context.Background(), Target{IP: "192.0.2.1", Port: 12345, TLSChecked: true})
	// Then HTTP is still discovered off-port.
	require.NotNil(t, got)
	require.Equal(t, "http", got.Name)
	require.Contains(t, sent(), "GET\n")
}

func TestSoftmatchProbeEligibility(t *testing.T) {
	for _, tc := range []struct {
		name, rules, service string
		want                 bool
	}{
		{"implicit NULL does not qualify", "match smtp m|^220|", "http", false},
		{"explicit NULL qualifies", "fallback NULL", "http", true},
		{"soft signature qualifies", "softmatch http m|^HTTP|", "http", true},
		{"generic SSL does not narrow", "match smtp m|^220|", "ssl", true},
		{"TLS softmatch normalizes", "match http m|^HTTP|", "ssl/http", true},
		{"missing fallback is ignored", "fallback Missing", "http", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a probe database and a known softmatched service.
			db := buildTestDB("Probe TCP NULL q||\nsoftmatch http m|^HTTP|\nProbe TCP Test q|TEST\\n|\n" + tc.rules + "\n")
			engine := New(db)
			// When deciding whether the active probe can recognize the service.
			got := engine.probeSupportsService(db.Probes[1], tc.service)
			// Then implicit NULL signatures do not keep unrelated probes alive.
			require.Equal(t, tc.want, got)
		})
	}
}

func TestCancelledFingerprintDoesNotDial(t *testing.T) {
	// Given cancellation before any fallback probe starts.
	dial, sent := softmatchEndpoint("", nil)
	engine := New(buildTestDB("Probe TCP HTTP q|GET\\n|\nmatch http m|^HTTP|\n"), WithDialer(dial))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// When fingerprinting is requested.
	got := engine.fingerprintOne(ctx, Target{IP: "192.0.2.1", Port: 12345, TLSChecked: true})
	// Then no probe is sent and no result is invented.
	require.Nil(t, got)
	require.Empty(t, sent())
}
