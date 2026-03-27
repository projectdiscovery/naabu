package fingerprint

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type connectionCounter struct {
	count atomic.Int64
}

func startCountingServer(banner string, respond func([]byte) []byte) (int, *connectionCounter, func()) {
	counter := &connectionCounter{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			counter.count.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				if banner != "" {
					_, _ = c.Write([]byte(banner))
				}
				if respond != nil {
					buf := make([]byte, 65535)
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					n, _ := c.Read(buf)
					if n > 0 {
						if resp := respond(buf[:n]); resp != nil {
							_, _ = c.Write(resp)
						}
					}
					time.Sleep(3 * time.Second)
				} else if banner != "" {
					buf := make([]byte, 1024)
					_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
					_, _ = c.Read(buf)
				}
			}(conn)
		}
	}()

	return port, counter, func() { ln.Close() }
}

func loadRealDB(tb testing.TB) *ProbeDB {
	path := LocateNmapProbes()
	if path == "" {
		tb.Skip("nmap-service-probes not found")
	}
	db, err := ParseProbeFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	return db
}

// BenchmarkFingerprintSSH measures single-target SSH detection time.
func BenchmarkFingerprintSSH(b *testing.B) {
	db := loadRealDB(b)
	port, _, cleanup := startCountingServer("SSH-2.0-OpenSSH_9.6\r\n", nil)
	defer cleanup()

	engine := New(db, WithTimeout(3*time.Second), WithWorkers(1))
	targets := []Target{{Host: "127.0.0.1", IP: "127.0.0.1", Port: port, TLSChecked: true}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results := engine.Fingerprint(context.Background(), targets)
		if len(results) == 0 {
			b.Fatal("no results")
		}
	}
}

// BenchmarkParseProbeFile measures nmap-service-probes file parsing time.
func BenchmarkParseProbeFile(b *testing.B) {
	path := LocateNmapProbes()
	if path == "" {
		b.Skip("nmap-service-probes not found")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db, err := ParseProbeFile(path)
		if err != nil {
			b.Fatal(err)
		}
		if len(db.Probes) < 50 {
			b.Fatal("too few probes")
		}
	}
}

// BenchmarkRegexMatching measures raw pattern matching speed.
func BenchmarkRegexMatching(b *testing.B) {
	db := loadRealDB(b)
	nullProbe := db.Probes[0]

	banners := []struct {
		name string
		data []byte
	}{
		{"SSH", []byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")},
		{"FTP", []byte("220 ProFTPD 1.3.8b Server (Debian)\r\n")},
		{"SMTP", []byte("220 mail.example.com ESMTP Postfix (Ubuntu)\r\n")},
		{"HTTP", []byte("HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\n\r\n")},
		{"NoMatch", []byte("UNKNOWN PROTOCOL v1.0\r\n")},
	}

	for _, bb := range banners {
		b.Run(bb.name, func(b *testing.B) {
			engine := New(db, WithTimeout(time.Second))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine.tryMatches(nullProbe.Matches, bb.data)
			}
		})
	}
}

// TestPerformanceProfile gives a comprehensive performance snapshot.
func TestPerformanceProfile(t *testing.T) {
	db := loadRealDB(t)

	t.Logf("Probe database: %d probes, %d total match rules",
		len(db.Probes), countRules(db))

	httpResponder := func(data []byte) []byte {
		if strings.HasPrefix(string(data), "GET") {
			return []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n")
		}
		return nil
	}

	type scenario struct {
		name    string
		banner  string
		respond func([]byte) []byte
		customDB *ProbeDB // nil = use real probes
	}

	scenarios := []scenario{
		{"SSH (NULL probe match)", "SSH-2.0-OpenSSH_9.6\r\n", nil, nil},
		{"FTP (NULL probe match)", "220 ProFTPD 1.3.8b Server (Debian) [::ffff:127.0.0.1]\r\n", nil, nil},
		{"SMTP (NULL probe match)", "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", nil, nil},
		{"HTTP (random port, sequential)", "", httpResponder, nil},
	}

	t.Log("")
	t.Log("=== Single Target Performance ===")
	t.Logf("%-35s %8s %8s %10s", "SERVICE", "CONNS", "TIME", "DETECTED")
	t.Logf("%-35s %8s %8s %10s", strings.Repeat("-", 35), "-----", "------", "--------")

	for _, sc := range scenarios {
		port, counter, cleanup := startCountingServer(sc.banner, sc.respond)
		useDB := db
		if sc.customDB != nil {
			useDB = sc.customDB
		}
		engine := New(useDB, WithTimeout(5*time.Second), WithWorkers(1))
		targets := []Target{{Host: "127.0.0.1", IP: "127.0.0.1", Port: port, TLSChecked: true}}

		counter.count.Store(0)
		start := time.Now()
		results := engine.Fingerprint(context.Background(), targets)
		elapsed := time.Since(start)

		key := fmt.Sprintf("127.0.0.1:%d", port)
		svc := results[key]
		svcName := "(none)"
		if svc != nil {
			svcName = svc.Name
		}

		t.Logf("%-35s %8d %8s %10s", sc.name, counter.count.Load(), elapsed.Round(time.Millisecond), svcName)
		cleanup()
	}

	// HTTP on hinted port (parallel): create a custom DB where GetRequest's
	// ports list includes the mock server's port, simulating real port 80.
	{
		httpPort, httpCounter, httpCleanup := startCountingServer("", httpResponder)
		defer httpCleanup()
		hintedProbes := fmt.Sprintf(`
Probe TCP NULL q||
totalwaitms 6000
match ssh m|^SSH-| p/OpenSSH/

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports %d
match http m|^HTTP/1\.[01] \d+.*Server: ([\w/._-]+)|s p/$1/
`, httpPort)
		hintedDB := buildTestDB(hintedProbes)
		engine := New(hintedDB, WithTimeout(8*time.Second), WithWorkers(1))
		targets := []Target{{Host: "127.0.0.1", IP: "127.0.0.1", Port: httpPort, TLSChecked: true}}

		httpCounter.count.Store(0)
		start := time.Now()
		results := engine.Fingerprint(context.Background(), targets)
		elapsed := time.Since(start)

		key := fmt.Sprintf("127.0.0.1:%d", httpPort)
		svc := results[key]
		svcName := "(none)"
		if svc != nil {
			svcName = svc.Name
		}
		t.Logf("%-35s %8d %8s %10s", "HTTP (port 80, parallel probes)", httpCounter.count.Load(), elapsed.Round(time.Millisecond), svcName)
	}

	// Multi-target throughput test
	t.Log("")
	t.Log("=== Multi-Target Throughput (30 banner services) ===")

	banners := []string{
		"SSH-2.0-OpenSSH_9.6\r\n",
		"220 ProFTPD 1.3.8b Server (Debian)\r\n",
		"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n",
	}

	var ports []int
	var cleanups []func()
	for _, banner := range banners {
		for i := 0; i < 10; i++ {
			port, _, cleanup := startCountingServer(banner, nil)
			ports = append(ports, port)
			cleanups = append(cleanups, cleanup)
		}
	}
	defer func() {
		for _, c := range cleanups {
			c()
		}
	}()

	var targets []Target
	for _, p := range ports {
		targets = append(targets, Target{Host: "127.0.0.1", IP: "127.0.0.1", Port: p, TLSChecked: true})
	}

	t.Logf("%-25s %8s %8s %10s", "WORKERS", "TIME", "DETECTED", "PER-TARGET")
	t.Logf("%-25s %8s %8s %10s", strings.Repeat("-", 25), "------", "--------", "----------")

	for _, workers := range []int{1, 5, 10, 25} {
		engine := New(db, WithTimeout(3*time.Second), WithWorkers(workers))
		start := time.Now()
		results := engine.Fingerprint(context.Background(), targets)
		elapsed := time.Since(start)

		perTarget := elapsed / time.Duration(len(targets))
		t.Logf("workers=%-18d %8s %5d/%-3d %10s",
			workers, elapsed.Round(time.Millisecond), len(results), len(targets), perTarget.Round(time.Microsecond))
	}

	// Regex matching cost
	t.Log("")
	t.Log("=== Regex Matching Cost (per banner, against NULL probe rules) ===")
	nullProbe := db.Probes[0]

	testBanners := []struct {
		name string
		data []byte
	}{
		{"SSH banner", []byte("SSH-2.0-OpenSSH_9.6p1\r\n")},
		{"FTP banner", []byte("220 ProFTPD 1.3.8b\r\n")},
		{"SMTP banner", []byte("220 mail ESMTP Postfix\r\n")},
		{"HTTP response", []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")},
		{"Unknown (no match)", []byte("UNKNOWN PROTOCOL v1.0\r\n")},
	}

	for _, bb := range testBanners {
		// Cold run (no cache)
		coldEngine := New(db, WithTimeout(time.Second))
		coldStart := time.Now()
		coldResult := coldEngine.tryMatches(nullProbe.Matches, bb.data)
		coldTime := time.Since(coldStart)

		// Warm run (cached)
		const warmIters = 100
		warmStart := time.Now()
		for i := 0; i < warmIters; i++ {
			coldEngine.tryMatches(nullProbe.Matches, bb.data)
		}
		warmAvg := time.Since(warmStart) / warmIters

		matchStr := "no"
		if coldResult != nil {
			matchStr = "yes"
		}
		t.Logf("  %-25s cold=%8s  warm=%8s  matched=%s  (%d rules)",
			bb.name, coldTime.Round(time.Microsecond), warmAvg.Round(time.Microsecond), matchStr, len(nullProbe.Matches))
	}
}

// TestParallelProbeSpeedup demonstrates that parallel probe execution
// eliminates the NULL probe timeout bottleneck for services that need
// active probes (like HTTP).
func TestParallelProbeSpeedup(t *testing.T) {
	port, _, cleanup := startCountingServer("", func(data []byte) []byte {
		if strings.HasPrefix(string(data), "GET") {
			return []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n")
		}
		return nil
	})
	defer cleanup()

	// Create probes where both NULL and GetRequest are hinted for our port.
	// This simulates what happens on real port 80 with the nmap probe file.
	probes := fmt.Sprintf(`
Probe TCP NULL q||
totalwaitms 6000
match ssh m|^SSH-| p/OpenSSH/

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports %d
match http m|^HTTP/1\.[01] \d+.*Server: ([\w/._-]+)|s p/$1/
`, port)

	db := buildTestDB(probes)
	engine := New(db, WithTimeout(8*time.Second), WithWorkers(1))
	targets := []Target{{Host: "127.0.0.1", IP: "127.0.0.1", Port: port, TLSChecked: true}}

	start := time.Now()
	results := engine.Fingerprint(context.Background(), targets)
	elapsed := time.Since(start)

	key := fmt.Sprintf("127.0.0.1:%d", port)
	svc := results[key]
	if svc == nil {
		t.Fatal("expected service detection result")
	}
	if svc.Name != "http" {
		t.Errorf("expected 'http', got %q", svc.Name)
	}

	t.Logf("HTTP detected in %s (NULL probe timeout is 6s)", elapsed.Round(time.Millisecond))

	// With parallel probes, GetRequest should match while NULL is still
	// waiting for a banner. Detection should complete in well under 1s,
	// not 6s+ which is what sequential execution would take.
	if elapsed > 2*time.Second {
		t.Errorf("parallel probes should complete in <2s, took %s (NULL probe is blocking)", elapsed)
	}
}

func countRules(db *ProbeDB) int {
	n := 0
	for _, p := range db.Probes {
		n += len(p.Matches)
		n += len(p.SoftMatches)
	}
	return n
}
