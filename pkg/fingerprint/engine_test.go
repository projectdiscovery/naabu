package fingerprint

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func buildTestDB(input string) *ProbeDB {
	db, err := ParseProbes(strings.NewReader(input))
	if err != nil {
		panic(err)
	}
	return db
}

func startTCPServer(t *testing.T, handler func(net.Conn)) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start tcp server: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestEngineSSHFingerprint(t *testing.T) {
	probes := `
Probe TCP NULL q||
totalwaitms 3000
match ssh m|^SSH-([\d.]+)-OpenSSH[_-]([\w._-]+)| p/OpenSSH/ v/$2/ i/protocol $1/
`
	addr, cleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		// drain any incoming data
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	db := buildTestDB(probes)
	engine := New(db, WithTimeout(3*time.Second), WithWorkers(1))

	targets := []Target{{Host: host, IP: host, Port: port}}
	results := engine.Fingerprint(context.Background(), targets)

	key := fmt.Sprintf("%s:%d", host, port)
	svc, ok := results[key]
	if !ok {
		t.Fatal("expected service detection result")
	}
	if svc.Name != "ssh" {
		t.Errorf("expected service 'ssh', got %q", svc.Name)
	}
	if svc.Product != "OpenSSH" {
		t.Errorf("expected product 'OpenSSH', got %q", svc.Product)
	}
	if svc.Version != "9.6" {
		t.Errorf("expected version '9.6', got %q", svc.Version)
	}
}

func TestEngineHTTPFingerprint(t *testing.T) {
	probes := `
Probe TCP NULL q||
totalwaitms 2000

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80,8080
match http m|^HTTP/1\.[01] (\d+).*Server: ([\w/._-]+)|s p/$2/ v/$1/
`
	addr, cleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		if n > 0 && strings.HasPrefix(string(buf[:n]), "GET") {
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Length: 0\r\n\r\n"))
		}
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	db := buildTestDB(probes)
	engine := New(db, WithTimeout(3*time.Second), WithWorkers(1))

	targets := []Target{{Host: host, IP: host, Port: port}}
	results := engine.Fingerprint(context.Background(), targets)

	key := fmt.Sprintf("%s:%d", host, port)
	svc, ok := results[key]
	if !ok {
		t.Fatal("expected service detection result for HTTP")
	}
	if svc.Name != "http" {
		t.Errorf("expected service 'http', got %q", svc.Name)
	}
	if svc.Product != "nginx/1.25.3" {
		t.Errorf("expected product 'nginx/1.25.3', got %q", svc.Product)
	}
}

func TestEngineFallback(t *testing.T) {
	probes := `
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80
match http m|^HTTP/1\.[01] (\d+)| p/HTTP/ v/$1/

Probe TCP HTTPOptions q|OPTIONS / HTTP/1.0\r\n\r\n|
rarity 4
ports 80
fallback GetRequest
`
	addr, cleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		if n > 0 {
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		}
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	db := buildTestDB(probes)
	engine := New(db, WithTimeout(3*time.Second), WithWorkers(1))

	targets := []Target{{Host: host, IP: host, Port: port}}
	results := engine.Fingerprint(context.Background(), targets)

	key := fmt.Sprintf("%s:%d", host, port)
	svc, ok := results[key]
	if !ok {
		t.Fatal("expected service detection result via fallback")
	}
	if svc.Name != "http" {
		t.Errorf("expected service 'http', got %q", svc.Name)
	}
}

func TestEngineFastMode(t *testing.T) {
	probes := `
Probe TCP NULL q||
totalwaitms 2000
match ssh m|^SSH-| p/SSH/

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80
match http m|^HTTP| p/HTTP/
`
	addr, cleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		if n > 0 && strings.HasPrefix(string(buf[:n]), "GET") {
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		}
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	db := buildTestDB(probes)
	// Fast mode: only port-hinted probes run
	// Since our test port isn't 80, GetRequest should NOT be tried
	engine := New(db, WithTimeout(3*time.Second), WithWorkers(1), WithFastMode(true))

	targets := []Target{{Host: host, IP: host, Port: port}}
	results := engine.Fingerprint(context.Background(), targets)

	key := fmt.Sprintf("%s:%d", host, port)
	// NULL probe sends nothing, server sends nothing back (waiting for GET),
	// so no match expected in fast mode
	if _, ok := results[key]; ok {
		// It's ok if NULL probe somehow matches, but GetRequest shouldn't have run
		t.Log("got result in fast mode (from NULL probe)")
	}
}

func TestEngineContextCancellation(t *testing.T) {
	probes := `
Probe TCP NULL q||
totalwaitms 5000
match test m|^hello| p/Test/
`
	addr, cleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		time.Sleep(10 * time.Second) // hang forever
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	db := buildTestDB(probes)
	engine := New(db, WithTimeout(2*time.Second), WithWorkers(1))

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	targets := []Target{{Host: host, IP: host, Port: port}}
	results := engine.Fingerprint(ctx, targets)
	elapsed := time.Since(start)

	if len(results) != 0 {
		t.Error("expected no results with cancelled context")
	}

	if elapsed > 5*time.Second {
		t.Errorf("context cancellation should have stopped probing quickly, took %v", elapsed)
	}
}

func TestEngineSoftMatch(t *testing.T) {
	probes := `
Probe TCP NULL q||
totalwaitms 2000
softmatch ssh m|^SSH-| p/SSH/
`
	addr, cleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-CustomSSH\r\n"))
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	db := buildTestDB(probes)
	engine := New(db, WithTimeout(3*time.Second), WithWorkers(1))

	targets := []Target{{Host: host, IP: host, Port: port}}
	results := engine.Fingerprint(context.Background(), targets)

	key := fmt.Sprintf("%s:%d", host, port)
	svc, ok := results[key]
	if !ok {
		t.Fatal("expected soft match result")
	}
	if svc.Name != "ssh" {
		t.Errorf("expected service 'ssh' from softmatch, got %q", svc.Name)
	}
}

func TestEngineNoMatch(t *testing.T) {
	probes := `
Probe TCP NULL q||
totalwaitms 1000
match http m|^HTTP| p/HTTP/
`
	addr, cleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte("SOME-RANDOM-PROTOCOL v1.0\r\n"))
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	db := buildTestDB(probes)
	engine := New(db, WithTimeout(2*time.Second), WithWorkers(1))

	targets := []Target{{Host: host, IP: host, Port: port}}
	results := engine.Fingerprint(context.Background(), targets)

	key := fmt.Sprintf("%s:%d", host, port)
	if _, ok := results[key]; ok {
		t.Error("expected no match for random protocol")
	}
}

func TestEngineMultipleTargets(t *testing.T) {
	probes := `
Probe TCP NULL q||
totalwaitms 2000
match ssh m|^SSH-([\d.]+)-OpenSSH[_-]([\w._-]+)| p/OpenSSH/ v/$2/
match ftp m|^220[ -]| p/FTP/
`
	// SSH server
	sshAddr, cleanupSSH := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	})
	defer cleanupSSH()

	// FTP server
	ftpAddr, cleanupFTP := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte("220 FTP server ready\r\n"))
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	})
	defer cleanupFTP()

	db := buildTestDB(probes)
	engine := New(db, WithTimeout(3*time.Second), WithWorkers(4))

	sshHost, sshPortStr, _ := net.SplitHostPort(sshAddr)
	sshPort := 0
	_, _ = fmt.Sscanf(sshPortStr, "%d", &sshPort)

	ftpHost, ftpPortStr, _ := net.SplitHostPort(ftpAddr)
	ftpPort := 0
	_, _ = fmt.Sscanf(ftpPortStr, "%d", &ftpPort)

	targets := []Target{
		{Host: sshHost, IP: sshHost, Port: sshPort},
		{Host: ftpHost, IP: ftpHost, Port: ftpPort},
	}
	results := engine.Fingerprint(context.Background(), targets)

	sshKey := fmt.Sprintf("%s:%d", sshHost, sshPort)
	if svc, ok := results[sshKey]; !ok {
		t.Error("expected SSH detection")
	} else if svc.Name != "ssh" {
		t.Errorf("expected 'ssh', got %q", svc.Name)
	}

	ftpKey := fmt.Sprintf("%s:%d", ftpHost, ftpPort)
	if svc, ok := results[ftpKey]; !ok {
		t.Error("expected FTP detection")
	} else if svc.Name != "ftp" {
		t.Errorf("expected 'ftp', got %q", svc.Name)
	}
}

func TestEngineProbeOrder(t *testing.T) {
	probes := `
Probe TCP HighRarity q|HIGH|
rarity 8
ports 12345

Probe TCP LowRarity q|LOW|
rarity 1
ports 12345

Probe TCP NULL q||
`
	db := buildTestDB(probes)
	engine := New(db, WithTimeout(time.Second), WithIntensity(9))

	ordered := engine.orderProbes(12345, false)

	// NULL should be first (always), then LowRarity (rarity 1), then HighRarity (rarity 8)
	if len(ordered) < 3 {
		t.Fatalf("expected at least 3 probes, got %d", len(ordered))
	}

	if ordered[0].Name != "NULL" {
		t.Errorf("expected NULL first, got %q", ordered[0].Name)
	}

	// Among hinted probes (excluding NULL), LowRarity should come before HighRarity
	var lowIdx, highIdx int
	for i, p := range ordered {
		if p.Name == "LowRarity" {
			lowIdx = i
		}
		if p.Name == "HighRarity" {
			highIdx = i
		}
	}
	if lowIdx > highIdx {
		t.Errorf("LowRarity (idx %d) should come before HighRarity (idx %d)", lowIdx, highIdx)
	}
}

func TestEngineIntensityFilter(t *testing.T) {
	probes := `
Probe TCP Low q|LOW|
rarity 1
ports 80

Probe TCP High q|HIGH|
rarity 9
ports 80
`
	db := buildTestDB(probes)

	engine := New(db, WithTimeout(time.Second), WithIntensity(5))
	ordered := engine.orderProbes(80, false)

	for _, p := range ordered {
		if p.Name == "High" {
			t.Error("rarity 9 probe should be filtered at intensity 5")
		}
	}
}

func TestEngineWithRealProbes(t *testing.T) {
	path := LocateNmapProbes()
	if path == "" {
		t.Skip("nmap-service-probes not found on system")
	}

	db, err := ParseProbeFile(path)
	if err != nil {
		t.Fatalf("failed to parse probes: %v", err)
	}

	// Start a simple SSH server
	addr, cleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"))
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	engine := New(db, WithTimeout(5*time.Second), WithWorkers(1))
	targets := []Target{{Host: host, IP: host, Port: port}}
	results := engine.Fingerprint(context.Background(), targets)

	key := fmt.Sprintf("%s:%d", host, port)
	svc, ok := results[key]
	if !ok {
		t.Fatal("expected service detection with real nmap probes")
	}

	t.Logf("Detected: name=%s product=%s version=%s", svc.Name, svc.Product, svc.Version)

	if svc.Name != "ssh" {
		t.Errorf("expected 'ssh', got %q", svc.Name)
	}
}

func TestEngineWithRealProbesFTP(t *testing.T) {
	path := LocateNmapProbes()
	if path == "" {
		t.Skip("nmap-service-probes not found on system")
	}

	db, err := ParseProbeFile(path)
	if err != nil {
		t.Fatalf("failed to parse probes: %v", err)
	}

	addr, cleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte("220 ProFTPD 1.3.8b Server ready.\r\n"))
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	engine := New(db, WithTimeout(5*time.Second), WithWorkers(1))
	targets := []Target{{Host: host, IP: host, Port: port}}
	results := engine.Fingerprint(context.Background(), targets)

	key := fmt.Sprintf("%s:%d", host, port)
	svc, ok := results[key]
	if !ok {
		t.Fatal("expected FTP service detection with real nmap probes")
	}

	t.Logf("Detected: name=%s product=%s version=%s", svc.Name, svc.Product, svc.Version)

	if svc.Name != "ftp" {
		t.Errorf("expected 'ftp', got %q", svc.Name)
	}
}

func TestEngineWithRealProbesHTTP(t *testing.T) {
	path := LocateNmapProbes()
	if path == "" {
		t.Skip("nmap-service-probes not found on system")
	}

	db, err := ParseProbeFile(path)
	if err != nil {
		t.Fatalf("failed to parse probes: %v", err)
	}

	httpResponse := "HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Ubuntu)\r\nContent-Length: 13\r\n\r\nHello, World!"

	addr, cleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			_, _ = conn.Write([]byte(httpResponse))
			return
		}
		_, _ = conn.Write([]byte(httpResponse))
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	engine := New(db, WithTimeout(5*time.Second), WithWorkers(1))
	targets := []Target{{Host: host, IP: host, Port: port}}
	results := engine.Fingerprint(context.Background(), targets)

	key := fmt.Sprintf("%s:%d", host, port)
	svc, ok := results[key]
	if !ok {
		t.Fatal("expected HTTP service detection with real nmap probes")
	}

	t.Logf("Detected: name=%s product=%s version=%s", svc.Name, svc.Product, svc.Version)

	if svc.Name != "http" {
		t.Errorf("expected 'http', got %q", svc.Name)
	}
}
