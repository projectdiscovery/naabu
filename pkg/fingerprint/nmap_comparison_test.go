package fingerprint

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// mockService defines a mock service for comparison testing.
type mockService struct {
	name          string
	banner        string              // sent immediately (NULL probe banner)
	respond       func([]byte) []byte // optional: respond to probe data
	expectService string
	expectProduct string
	expectVersion string
}

var comparisonServices = []mockService{
	{
		name:          "OpenSSH",
		banner:        "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n",
		expectService: "ssh",
		expectProduct: "OpenSSH",
		expectVersion: "9.6p1 Ubuntu 3ubuntu13.5",
	},
	{
		name:          "ProFTPD",
		banner:        "220 ProFTPD 1.3.8b Server (Debian) [::ffff:10.0.0.1]\r\n",
		expectService: "ftp",
		expectProduct: "ProFTPD",
		expectVersion: "1.3.8b",
	},
	{
		name:          "vsftpd",
		banner:        "220 (vsFTPd 3.0.5)\r\n",
		expectService: "ftp",
		expectProduct: "vsftpd",
		expectVersion: "3.0.5",
	},
	{
		name:          "Postfix SMTP",
		banner:        "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n",
		expectService: "smtp",
		expectProduct: "Postfix smtpd",
	},
	{
		name:          "Exim SMTP",
		banner:        "220 mail.example.org ESMTP Exim 4.97.1 Tue, 25 Mar 2025 12:00:00 +0000\r\n",
		expectService: "smtp",
		expectProduct: "Exim smtpd",
		expectVersion: "4.97.1",
	},
	{
		name:          "Dovecot IMAP",
		banner:        "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN AUTH=LOGIN] Dovecot (Ubuntu) ready.\r\n",
		expectService: "imap",
		expectProduct: "Dovecot imapd",
	},
	{
		name:          "Dovecot POP3",
		banner:        "+OK Dovecot ready.\r\n",
		expectService: "pop3",
		expectProduct: "Dovecot pop3d",
	},
	{
		name:          "MySQL 8.0",
		expectService: "mysql",
		banner: string(append(
			// Length (74) + sequence (0) + protocol version (10) + version string
			[]byte{0x4a, 0x00, 0x00, 0x00, 0x0a},
			append([]byte("8.0.36"), // version string
				append([]byte{0x00}, // null terminator
					// thread id + auth plugin data + filler + capability flags (enough for match)
					[]byte{0x01, 0x00, 0x00, 0x00,
						0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, // scramble
						0x00,       // filler
						0xff, 0xff, // capability flags lower
						0x21,       // charset
						0x02, 0x00, // status flags
						0x3f, 0x40, // capability flags upper
					}...,
				)...,
			)...,
		)),
	},
	{
		name:          "nginx HTTP",
		expectService: "http",
		expectProduct: "nginx",
		expectVersion: "1.24.0",
		respond: func(data []byte) []byte {
			if len(data) > 0 {
				return []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nContent-Length: 0\r\n\r\n")
			}
			return nil
		},
	},
	{
		name:          "Apache HTTP",
		expectService: "http",
		expectProduct: "Apache httpd",
		expectVersion: "2.4.58",
		respond: func(data []byte) []byte {
			if len(data) > 0 {
				return []byte("HTTP/1.1 200 OK\r\nDate: Tue, 25 Mar 2025 12:00:00 GMT\r\nServer: Apache/2.4.58 (Ubuntu)\r\nContent-Length: 0\r\n\r\n")
			}
			return nil
		},
	},
	{
		name: "Cisco Telnet",
		// IAC WILL ECHO, WILL SGA, DO NAWS, DO TTYPE — matches Cisco IOS telnetd softmatch
		banner:        "\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f",
		expectService: "telnet",
	},
}

// startMockServer starts a TCP server that simulates a service.
func startMockServer(t *testing.T, svc mockService) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed for %s: %v", svc.name, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck

				if svc.banner != "" {
					_, _ = c.Write([]byte(svc.banner))
				}

				if svc.respond != nil {
					buf := make([]byte, 65535)
					_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
					n, err := c.Read(buf)
					if err != nil || n == 0 {
						time.Sleep(4 * time.Second)
						return
					}
					if resp := svc.respond(buf[:n]); resp != nil {
						_, _ = c.Write(resp)
					}
				} else if svc.banner != "" {
					buf := make([]byte, 1024)
					_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
					_, _ = c.Read(buf)
				}
			}(conn)
		}
	}()

	return port, func() { ln.Close() } //nolint:errcheck
}

// TestNmapComparison starts mock services and compares naabu vs nmap detection.
func TestNmapComparison(t *testing.T) {
	probesPath := LocateNmapProbes()
	if probesPath == "" {
		t.Skip("nmap-service-probes not found on system")
	}

	db, err := ParseProbeFile(probesPath)
	if err != nil {
		t.Fatalf("failed to parse probes: %v", err)
	}

	engine := New(db, WithTimeout(10*time.Second), WithWorkers(len(comparisonServices)))

	type testPort struct {
		svc     mockService
		port    int
		cleanup func()
	}

	var tests []testPort
	for _, svc := range comparisonServices {
		port, cleanup := startMockServer(t, svc)
		tests = append(tests, testPort{svc: svc, port: port, cleanup: cleanup})
	}
	defer func() {
		for _, tp := range tests {
			tp.cleanup()
		}
	}()

	// Build targets
	var targets []Target
	for _, tp := range tests {
		targets = append(targets, Target{
			Host: "127.0.0.1",
			IP:   "127.0.0.1",
			Port: tp.port,
		})
	}

	// Run our engine
	results := engine.Fingerprint(context.Background(), targets)

	t.Log("=== Naabu Service Detection Results ===")
	for _, tp := range tests {
		key := fmt.Sprintf("127.0.0.1:%d", tp.port)
		svc, ok := results[key]

		if !ok {
			t.Errorf("[%s] port %d: NO DETECTION (expected service=%s)", tp.svc.name, tp.port, tp.svc.expectService)
			continue
		}

		t.Logf("[%s] port %d: service=%s product=%s version=%s", tp.svc.name, tp.port, svc.Name, svc.Product, svc.Version)

		if tp.svc.expectService != "" && svc.Name != tp.svc.expectService {
			t.Errorf("[%s] service mismatch: got %q, want %q", tp.svc.name, svc.Name, tp.svc.expectService)
		}
		if tp.svc.expectProduct != "" && svc.Product != tp.svc.expectProduct {
			t.Errorf("[%s] product mismatch: got %q, want %q", tp.svc.name, svc.Product, tp.svc.expectProduct)
		}
		if tp.svc.expectVersion != "" && svc.Version != tp.svc.expectVersion {
			t.Errorf("[%s] version mismatch: got %q, want %q", tp.svc.name, svc.Version, tp.svc.expectVersion)
		}
	}

	// If nmap is available, run it and compare
	nmapPath, err := exec.LookPath("nmap")
	if err != nil {
		t.Log("nmap not found in PATH, skipping nmap comparison")
		return
	}

	t.Log("")
	t.Log("=== Running nmap for comparison ===")

	var portList []string
	for _, tp := range tests {
		portList = append(portList, fmt.Sprintf("%d", tp.port))
	}

	args := []string{
		"-sV",
		"--version-intensity", "7",
		"-p", strings.Join(portList, ","),
		"-Pn",
		"-T4",
		"--host-timeout", "60s",
		"-oX", "-",
		"127.0.0.1",
	}

	t.Logf("Running: %s %s", nmapPath, strings.Join(args, " "))
	cmd := exec.Command(nmapPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("nmap failed (may need root): %v", err)
		t.Log("Comparing with nmap XML output if available...")
	}

	nmapResults := parseNmapXMLServices(string(out))
	if len(nmapResults) == 0 {
		t.Log("No nmap results to compare (nmap may need sudo for -sV)")
		return
	}

	t.Log("")
	t.Log("=== Side-by-side comparison ===")
	t.Logf("%-15s | %-6s | %-20s %-20s | %-20s %-20s | %s",
		"SERVICE", "PORT", "NAABU_SVC", "NAABU_PRODUCT", "NMAP_SVC", "NMAP_PRODUCT", "MATCH?")
	t.Log(strings.Repeat("-", 120))

	matches := 0
	total := 0
	for _, tp := range tests {
		key := fmt.Sprintf("127.0.0.1:%d", tp.port)
		portStr := fmt.Sprintf("%d", tp.port)

		naabuSvc := results[key]
		nmapSvc := nmapResults[portStr]

		naabuName := ""
		naabuProduct := ""
		if naabuSvc != nil {
			naabuName = naabuSvc.Name
			naabuProduct = naabuSvc.Product
		}
		nmapName := ""
		nmapProduct := ""
		if nmapSvc != nil {
			nmapName = nmapSvc.Name
			nmapProduct = nmapSvc.Product
		}

		serviceMatch := naabuName == nmapName
		matchStr := "YES"
		if !serviceMatch {
			matchStr = "MISMATCH"
		}

		total++
		if serviceMatch {
			matches++
		}

		t.Logf("%-15s | %-6s | %-20s %-20s | %-20s %-20s | %s",
			tp.svc.name, portStr, naabuName, naabuProduct, nmapName, nmapProduct, matchStr)
	}

	t.Logf("\nService name match rate: %d/%d (%.0f%%)", matches, total, float64(matches)/float64(total)*100)
}

// nmapXMLService holds service info parsed from nmap XML output.
type nmapXMLService struct {
	Name    string
	Product string
	Version string
}

// parseNmapXMLServices is a quick-and-dirty parser for nmap's XML output.
func parseNmapXMLServices(xmlData string) map[string]*nmapXMLService {
	results := make(map[string]*nmapXMLService)

	for _, line := range strings.Split(xmlData, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "<port ") {
			continue
		}

		portID := extractXMLAttr(line, "portid")
		// Read ahead to find the service element
		svcLine := line
		if !strings.Contains(svcLine, "<service ") {
			continue
		}
		// Find the service tag in the same or subsequent content
		serviceIdx := strings.Index(xmlData, line)
		if serviceIdx < 0 {
			continue
		}
		chunk := xmlData[serviceIdx:]
		svcTagStart := strings.Index(chunk, "<service ")
		if svcTagStart < 0 {
			continue
		}
		svcTagEnd := strings.Index(chunk[svcTagStart:], "/>")
		if svcTagEnd < 0 {
			svcTagEnd = strings.Index(chunk[svcTagStart:], ">")
		}
		if svcTagEnd < 0 {
			continue
		}
		svcTag := chunk[svcTagStart : svcTagStart+svcTagEnd+2]

		if portID != "" {
			results[portID] = &nmapXMLService{
				Name:    extractXMLAttr(svcTag, "name"),
				Product: extractXMLAttr(svcTag, "product"),
				Version: extractXMLAttr(svcTag, "version"),
			}
		}
	}

	// More robust: parse line by line looking for port/service pairs
	if len(results) == 0 {
		lines := strings.Split(xmlData, "\n")
		var currentPort string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "<port ") {
				currentPort = extractXMLAttr(line, "portid")
			}
			if strings.HasPrefix(line, "<service ") && currentPort != "" {
				results[currentPort] = &nmapXMLService{
					Name:    extractXMLAttr(line, "name"),
					Product: extractXMLAttr(line, "product"),
					Version: extractXMLAttr(line, "version"),
				}
				currentPort = ""
			}
		}
	}

	return results
}

func extractXMLAttr(tag, attr string) string {
	key := attr + `="`
	idx := strings.Index(tag, key)
	if idx < 0 {
		return ""
	}
	start := idx + len(key)
	end := strings.Index(tag[start:], `"`)
	if end < 0 {
		return ""
	}
	return tag[start : start+end]
}

// TestNmapComparisonJSON runs naabu detection and outputs results in a format
// that can be compared with nmap's JSON output.
func TestNmapComparisonJSON(t *testing.T) {
	probesPath := LocateNmapProbes()
	if probesPath == "" {
		t.Skip("nmap-service-probes not found on system")
	}

	db, err := ParseProbeFile(probesPath)
	if err != nil {
		t.Fatalf("failed to parse probes: %v", err)
	}

	engine := New(db, WithTimeout(10*time.Second), WithWorkers(len(comparisonServices)))

	type result struct {
		Name    string `json:"name"`
		Service string `json:"service"`
		Product string `json:"product"`
		Version string `json:"version"`
		Port    int    `json:"port"`
	}

	var allResults []result

	for _, svc := range comparisonServices {
		port, cleanup := startMockServer(t, svc)

		targets := []Target{{Host: "127.0.0.1", IP: "127.0.0.1", Port: port}}
		services := engine.Fingerprint(context.Background(), targets)

		key := fmt.Sprintf("127.0.0.1:%d", port)
		r := result{Name: svc.name, Port: port}
		if s, ok := services[key]; ok {
			r.Service = s.Name
			r.Product = s.Product
			r.Version = s.Version
		}
		allResults = append(allResults, r)
		cleanup()
	}

	jsonOut, _ := json.MarshalIndent(allResults, "", "  ")
	t.Logf("Detection results:\n%s", string(jsonOut))
}

// TestFallbackChain tests comma-separated fallback probes.
func TestFallbackChain(t *testing.T) {
	probes := `
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80
match http m|^HTTP/1\.[01] (\d+).*Server: ([\w/._-]+)|s p/$2/ v/$1/

Probe TCP HTTPOptions q|OPTIONS / HTTP/1.0\r\n\r\n|
rarity 4
ports 80
match options-only m|^OPTIONS| p/Options Only/
fallback GetRequest

Probe TCP SomeOther q|SOME\r\n|
rarity 5
ports 80
fallback GetRequest,HTTPOptions
`
	addr, cleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close() //nolint:errcheck
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		if n > 0 {
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\n"))
		}
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	db := buildTestDB(probes)
	engine := New(db, WithTimeout(3*time.Second), WithWorkers(1), WithIntensity(9))

	targets := []Target{{Host: host, IP: host, Port: port}}
	results := engine.Fingerprint(context.Background(), targets)

	key := fmt.Sprintf("%s:%d", host, port)
	svc, ok := results[key]
	if !ok {
		t.Fatal("expected service detection via fallback chain")
	}
	// Should match via GetRequest's match rules (first in fallback chain)
	if svc.Name != "http" {
		t.Errorf("expected 'http' via fallback chain, got %q", svc.Name)
	}
}

// TestTcpWrapped tests tcpwrapped detection.
func TestTcpWrapped(t *testing.T) {
	probes := `
Probe TCP NULL q||
totalwaitms 6000
tcpwrappedms 3000
match ssh m|^SSH-| p/SSH/
`
	// Server that accepts and immediately closes
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close() // close immediately = tcpwrapped //nolint:errcheck
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	db := buildTestDB(probes)
	engine := New(db, WithTimeout(5*time.Second), WithWorkers(1))

	targets := []Target{{Host: host, IP: host, Port: port}}
	results := engine.Fingerprint(context.Background(), targets)

	key := fmt.Sprintf("%s:%d", host, port)
	svc, ok := results[key]
	if !ok {
		t.Fatal("expected tcpwrapped detection")
	}
	if svc.Name != "tcpwrapped" {
		t.Errorf("expected 'tcpwrapped', got %q", svc.Name)
	}
}
