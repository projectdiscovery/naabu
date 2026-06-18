package fingerprint

import (
	"strings"
	"testing"
)

func TestParseProbeBasic(t *testing.T) {
	input := `
Probe TCP NULL q||
totalwaitms 6000
tcpwrappedms 3000
match ssh m|^SSH-([\d.]+)-OpenSSH[_-]([\w._-]+)| p/OpenSSH/ v/$2/ i/protocol $1/
softmatch ssh m|^SSH-| p/SSH/

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80,443,8080
sslports 443
match http m|^HTTP/1\.[01] (\d\d\d)| p/Apache httpd/ v/$1/
`
	db, err := ParseProbes(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(db.Probes) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(db.Probes))
	}

	// NULL probe
	null := db.Probes[0]
	if null.Name != "NULL" {
		t.Errorf("expected probe name 'NULL', got %q", null.Name)
	}
	if null.Protocol != "TCP" {
		t.Errorf("expected TCP protocol, got %q", null.Protocol)
	}
	if len(null.Data) != 0 {
		t.Errorf("expected empty data for NULL probe, got %d bytes", len(null.Data))
	}
	if null.TotalWaitMS != 6000 {
		t.Errorf("expected totalwaitms 6000, got %d", null.TotalWaitMS)
	}
	if null.TCPWrappedMS != 3000 {
		t.Errorf("expected tcpwrappedms 3000, got %d", null.TCPWrappedMS)
	}
	if len(null.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(null.Matches))
	}
	if len(null.SoftMatches) != 1 {
		t.Fatalf("expected 1 softmatch, got %d", len(null.SoftMatches))
	}
	if null.Matches[0].Service != "ssh" {
		t.Errorf("expected service 'ssh', got %q", null.Matches[0].Service)
	}
	if null.Matches[0].Product != "OpenSSH" {
		t.Errorf("expected product 'OpenSSH', got %q", null.Matches[0].Product)
	}

	// GetRequest probe
	get := db.Probes[1]
	if get.Name != "GetRequest" {
		t.Errorf("expected probe name 'GetRequest', got %q", get.Name)
	}
	if get.Rarity != 1 {
		t.Errorf("expected rarity 1, got %d", get.Rarity)
	}
	if !get.Ports.Contains(80) || !get.Ports.Contains(443) || !get.Ports.Contains(8080) {
		t.Errorf("expected ports 80,443,8080 to be in ports set")
	}
	if !get.SSLPorts.Contains(443) {
		t.Errorf("expected port 443 in sslports")
	}
	expectedData := "GET / HTTP/1.0\r\n\r\n"
	if string(get.Data) != expectedData {
		t.Errorf("expected data %q, got %q", expectedData, string(get.Data))
	}
}

func TestParseExclude(t *testing.T) {
	input := `Exclude T:9100-9107
Probe TCP NULL q||
`
	db, err := ParseProbes(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for p := 9100; p <= 9107; p++ {
		if !db.ExcludeTCP.Contains(p) {
			t.Errorf("expected port %d in TCP exclude set", p)
		}
	}
	if db.ExcludeTCP.Contains(9108) {
		t.Error("port 9108 should not be excluded")
	}
}

func TestParseFallback(t *testing.T) {
	input := `
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80
match http m|^HTTP/1\.[01]| p/HTTP/

Probe TCP HTTPOptions q|OPTIONS / HTTP/1.0\r\n\r\n|
rarity 4
ports 80
fallback GetRequest
`
	db, err := ParseProbes(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(db.Probes) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(db.Probes))
	}

	opts := db.Probes[1]
	if opts.Fallback != "GetRequest" {
		t.Errorf("expected fallback 'GetRequest', got %q", opts.Fallback)
	}
}

func TestParseUDPProbe(t *testing.T) {
	input := `
Probe UDP DNSVersionBindReq q|\0\x06\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03|
rarity 1
ports 53,1967,2967,26198
match dns m|^\0.\0.\x85\0\0\x01\0\x01.*\x07version\x04bind|s p/ISC BIND/
`
	db, err := ParseProbes(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(db.Probes) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(db.Probes))
	}

	probe := db.Probes[0]
	if probe.Protocol != "UDP" {
		t.Errorf("expected UDP protocol, got %q", probe.Protocol)
	}
	if !probe.Ports.Contains(53) {
		t.Error("expected port 53 in ports set")
	}
}

func TestMatchApply(t *testing.T) {
	input := `
Probe TCP NULL q||
match ssh m|^SSH-([\d.]+)-OpenSSH[_-]([\w._-]+)| p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
`
	db, err := ParseProbes(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := db.Probes[0].Matches[0]
	banner := []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4")

	strs := FindSubmatch(m.Pattern, banner)
	if strs == nil {
		t.Fatal("expected match on SSH banner")
	}

	result := m.Apply(strs)

	if result.Service != "ssh" {
		t.Errorf("expected service 'ssh', got %q", result.Service)
	}
	if result.Product != "OpenSSH" {
		t.Errorf("expected product 'OpenSSH', got %q", result.Product)
	}
	if result.Version != "8.9p1" {
		t.Errorf("expected version '8.9p1', got %q", result.Version)
	}
	if result.Info != "protocol 2.0" {
		t.Errorf("expected info 'protocol 2.0', got %q", result.Info)
	}
	if len(result.CPEs) != 1 || result.CPEs[0] != "cpe:/a:openbsd:openssh:8.9p1/" {
		t.Errorf("unexpected CPEs: %v", result.CPEs)
	}
}

func TestDecodeNmapEscapes(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"\\r\\n", []byte{'\r', '\n'}},
		{"\\x00\\xff", []byte{0x00, 0xff}},
		{"\\t\\a", []byte{'\t', '\a'}},
		{"\\0", []byte{0}},
		{"\\\\", []byte{'\\'}},
		{"hello", []byte("hello")},
		{"GET / HTTP/1.0\\r\\n\\r\\n", []byte("GET / HTTP/1.0\r\n\r\n")},
	}

	for _, tt := range tests {
		got := decodeNmapEscapes(tt.input)
		if string(got) != string(tt.expected) {
			t.Errorf("decodeNmapEscapes(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		input    string
		contains []int
		absent   []int
	}{
		{"80,443,8080", []int{80, 443, 8080}, []int{81, 8081}},
		{"100-105", []int{100, 101, 102, 103, 104, 105}, []int{99, 106}},
		{"22,80,8000-8010", []int{22, 80, 8000, 8005, 8010}, []int{21, 7999, 8011}},
	}

	for _, tt := range tests {
		ps := parsePorts(tt.input)
		for _, p := range tt.contains {
			if !ps.Contains(p) {
				t.Errorf("parsePorts(%q): expected port %d to be present", tt.input, p)
			}
		}
		for _, p := range tt.absent {
			if ps.Contains(p) {
				t.Errorf("parsePorts(%q): expected port %d to be absent", tt.input, p)
			}
		}
	}
}

func TestParseMatchFlags(t *testing.T) {
	input := `
Probe TCP NULL q||
match test m|^hello.*world$|si p/Test Service/
`
	db, err := ParseProbes(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := db.Probes[0].Matches[0]

	result := FindSubmatch(m.Pattern, []byte("HELLO\nWORLD"))
	if result == nil {
		t.Error("expected pattern to match with dotall + case-insensitive")
	}
}

func TestParseRealProbeFile(t *testing.T) {
	path := LocateNmapProbes()
	if path == "" {
		t.Skip("nmap-service-probes not found on system")
	}

	db, err := ParseProbeFile(path)
	if err != nil {
		t.Fatalf("failed to parse real probe file: %v", err)
	}

	if len(db.Probes) < 50 {
		t.Errorf("expected at least 50 probes, got %d", len(db.Probes))
	}

	// The NULL probe should exist and be the first one
	if db.Probes[0].Name != "NULL" {
		t.Errorf("expected first probe to be NULL, got %q", db.Probes[0].Name)
	}

	totalMatches := 0
	for _, p := range db.Probes {
		totalMatches += len(p.Matches) + len(p.SoftMatches)
	}
	if totalMatches < 1000 {
		t.Errorf("expected at least 1000 total matches, got %d", totalMatches)
	}

	t.Logf("Parsed %d probes with %d total match rules", len(db.Probes), totalMatches)
}

func TestMatchAlternateDelimiter(t *testing.T) {
	// Nmap uses | as delimiter but the first char after 'm' is the delimiter
	// Some entries use different delimiters
	input := `
Probe TCP NULL q||
match test m=^hello= p/Test/
`
	db, err := ParseProbes(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(db.Probes[0].Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(db.Probes[0].Matches))
	}

	m := db.Probes[0].Matches[0]
	result := FindSubmatch(m.Pattern, []byte("hello"))
	if result == nil {
		t.Error("expected pattern to match 'hello'")
	}
}

func TestParseMatchCPEs(t *testing.T) {
	input := `
Probe TCP NULL q||
match http m|^HTTP| p/Apache/ v/$1/ cpe:/a:apache:httpd:$1/ cpe:/o:linux:linux_kernel/
`
	db, err := ParseProbes(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := db.Probes[0].Matches[0]
	if len(m.CPEs) != 2 {
		t.Fatalf("expected 2 CPEs, got %d: %v", len(m.CPEs), m.CPEs)
	}
	if m.CPEs[0] != "cpe:/a:apache:httpd:$1/" {
		t.Errorf("unexpected CPE[0]: %q", m.CPEs[0])
	}
	if m.CPEs[1] != "cpe:/o:linux:linux_kernel/" {
		t.Errorf("unexpected CPE[1]: %q", m.CPEs[1])
	}
}

func TestParseExcludeProtocol(t *testing.T) {
	input := `Exclude T:9100-9107,U:5353
Probe TCP NULL q||
`
	db, err := ParseProbes(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !db.ExcludeTCP.Contains(9100) {
		t.Error("expected TCP:9100 in exclude")
	}
	if !db.ExcludeUDP.Contains(5353) {
		t.Error("expected UDP:5353 in exclude")
	}
	if db.ExcludeTCP.Contains(5353) {
		t.Error("TCP:5353 should not be excluded")
	}
}

func TestProbeWaitDuration(t *testing.T) {
	probe := &ServiceProbe{TotalWaitMS: 3000}
	if d := probe.WaitDuration(); d.Milliseconds() != 3000 {
		t.Errorf("expected 3000ms, got %v", d)
	}

	probe2 := &ServiceProbe{}
	if d := probe2.WaitDuration(); d.Seconds() != 5 {
		t.Errorf("expected default 5s, got %v", d)
	}
}
