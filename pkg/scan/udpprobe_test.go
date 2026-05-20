package scan

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Mzack9999/gopacket"
	"github.com/Mzack9999/gopacket/layers"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

// stubProvider is a test provider that returns a fixed payload for a
// configured port and nil for every other port.
type stubProvider struct {
	wantPort int
	payload  []byte
}

func (s stubProvider) UDPProbe(p int) []byte {
	if p == s.wantPort {
		return s.payload
	}
	return nil
}

// newScannerWithProvider builds a Scanner backed by a synthetic
// ListenHandler (no raw sockets) and installs the given provider on
// both. Using a synthetic handler keeps the unit tests deterministic
// on hosts where Acquire would otherwise need privileges, and the
// integration tests below upgrade to NewScanner where they need the
// full stack.
func newScannerWithProvider(p UDPProbeProvider) *Scanner {
	s := &Scanner{ListenHandler: NewListenHandler()}
	s.SetUDPProbeProvider(p)
	return s
}

// TestNilProviderIsNoop documents the at-rest behavior: a Scanner
// with no provider installed reports nil for any port, which keeps
// the legacy zero-length-datagram path active.
func TestNilProviderIsNoop(t *testing.T) {
	s := &Scanner{ListenHandler: NewListenHandler()}
	if got := s.udpProbePayload(53); got != nil {
		t.Fatalf("expected nil payload from default provider, got %x", got)
	}
	if got := s.ListenHandler.udpProbePayload(53); got != nil {
		t.Fatalf("expected nil payload from default handler, got %x", got)
	}
}

// TestSetUDPProbeProviderPropagates confirms the provider set on the
// Scanner is also visible on its ListenHandler, which is the surface
// the raw send path consults.
func TestSetUDPProbeProviderPropagates(t *testing.T) {
	s := newScannerWithProvider(stubProvider{wantPort: 53, payload: []byte{0xAA, 0xBB}})

	if got := s.udpProbePayload(53); !bytes.Equal(got, []byte{0xAA, 0xBB}) {
		t.Fatalf("scanner got %x, want AABB", got)
	}
	if got := s.ListenHandler.udpProbePayload(53); !bytes.Equal(got, []byte{0xAA, 0xBB}) {
		t.Fatalf("handler got %x, want AABB", got)
	}
}

// TestSetUDPProbeProviderConcurrentReads confirms repeated reads from
// many goroutines see a consistent provider. The atomic story is gone
// (the provider lives in plain struct fields), so this guards the
// invariant that we install the provider once before the scan starts
// rather than mutating it mid-flight.
func TestSetUDPProbeProviderConcurrentReads(t *testing.T) {
	s := newScannerWithProvider(stubProvider{wantPort: 53, payload: []byte{0xAA, 0xBB}})

	var wg sync.WaitGroup
	results := make([][]byte, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = s.udpProbePayload(53)
		}(i)
	}
	wg.Wait()
	for _, r := range results {
		if !bytes.Equal(r, []byte{0xAA, 0xBB}) {
			t.Fatalf("goroutine got %x, want AABB", r)
		}
	}
}

// TestSetUDPProbeProviderNilDisables guarantees that passing nil
// clears the provider on both the scanner and its handler, returning
// to the legacy zero-length-datagram behavior.
func TestSetUDPProbeProviderNilDisables(t *testing.T) {
	s := newScannerWithProvider(stubProvider{wantPort: 53, payload: []byte{0x01}})
	s.SetUDPProbeProvider(nil)
	if got := s.udpProbePayload(53); got != nil {
		t.Fatalf("scanner expected nil after SetUDPProbeProvider(nil), got %x", got)
	}
	if got := s.ListenHandler.udpProbePayload(53); got != nil {
		t.Fatalf("handler expected nil after SetUDPProbeProvider(nil), got %x", got)
	}
}

// TestUDPLayersWithProbeAppendsPayload pins the wire format: when the
// handler's provider returns bytes for the destination port, those
// bytes appear as the UDP payload in the serialized packet. This is
// the contract that the raw scan path relies on.
func TestUDPLayersWithProbeAppendsPayload(t *testing.T) {
	probe := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	s := newScannerWithProvider(stubProvider{wantPort: 53, payload: probe})

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(12345),
		DstPort: layers.UDPPort(53),
	}
	ip4 := &layers.IPv4{
		Version:  4,
		SrcIP:    net.IPv4(127, 0, 0, 1),
		DstIP:    net.IPv4(127, 0, 0, 2),
		TTL:      255,
		Protocol: layers.IPProtocolUDP,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, s.ListenHandler.udpLayersWithProbe(udp, 53)...); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	if !bytes.HasSuffix(buf.Bytes(), probe) {
		t.Fatalf("serialized packet does not end with probe payload: % x", buf.Bytes())
	}
}

// TestUDPLayersWithProbeEmptyKeepsLegacyShape documents that when the
// provider has nothing to say for a port, the serialized packet
// matches the pre-feature shape (just the UDP header), preserving the
// historical wire behavior for callers who don't opt in.
func TestUDPLayersWithProbeEmptyKeepsLegacyShape(t *testing.T) {
	s := newScannerWithProvider(stubProvider{wantPort: 999})

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(12345),
		DstPort: layers.UDPPort(53),
	}
	ip4 := &layers.IPv4{
		Version:  4,
		SrcIP:    net.IPv4(127, 0, 0, 1),
		DstIP:    net.IPv4(127, 0, 0, 2),
		TTL:      255,
		Protocol: layers.IPProtocolUDP,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, s.ListenHandler.udpLayersWithProbe(udp, 53)...); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	if got := len(buf.Bytes()); got != 8 {
		t.Fatalf("expected 8-byte UDP header only, got %d bytes: % x", got, buf.Bytes())
	}
}

// startDNSServer spins up an in-process DNS server on an ephemeral
// UDP port backed by miekg/dns. The server understands real DNS
// queries (including the CHAOS TXT version.bind query that nmap's
// DNSVersionBindReq sends) and answers them with a synthetic record.
// This lets the test drive ConnectPort with the exact bytes nmap
// would put on the wire, then observe a real protocol-conformant
// response coming back.
func startDNSServer(t *testing.T) (int, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("DNS listen: %v", err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			for _, q := range r.Question {
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: q.Qclass, Ttl: 0},
					Txt: []string{"naabu-test"},
				})
			}
			_ = w.WriteMsg(m)
		}),
	}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	port := pc.LocalAddr().(*net.UDPAddr).Port
	return port, func() { _ = srv.Shutdown() }
}

// startNTPServer spins up a minimal NTPv4 server: any 48-byte client
// datagram is answered with a server-mode response so the scanner
// sees a real reply. This is enough to validate that the
// NTPRequest probe (a 48-byte mode-3 client packet) reaches the wire
// and produces a response.
func startNTPServer(t *testing.T) (int, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("NTP listen: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = pc.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, src, err := pc.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			if n < 1 {
				continue
			}
			// Server-mode NTPv4 response: LI=0, VN=4, Mode=4
			// (server), stratum 1, poll 6, precision -20.
			resp := make([]byte, 48)
			resp[0] = (0 << 6) | (4 << 3) | 4
			resp[1] = 1
			resp[2] = 6
			resp[3] = 0xEC
			_, _ = pc.WriteToUDP(resp, src)
		}
	}()
	return port, func() {
		close(stop)
		_ = pc.Close()
		<-done
	}
}

// remapProvider wraps a fingerprint.ProbeDB and serves probes for an
// ephemeral test port using the well-known port the probe was
// authored for. This is how we exercise the full provider path
// (scan -> provider -> fingerprint -> nmap-service-probes) without
// having to ask the kernel for privileged ports 53/123.
type remapProvider struct {
	db    *fingerprint.ProbeDB
	remap map[int]int
}

func (r remapProvider) UDPProbe(p int) []byte {
	if wk, ok := r.remap[p]; ok {
		return r.db.UDPProbeForPort(wk)
	}
	return r.db.UDPProbeForPort(p)
}

// TestUDPProbesAgainstRealServers is the headline end-to-end test:
// it loads the real nmap-service-probes file installed on the host,
// stands up real DNS and NTP responders in-process, and drives
// ConnectPort. A port is reported as open only when the actual probe
// bytes nmap ships for that service elicit a real protocol response,
// which is the user-visible behavior naabu#1633 is asking for. The
// test skips cleanly on hosts without nmap installed.
func TestUDPProbesAgainstRealServers(t *testing.T) {
	probesPath := fingerprint.LocateNmapProbes()
	if probesPath == "" {
		t.Skip("nmap-service-probes not found on system")
	}
	db, err := fingerprint.ParseProbeFile(probesPath)
	if err != nil {
		t.Fatalf("parse nmap-service-probes: %v", err)
	}

	dnsPort, dnsCleanup := startDNSServer(t)
	defer dnsCleanup()
	ntpPort, ntpCleanup := startNTPServer(t)
	defer ntpCleanup()

	scanner, err := NewScanner(&Options{})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	t.Cleanup(func() { _ = scanner.Close() })
	scanner.SetUDPProbeProvider(remapProvider{
		db:    db,
		remap: map[int]int{dnsPort: 53, ntpPort: 123},
	})

	cases := []struct {
		name   string
		port   int
		probed bool // do we expect db to have a probe for the well-known port?
		wkPort int
	}{
		{"DNS", dnsPort, true, 53},
		{"NTP", ntpPort, true, 123},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if probe := db.UDPProbeForPort(tc.wkPort); len(probe) == 0 {
				t.Skipf("host's nmap-service-probes has no UDP probe for port %d", tc.wkPort)
			}
			p := &port.Port{Port: tc.port, Protocol: protocol.UDP}
			open, err := scanner.ConnectPort("127.0.0.1", "", p, 2*time.Second)
			if err != nil {
				t.Fatalf("ConnectPort: %v", err)
			}
			if !open {
				t.Fatal("expected port reported as open after probing real server")
			}
		})
	}

	// Sanity: with the no-op provider an empty UDP datagram does not
	// elicit a DNS reply (the server can't decode it), so the same
	// port comes back as not-open. This locks in the legacy behavior
	// users get without -uP.
	t.Run("NoProviderNoOpen", func(t *testing.T) {
		scanner.SetUDPProbeProvider(nil)
		t.Cleanup(func() {
			scanner.SetUDPProbeProvider(remapProvider{db: db, remap: map[int]int{dnsPort: 53}})
		})
		open, err := scanner.ConnectPort("127.0.0.1", "",
			&port.Port{Port: dnsPort, Protocol: protocol.UDP}, 500*time.Millisecond)
		if err != nil {
			t.Fatalf("ConnectPort: %v", err)
		}
		if open {
			t.Fatal("expected not-open with no probe payload, the DNS server should drop the malformed datagram")
		}
	})
}

// TestUDPProbesCallerPayloadWinsAgainstRealServer documents the
// priority rule using a real DNS server: a non-empty caller payload
// (i.e. -cp) takes precedence over the provider. We pass the real
// nmap DNS probe as the caller payload while installing a broken
// provider that would otherwise produce garbage. The server replies,
// proving the bytes actually came from the caller and not from the
// provider.
func TestUDPProbesCallerPayloadWinsAgainstRealServer(t *testing.T) {
	probesPath := fingerprint.LocateNmapProbes()
	if probesPath == "" {
		t.Skip("nmap-service-probes not found on system")
	}
	db, err := fingerprint.ParseProbeFile(probesPath)
	if err != nil {
		t.Fatalf("parse nmap-service-probes: %v", err)
	}
	dnsProbe := db.UDPProbeForPort(53)
	if len(dnsProbe) == 0 {
		t.Skip("host's nmap-service-probes has no UDP probe for :53")
	}

	dnsPort, cleanup := startDNSServer(t)
	defer cleanup()

	scanner, err := NewScanner(&Options{})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	t.Cleanup(func() { _ = scanner.Close() })
	scanner.SetUDPProbeProvider(stubProvider{wantPort: dnsPort, payload: []byte{0xDE, 0xAD}})
	open, err := scanner.ConnectPort("127.0.0.1", string(dnsProbe),
		&port.Port{Port: dnsPort, Protocol: protocol.UDP}, 2*time.Second)
	if err != nil {
		t.Fatalf("ConnectPort: %v", err)
	}
	if !open {
		t.Fatal("expected open when caller supplied a real DNS probe (provider has bogus bytes)")
	}
}
