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

// withProvider installs a provider for the duration of t and restores
// the previous one on cleanup. Tests that touch the global provider
// must use this helper so the state never leaks across tests.
func withProvider(t *testing.T, p UDPProbeProvider) {
	t.Helper()
	prev := GetUDPProbeProvider()
	SetUDPProbeProvider(p)
	t.Cleanup(func() { SetUDPProbeProvider(prev) })
}

// TestDefaultProviderIsNoop documents the at-rest behavior: with no
// SetUDPProbeProvider call the global accessor returns the no-op
// provider, which always yields nil.
func TestDefaultProviderIsNoop(t *testing.T) {
	if got := udpProbePayload(53); got != nil {
		t.Fatalf("expected nil payload from default provider, got %x", got)
	}
}

// TestSetUDPProbeProviderRoundTrips confirms a provider can be
// installed and retrieved across goroutines (atomic.Value semantics).
func TestSetUDPProbeProviderRoundTrips(t *testing.T) {
	withProvider(t, stubProvider{wantPort: 53, payload: []byte{0xAA, 0xBB}})

	var wg sync.WaitGroup
	results := make([][]byte, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = udpProbePayload(53)
		}(i)
	}
	wg.Wait()
	for _, r := range results {
		if !bytes.Equal(r, []byte{0xAA, 0xBB}) {
			t.Fatalf("goroutine got %x, want AABB", r)
		}
	}
}

// TestSetNilRestoresNoop guarantees that passing nil reverts to the
// no-op provider instead of panicking on a nil receiver later.
func TestSetNilRestoresNoop(t *testing.T) {
	withProvider(t, stubProvider{wantPort: 53, payload: []byte{0x01}})
	SetUDPProbeProvider(nil)
	if got := udpProbePayload(53); got != nil {
		t.Fatalf("expected nil after SetUDPProbeProvider(nil), got %x", got)
	}
}

// TestUDPLayersWithProbeAppendsPayload pins the wire format: when the
// provider returns bytes for the destination port, those bytes appear
// as the UDP payload in the serialized packet. This is the contract
// that the raw scan path relies on.
func TestUDPLayersWithProbeAppendsPayload(t *testing.T) {
	probe := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	withProvider(t, stubProvider{wantPort: 53, payload: probe})

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
	if err := gopacket.SerializeLayers(buf, opts, udpLayersWithProbe(udp, 53)...); err != nil {
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
	withProvider(t, stubProvider{wantPort: 999})

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
	if err := gopacket.SerializeLayers(buf, opts, udpLayersWithProbe(udp, 53)...); err != nil {
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

	withProvider(t, remapProvider{
		db:    db,
		remap: map[int]int{dnsPort: 53, ntpPort: 123},
	})

	scanner, err := NewScanner(&Options{})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

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
		SetUDPProbeProvider(nil)
		t.Cleanup(func() {
			SetUDPProbeProvider(remapProvider{db: db, remap: map[int]int{dnsPort: 53}})
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

	withProvider(t, stubProvider{wantPort: dnsPort, payload: []byte{0xDE, 0xAD}})

	scanner, err := NewScanner(&Options{})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	open, err := scanner.ConnectPort("127.0.0.1", string(dnsProbe),
		&port.Port{Port: dnsPort, Protocol: protocol.UDP}, 2*time.Second)
	if err != nil {
		t.Fatalf("ConnectPort: %v", err)
	}
	if !open {
		t.Fatal("expected open when caller supplied a real DNS probe (provider has bogus bytes)")
	}
}
