package runner

import (
	"bytes"
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
)

type stubProvider struct{ payload []byte }

func (s stubProvider) UDPProbe(int) []byte { return s.payload }

func makeUDPProbe(name string, rarity int, payload []byte, ports ...int) *fingerprint.ServiceProbe {
	ps := fingerprint.NewPortSet()
	for _, p := range ports {
		ps.Add(p)
	}
	return &fingerprint.ServiceProbe{
		Protocol: "UDP",
		Name:     name,
		Data:     payload,
		Ports:    ps,
		Rarity:   rarity,
	}
}

// TestUDPProbeAdapterReturnsBytes is the happy-path contract: a probe
// DB containing a UDP probe for a port produces that probe's payload
// when the scan package asks for it.
func TestUDPProbeAdapterReturnsBytes(t *testing.T) {
	db := &fingerprint.ProbeDB{
		Probes: []*fingerprint.ServiceProbe{
			makeUDPProbe("DNS", 1, []byte{0x00, 0x06, 0x01}, 53),
		},
	}
	a := udpProbeAdapter{db: db}
	got := a.UDPProbe(53)
	if !bytes.Equal(got, []byte{0x00, 0x06, 0x01}) {
		t.Fatalf("UDPProbe(53) = %x, want 000601", got)
	}
}

// TestUDPProbeAdapterUnknownPort documents that ports without a probe
// produce nil, which is the signal the scan layer uses to keep its
// empty-payload behavior.
func TestUDPProbeAdapterUnknownPort(t *testing.T) {
	db := &fingerprint.ProbeDB{
		Probes: []*fingerprint.ServiceProbe{
			makeUDPProbe("DNS", 1, []byte{0xAA}, 53),
		},
	}
	a := udpProbeAdapter{db: db}
	if got := a.UDPProbe(8080); got != nil {
		t.Fatalf("UDPProbe(8080) = %x, want nil", got)
	}
}

// TestUDPProbeAdapterNilDB confirms the nil-receiver contract: the
// adapter must work even when the probe file could not be loaded, so
// the scan path never panics on a misconfigured runner.
func TestUDPProbeAdapterNilDB(t *testing.T) {
	a := udpProbeAdapter{db: nil}
	if got := a.UDPProbe(53); got != nil {
		t.Fatalf("UDPProbe(53) with nil DB = %x, want nil", got)
	}
}

// TestInitUDPProbesDisabledClearsStaleProvider guards the library use
// case where two runners share a process: a previous run that turned
// -uP on must not leak its provider into a follow-up run that has
// -uP off. initUDPProbes restores the no-op provider before doing
// anything else, so the global is clean regardless of which path is
// taken.
func TestInitUDPProbesDisabledClearsStaleProvider(t *testing.T) {
	scan.SetUDPProbeProvider(stubProvider{payload: []byte{0xDE, 0xAD}})
	t.Cleanup(func() { scan.SetUDPProbeProvider(nil) })

	r := &Runner{options: &Options{UDPProbes: false}}
	r.initUDPProbes()

	if got := scan.GetUDPProbeProvider().UDPProbe(53); got != nil {
		t.Fatalf("stale provider leaked: UDPProbe(53) = %x, want nil", got)
	}
}

// TestInitUDPProbesMissingFileClearsStaleProvider documents the same
// invariant for the failure path: enabling -uP without a discoverable
// nmap-service-probes file must not silently keep a previous run's
// adapter active.
func TestInitUDPProbesMissingFileClearsStaleProvider(t *testing.T) {
	scan.SetUDPProbeProvider(stubProvider{payload: []byte{0xBE, 0xEF}})
	t.Cleanup(func() { scan.SetUDPProbeProvider(nil) })

	r := &Runner{options: &Options{UDPProbes: true, ServiceProbesFile: "/does/not/exist/nmap-service-probes"}}
	r.initUDPProbes()

	if got := scan.GetUDPProbeProvider().UDPProbe(53); got != nil {
		t.Fatalf("stale provider leaked on load failure: UDPProbe(53) = %x, want nil", got)
	}
}
