package runner

import (
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleServiceFingerprinting_Disabled(t *testing.T) {
	r := &Runner{
		options: &Options{},
	}

	require.NoError(t, r.handleServiceFingerprinting())
}

func TestIntegrateNervaResults_ServiceDiscoveryOnly(t *testing.T) {
	r := &Runner{
		options: &Options{ServiceDiscovery: true, ServiceVersion: false},
		scanner: &scan.Scanner{ScanResults: result.NewResult()},
	}

	r.scanner.ScanResults.AddPort("127.0.0.1", &port.Port{Port: 80, Protocol: protocol.TCP})

	r.integrateNervaResults([]plugins.Service{{
		IP:        "127.0.0.1",
		Port:      80,
		Protocol:  "http",
		Transport: "tcp",
		Version:   "1.1",
		Raw:       []byte(`{"server":"nginx"}`),
	}})

	var got *port.Port
	for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
		if hostResult.IP == "127.0.0.1" {
			for _, p := range hostResult.Ports {
				if p.Port == 80 && p.Protocol == protocol.TCP {
					got = p
				}
			}
		}
	}

	require.NotNil(t, got)
	require.NotNil(t, got.Service)
	assert.Equal(t, "http", got.Service.Name)
	assert.Empty(t, got.Service.Version)
	assert.Empty(t, got.Service.Product)
	assert.Empty(t, got.Service.ExtraInfo)
}

func TestIntegrateNervaResults_ServiceVersionEnabled(t *testing.T) {
	r := &Runner{
		options: &Options{ServiceVersion: true},
		scanner: &scan.Scanner{ScanResults: result.NewResult()},
	}

	r.scanner.ScanResults.AddPort("127.0.0.1", &port.Port{Port: 443, Protocol: protocol.TCP})

	r.integrateNervaResults([]plugins.Service{{
		IP:        "127.0.0.1",
		Port:      443,
		Protocol:  "https",
		Transport: "tcp",
		Version:   "2.0",
		Raw:       []byte(`{"alpn":["h2"]}`),
	}})

	var got *port.Port
	for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
		if hostResult.IP == "127.0.0.1" {
			for _, p := range hostResult.Ports {
				if p.Port == 443 && p.Protocol == protocol.TCP {
					got = p
				}
			}
		}
	}

	require.NotNil(t, got)
	require.NotNil(t, got.Service)
	assert.Equal(t, "https", got.Service.Name)
	assert.Equal(t, "2.0", got.Service.Version)
	assert.Equal(t, "https", got.Service.Product)
	assert.Equal(t, `{"alpn":["h2"]}`, got.Service.ExtraInfo)
}

func TestIntegrateNervaResults_AddsMissingPort(t *testing.T) {
	r := &Runner{
		options: &Options{ServiceVersion: true},
		scanner: &scan.Scanner{ScanResults: result.NewResult()},
	}

	r.integrateNervaResults([]plugins.Service{{
		IP:        "127.0.0.1",
		Port:      53,
		Protocol:  "dns",
		Transport: "udp",
	}})

	found := false
	for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
		if hostResult.IP == "127.0.0.1" {
			for _, p := range hostResult.Ports {
				if p.Port == 53 && p.Protocol == protocol.UDP {
					found = true
					require.NotNil(t, p.Service)
					assert.Equal(t, "dns", p.Service.Name)
				}
			}
		}
	}

	assert.True(t, found)
}

func TestJoinAddrPort(t *testing.T) {
	valid := joinAddrPort("127.0.0.1", 443)
	assert.True(t, valid.IsValid())
	assert.Equal(t, "127.0.0.1:443", valid.String())

	invalidIP := joinAddrPort("not-an-ip", 443)
	assert.False(t, invalidIP.IsValid())

	invalidPort := joinAddrPort("127.0.0.1", 70000)
	assert.False(t, invalidPort.IsValid())
}

func TestNormalizeServiceRawMetadata(t *testing.T) {
	assert.Equal(t, `{"k":1,"nested":{"v":2}}`, normalizeServiceRawMetadata([]byte("  {\n  \"k\": 1, \"nested\": { \"v\": 2 }\n}\n")))
	assert.Equal(t, `not-json-payload`, normalizeServiceRawMetadata([]byte("  not-json-payload  ")))
	assert.Equal(t, "", normalizeServiceRawMetadata(nil))
}
