package runner

import (
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/stretchr/testify/assert"
)

func TestHandleNmap(t *testing.T) {
	var r Runner
	r.options = &Options{}

	res := result.NewResult()
	r.scanner = &scan.Scanner{}
	r.scanner.ScanResults = res

	// Test with no results and no nmap CLI - should skip
	assert.Nil(t, r.handleNmap())

	// Test with some scan results but no nmap CLI - should skip
	r.scanner.ScanResults.SetPorts("127.0.0.1", []*port.Port{
		{Port: 80, Protocol: protocol.TCP},
		{Port: 443, Protocol: protocol.TCP},
	})

	// This should skip nmap since no NmapCLI is provided
	assert.Nil(t, r.handleNmap())
}

func TestHandleNmapWithCustomCLI(t *testing.T) {
	var r Runner
	r.options = &Options{
		NmapCLI: "-sV -O", // Custom nmap arguments
	}

	res := result.NewResult()
	r.scanner = &scan.Scanner{}
	r.scanner.ScanResults = res

	// Test with some scan results
	r.scanner.ScanResults.SetPorts("127.0.0.1", []*port.Port{
		{Port: 80, Protocol: protocol.TCP},
	})

	// This should use the custom CLI arguments
	assert.Nil(t, r.handleNmap())
}

func TestUpdatePortWithServiceInfo(t *testing.T) {
	var r Runner
	r.options = &Options{}

	res := result.NewResult()
	r.scanner = &scan.Scanner{}
	r.scanner.ScanResults = res

	// Add initial port without service info
	initialPort := &port.Port{Port: 80, Protocol: protocol.TCP}
	r.scanner.ScanResults.AddPort("127.0.0.1", initialPort)

	// Create enhanced port with service info
	enhancedPort := &port.Port{
		Port:     80,
		Protocol: protocol.TCP,
		Service: &port.Service{
			Name:    "http",
			Product: "nginx",
			Version: "1.18.0",
		},
	}

	// Update the port with service info
	r.updatePortWithServiceInfo("127.0.0.1", enhancedPort)

	// Verify the port was updated with service info
	for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
		if hostResult.IP == "127.0.0.1" {
			for _, p := range hostResult.Ports {
				if p.Port == 80 {
					assert.NotNil(t, p.Service)
					assert.Equal(t, "http", p.Service.Name)
					assert.Equal(t, "nginx", p.Service.Product)
					assert.Equal(t, "1.18.0", p.Service.Version)
					return
				}
			}
		}
	}

	t.Fatal("Port not found or not updated correctly")
}
