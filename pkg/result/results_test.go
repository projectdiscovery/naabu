package result

import (
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/stretchr/testify/assert"
)

func TestAddPort(t *testing.T) {
	targetIP := "127.0.0.1"
	targetPort := &port.Port{Port: 8080, Protocol: protocol.TCP}
	targetPorts := map[string]*port.Port{targetPort.String(): targetPort}

	res := NewResult()
	res.AddPort(targetIP, targetPort)

	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, expectedIPS, res.ips)

	expectedIPSPorts := map[string]map[string]*port.Port{targetIP: targetPorts}
	assert.Equal(t, res.ipPorts, expectedIPSPorts)
}

func TestSetPorts(t *testing.T) {
	targetIP := "127.0.0.1"
	port80 := &port.Port{Port: 80, Protocol: protocol.TCP}
	port443 := &port.Port{Port: 443, Protocol: protocol.TCP}
	targetPorts := map[string]*port.Port{
		port80.String():  port80,
		port443.String(): port443,
	}

	res := NewResult()
	res.SetPorts(targetIP, []*port.Port{port80, port443})

	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, res.ips, expectedIPS)

	expectedIPSPorts := map[string]map[string]*port.Port{targetIP: targetPorts}
	assert.Equal(t, res.ipPorts, expectedIPSPorts)
}

func TestIPHasPort(t *testing.T) {
	targetIP := "127.0.0.1"
	expectedPort := &port.Port{Port: 8080, Protocol: protocol.TCP}
	unexpectedPort := &port.Port{Port: 8081, Protocol: protocol.TCP}

	res := NewResult()
	res.AddPort(targetIP, expectedPort)
	assert.True(t, res.IPHasPort(targetIP, expectedPort))
	assert.False(t, res.IPHasPort(targetIP, unexpectedPort))
}

func TestAddIP(t *testing.T) {
	targetIP := "127.0.0.1"

	res := NewResult()
	res.AddIp(targetIP)
	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, res.ips, expectedIPS)
}

func TestHasIP(t *testing.T) {
	targetIP := "127.0.0.1"

	res := NewResult()
	res.AddIp(targetIP)
	assert.True(t, res.HasIP(targetIP))
	assert.False(t, res.HasIP("1.2.3.4"))
}

func TestDeadHosts(t *testing.T) {
	res := NewResult()
	assert.False(t, res.HasDeadHosts())

	res.AddDeadHost("10.0.0.1")
	res.AddDeadHost("10.0.0.2")
	// adding the same host again must not duplicate it
	res.AddDeadHost("10.0.0.1")

	assert.True(t, res.HasDeadHosts())
	assert.ElementsMatch(t, []string{"10.0.0.1", "10.0.0.2"}, res.GetDeadHosts())
}

func TestMACAddress(t *testing.T) {
	res := NewResult()
	assert.Empty(t, res.GetMACAddress("10.0.0.1"))

	res.SetMACAddress("10.0.0.1", "aa:bb:cc:dd:ee:ff")
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", res.GetMACAddress("10.0.0.1"))

	// empty MAC values are ignored and never overwrite an existing entry
	res.SetMACAddress("10.0.0.1", "")
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", res.GetMACAddress("10.0.0.1"))
}
