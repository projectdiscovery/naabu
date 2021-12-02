package result

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddPort(t *testing.T) {
	targetIP := "127.0.0.1"
	targetPort := 8080
	targetPorts := map[int]struct{}{targetPort: {}}

	res := NewResult()
	res.AddPort(targetIP, targetPort)

	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, res.IPS, expectedIPS)

	expectedIPSPorts := map[string]map[int]struct{}{targetIP: targetPorts}
	assert.Equal(t, res.IPPorts, expectedIPSPorts)
}

func TestSetPorts(t *testing.T) {
	targetIP := "127.0.0.1"
	targetPorts := map[int]struct{}{80: {}, 8080: {}}

	res := NewResult()
	res.SetPorts(targetIP, targetPorts)

	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, res.IPS, expectedIPS)

	expectedIPSPorts := map[string]map[int]struct{}{targetIP: targetPorts}
	assert.Equal(t, res.IPPorts, expectedIPSPorts)
}

func TestIPHasPort(t *testing.T) {
	targetIP := "127.0.0.1"
	targetPort := 8080

	res := NewResult()
	res.AddPort(targetIP, targetPort)
	assert.True(t, res.IPHasPort(targetIP, targetPort))
	assert.False(t, res.IPHasPort(targetIP, 1111))
}

func TestSetIP(t *testing.T) {
	targetIP := "127.0.0.1"

	res := NewResult()
	res.SetIP(targetIP)
	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, res.IPS, expectedIPS)
}

func TestHasIP(t *testing.T) {
	targetIP := "127.0.0.1"

	res := NewResult()
	res.SetIP(targetIP)
	assert.True(t, res.HasIP(targetIP))
	assert.False(t, res.HasIP("1.2.3.4"))
}
