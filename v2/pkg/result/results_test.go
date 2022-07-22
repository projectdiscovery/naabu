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
	assert.Equal(t, res.ips, expectedIPS)

	expectedIPSPorts := map[string]map[int]struct{}{targetIP: targetPorts}
	assert.Equal(t, res.ipPorts, expectedIPSPorts)
}

func TestSetPorts(t *testing.T) {
	targetIP := "127.0.0.1"
	targetPorts := map[int]struct{}{80: {}, 8080: {}}

	res := NewResult()
	res.SetPorts(targetIP, []int{80, 8080})

	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, res.ips, expectedIPS)

	expectedIPSPorts := map[string]map[int]struct{}{targetIP: targetPorts}
	assert.Equal(t, res.ipPorts, expectedIPSPorts)
}

func TestIPHasPort(t *testing.T) {
	targetIP := "127.0.0.1"
	targetPort := 8080

	res := NewResult()
	res.AddPort(targetIP, targetPort)
	assert.True(t, res.IPHasPort(targetIP, targetPort))
	assert.False(t, res.IPHasPort(targetIP, 1111))
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
