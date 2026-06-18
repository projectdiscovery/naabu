package macvendor

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookup(t *testing.T) {
	// 00:00:0C is a well-known IEEE OUI assigned to Cisco.
	assert.Contains(t, Lookup("00:00:0c:aa:bb:cc"), "Cisco")

	// separators and case must not matter
	assert.Equal(t, Lookup("00:00:0C:11:22:33"), Lookup("00-00-0c-11-22-33"))
	assert.Equal(t, Lookup("00000c112233"), Lookup("00:00:0c:11:22:33"))

	// bare OUI is accepted
	assert.NotEmpty(t, Lookup("0000.0c"))
}

func TestLookupUnknownAndInvalid(t *testing.T) {
	assert.Empty(t, Lookup(""))
	assert.Empty(t, Lookup("zz:zz"))
	// locally administered / unassigned prefix
	assert.Empty(t, Lookup("02:00:00:00:00:00"))
}

func TestVendorFromMAC(t *testing.T) {
	mac, err := net.ParseMAC("00:00:0c:de:ad:be")
	assert.NoError(t, err)
	assert.Contains(t, VendorFromMAC(mac), "Cisco")
}

func TestDatasetLoaded(t *testing.T) {
	// sanity check that the embedded dataset decompresses and is populated
	once.Do(load)
	assert.Greater(t, len(db), 10000)
}
