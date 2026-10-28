package routing

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseARPHardwareAddrLinux(t *testing.T) {
	out := `Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.1              ether   aa:bb:cc:dd:ee:ff   C                     eth0
`
	mac, err := parseARPHardwareAddr("192.168.1.1", out)
	require.NoError(t, err)
	require.Equal(t, "aa:bb:cc:dd:ee:ff", mac.String())
}

func TestParseARPHardwareAddrWindows(t *testing.T) {
	out := `Interface: 192.168.1.10 --- 0xa
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.20          11-22-33-44-55-66     dynamic
`
	mac, err := parseARPHardwareAddr("192.168.1.1", out)
	require.NoError(t, err)
	require.Equal(t, net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, mac)

	mac, err = parseARPHardwareAddr("192.168.1.20", out)
	require.NoError(t, err)
	require.Equal(t, "11:22:33:44:55:66", mac.String())
}

func TestParseARPHardwareAddrIPPrefixCollision(t *testing.T) {
	// Full-table Windows arp output can list longer addresses first; substring
	// matching would return the wrong MAC for 192.168.1.1.
	out := `Interface: 192.168.1.50 --- 0xa
  Internet Address      Physical Address      Type
  192.168.1.10          aa-aa-aa-aa-aa-aa     dynamic
  192.168.1.100         bb-bb-bb-bb-bb-bb     dynamic
  192.168.1.1           cc-cc-cc-cc-cc-cc     dynamic
`
	mac, err := parseARPHardwareAddr("192.168.1.1", out)
	require.NoError(t, err)
	require.Equal(t, "cc:cc:cc:cc:cc:cc", mac.String())
}

func TestParseARPHardwareAddrMissing(t *testing.T) {
	_, err := parseARPHardwareAddr("10.0.0.1", "Interface: 192.168.1.10 --- 0xa\n")
	require.Error(t, err)
}
