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

func TestParseARPHardwareAddrMissing(t *testing.T) {
	_, err := parseARPHardwareAddr("10.0.0.1", "Interface: 192.168.1.10 --- 0xa\n")
	require.Error(t, err)
}
