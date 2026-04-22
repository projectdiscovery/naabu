package routing

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---

func iface(name string, mac string) *net.Interface {
	hw, _ := net.ParseMAC(mac)
	return &net.Interface{
		Index:        1,
		MTU:          1500,
		Name:         name,
		HardwareAddr: hw,
		Flags:        net.FlagUp | net.FlagBroadcast,
	}
}

var (
	eth0 = iface("eth0", "00:11:22:33:44:55")
	eth1 = iface("eth1", "66:77:88:99:aa:bb")
	wlan = iface("wlan0", "cc:dd:ee:ff:00:11")
)

// --- FindRouteForIp ---

func TestFindRouteForIp_ExactIPMatch(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth0},
		{Type: IPv4, Destination: "10.1.2.3", NetworkInterface: eth1},
	}

	route, err := FindRouteForIp(net.ParseIP("10.1.2.3"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth1, route.NetworkInterface, "exact IP match should win over /8 CIDR")
}

func TestFindRouteForIp_ExactIPMatchDoesNotAffectOtherIPs(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "10.1.2.3", NetworkInterface: eth1},
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth0},
	}

	route, err := FindRouteForIp(net.ParseIP("10.1.2.4"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth0, route.NetworkInterface, "non-matching exact IP should fall through to CIDR")
}

func TestFindRouteForIp_LongestPrefixMatch(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth0},
		{Type: IPv4, Destination: "10.1.0.0/16", NetworkInterface: eth1},
		{Type: IPv4, Destination: "10.1.2.0/24", NetworkInterface: wlan},
	}

	route, err := FindRouteForIp(net.ParseIP("10.1.2.5"), routes)
	require.NoError(t, err)
	assert.Equal(t, wlan, route.NetworkInterface, "/24 should win over /16 and /8")
}

func TestFindRouteForIp_LPM_ReverseOrder(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "10.1.2.0/24", NetworkInterface: wlan},
		{Type: IPv4, Destination: "10.1.0.0/16", NetworkInterface: eth1},
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth0},
	}

	route, err := FindRouteForIp(net.ParseIP("10.1.2.5"), routes)
	require.NoError(t, err)
	assert.Equal(t, wlan, route.NetworkInterface, "order should not matter for LPM")
}

func TestFindRouteForIp_FallbackToDefault_IPv4(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Default: true, Destination: "0.0.0.0/0", NetworkInterface: eth0},
		{Type: IPv4, Destination: "192.168.1.0/24", NetworkInterface: eth1},
	}

	route, err := FindRouteForIp(net.ParseIP("8.8.8.8"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth0, route.NetworkInterface, "no matching CIDR should fall back to default")
}

func TestFindRouteForIp_FallbackToDefault_IPv6(t *testing.T) {
	routes := []*Route{
		{Type: IPv6, Default: true, Destination: "::/0", NetworkInterface: eth0},
		{Type: IPv6, Destination: "fd00::/8", NetworkInterface: eth1},
	}

	route, err := FindRouteForIp(net.ParseIP("2001:db8::1"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth0, route.NetworkInterface)
}

func TestFindRouteForIp_NoMatchNoDefault(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "192.168.1.0/24", NetworkInterface: eth0},
	}

	_, err := FindRouteForIp(net.ParseIP("8.8.8.8"), routes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "route not found")
}

func TestFindRouteForIp_EmptyRoutes(t *testing.T) {
	_, err := FindRouteForIp(net.ParseIP("10.0.0.1"), nil)
	assert.Error(t, err)
}

func TestFindRouteForIp_NilRoutesInSlice(t *testing.T) {
	routes := []*Route{
		nil,
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth0},
		nil,
	}

	route, err := FindRouteForIp(net.ParseIP("10.1.2.3"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth0, route.NetworkInterface)
}

func TestFindRouteForIp_IPv4InIPv6Routes(t *testing.T) {
	routes := []*Route{
		{Type: IPv6, Default: true, Destination: "::/0", NetworkInterface: eth0},
		{Type: IPv4, Default: true, Destination: "0.0.0.0/0", NetworkInterface: eth1},
	}

	route, err := FindRouteForIp(net.ParseIP("10.0.0.1"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth1, route.NetworkInterface, "IPv4 dst should match IPv4 default route")
}

func TestFindRouteForIp_DefaultRouteOnlySelectedWhenNoCIDRMatch(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Default: true, Destination: "0.0.0.0/0", NetworkInterface: eth0, Gateway: "10.0.0.1"},
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth1},
	}

	route, err := FindRouteForIp(net.ParseIP("10.5.5.5"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth1, route.NetworkInterface, "CIDR match should beat default route")
}

func TestFindRouteForIp_IPv6_LPM(t *testing.T) {
	routes := []*Route{
		{Type: IPv6, Destination: "fd00::/8", NetworkInterface: eth0},
		{Type: IPv6, Destination: "fd00:1::/32", NetworkInterface: eth1},
		{Type: IPv6, Destination: "fd00:1:2::/48", NetworkInterface: wlan},
	}

	route, err := FindRouteForIp(net.ParseIP("fd00:1:2::1"), routes)
	require.NoError(t, err)
	assert.Equal(t, wlan, route.NetworkInterface, "/48 should beat /32 and /8")
}

func TestFindRouteForIp_InvalidDestinations(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "not-a-cidr"},
		{Type: IPv4, Destination: "also-invalid", NetworkInterface: eth0},
		{Type: IPv4, Default: true, Destination: "0.0.0.0/0", NetworkInterface: eth1},
	}

	route, err := FindRouteForIp(net.ParseIP("10.0.0.1"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth1, route.NetworkInterface, "invalid destinations should be skipped gracefully")
}

func TestFindRouteForIp_HostRouteViaCIDR32(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth0},
		{Type: IPv4, Destination: "10.1.2.3/32", NetworkInterface: eth1},
	}

	route, err := FindRouteForIp(net.ParseIP("10.1.2.3"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth1, route.NetworkInterface, "/32 CIDR host route should be most specific")
}

func TestFindRouteForIp_MultipleDefaultsTakesFirst(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Default: true, Destination: "0.0.0.0/0", NetworkInterface: eth0, Gateway: "10.0.0.1"},
		{Type: IPv4, Default: true, Destination: "0.0.0.0/0", NetworkInterface: eth1, Gateway: "10.0.0.2"},
	}

	route, err := FindRouteForIp(net.ParseIP("8.8.8.8"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth0, route.NetworkInterface, "first default route should be used")
}

// --- FindRouteWithHwAndIp ---

func TestFindRouteWithHwAndIp_MatchByHWAddr(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth0},
		{Type: IPv4, Destination: "192.168.0.0/16", NetworkInterface: eth1},
	}

	route, err := FindRouteWithHwAndIp(eth1.HardwareAddr, nil, routes)
	require.NoError(t, err)
	assert.Equal(t, eth1, route.NetworkInterface)
}

func TestFindRouteWithHwAndIp_NoMatchHWAddr(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth0},
	}

	unknownMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	_, err := FindRouteWithHwAndIp(unknownMAC, nil, routes)
	assert.Error(t, err)
}

func TestFindRouteWithHwAndIp_BothEmpty(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth0},
	}

	_, err := FindRouteWithHwAndIp(nil, nil, routes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "both empty")
}

func TestFindRouteWithHwAndIp_NilRouteInSlice(t *testing.T) {
	routes := []*Route{
		nil,
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth0},
	}

	route, err := FindRouteWithHwAndIp(eth0.HardwareAddr, nil, routes)
	require.NoError(t, err)
	assert.Equal(t, eth0, route.NetworkInterface)
}

func TestFindRouteWithHwAndIp_NilInterface(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: nil},
	}

	unknownMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	_, err := FindRouteWithHwAndIp(unknownMAC, nil, routes)
	assert.Error(t, err)
}

// --- baseRouter ---

func TestBaseRouter_Route_DefaultSourceIP(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100")
	routes := []*Route{
		{
			Type:            IPv4,
			Default:         true,
			Destination:     "0.0.0.0/0",
			DefaultSourceIP: srcIP,
		},
	}

	router := &baseRouter{Routes: routes}
	_, _, preferredSrc, err := router.Route(net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	assert.Equal(t, srcIP, preferredSrc)
}

func TestBaseRouter_Route_NoRoutes(t *testing.T) {
	router := &baseRouter{Routes: nil}
	_, _, _, err := router.Route(net.ParseIP("8.8.8.8"))
	assert.Error(t, err)
}

func TestBaseRouter_Route_GatewayParsed(t *testing.T) {
	routes := []*Route{
		{
			Type:            IPv4,
			Default:         true,
			Destination:     "0.0.0.0/0",
			Gateway:         "10.0.0.1",
			DefaultSourceIP: net.ParseIP("10.0.0.100"),
		},
	}

	router := &baseRouter{Routes: routes}
	_, _, preferredSrc, err := router.Route(net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	assert.Equal(t, net.ParseIP("10.0.0.100"), preferredSrc)
}

func TestBaseRouter_Route_NoNetworkInterface(t *testing.T) {
	routes := []*Route{
		{
			Type:             IPv4,
			Default:          true,
			Destination:      "0.0.0.0/0",
			Gateway:          "10.0.0.1",
			NetworkInterface: nil,
		},
	}

	router := &baseRouter{Routes: routes}
	_, _, _, err := router.Route(net.ParseIP("8.8.8.8"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network interface")
}

func TestBaseRouter_RouteWithSrc_BothNil_DelegatesToRoute(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100")
	routes := []*Route{
		{
			Type:            IPv4,
			Default:         true,
			Destination:     "0.0.0.0/0",
			DefaultSourceIP: srcIP,
		},
	}

	router := &baseRouter{Routes: routes}
	_, _, preferredSrc, err := router.RouteWithSrc(nil, nil, net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	assert.Equal(t, srcIP, preferredSrc)
}

func TestBaseRouter_RouteWithSrc_InputNilSrcSet(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.5")
	routes := []*Route{
		{
			Type:             IPv4,
			Default:          true,
			Destination:      "0.0.0.0/0",
			Gateway:          "10.0.0.1",
			NetworkInterface: eth0,
		},
	}

	router := &baseRouter{Routes: routes}
	iface, gw, preferred, err := router.RouteWithSrc(nil, srcIP, net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	assert.Equal(t, eth0, iface)
	assert.Equal(t, net.ParseIP("10.0.0.1"), gw)
	assert.Equal(t, srcIP, preferred, "caller-specified src should be returned as preferred")
}

func TestBaseRouter_RouteWithSrc_HWAddrMatch(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.5")
	routes := []*Route{
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth0, Gateway: "10.0.0.1"},
		{Type: IPv4, Destination: "192.168.0.0/16", NetworkInterface: eth1, Gateway: "192.168.0.1"},
	}

	router := &baseRouter{Routes: routes}
	iface, _, _, err := router.RouteWithSrc(eth1.HardwareAddr, nil, net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	assert.Equal(t, eth1, iface)

	_ = srcIP
}

// --- RouteType ---

func TestRouteType_String(t *testing.T) {
	assert.Equal(t, "ipv4", IPv4.String())
	assert.Equal(t, "ipv6", IPv6.String())
}

// --- Edge cases ---

func TestFindRouteForIp_OverlappingCIDRs_SameMask(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "10.1.2.0/24", NetworkInterface: eth0, Gateway: "10.1.2.1"},
		{Type: IPv4, Destination: "10.1.2.0/24", NetworkInterface: eth1, Gateway: "10.1.2.2"},
	}

	route, err := FindRouteForIp(net.ParseIP("10.1.2.5"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth0, route.NetworkInterface, "same mask size, first encountered wins")
}

func TestFindRouteForIp_ExactIP_BothIPAndCIDR32(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "10.1.2.3/32", NetworkInterface: eth0},
		{Type: IPv4, Destination: "10.1.2.3", NetworkInterface: eth1},
	}

	route, err := FindRouteForIp(net.ParseIP("10.1.2.3"), routes)
	require.NoError(t, err)
	// Both have the same effective mask (/32), so the first one wins
	assert.Equal(t, eth0, route.NetworkInterface)
}

func TestFindRouteForIp_IPv6_ExactMatch(t *testing.T) {
	routes := []*Route{
		{Type: IPv6, Destination: "fd00::/8", NetworkInterface: eth0},
		{Type: IPv6, Destination: "fd00::1", NetworkInterface: eth1},
	}

	route, err := FindRouteForIp(net.ParseIP("fd00::1"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth1, route.NetworkInterface, "exact IPv6 match should beat /8")
}

func TestFindRouteForIp_MixedIPv4IPv6Routes(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Default: true, Destination: "0.0.0.0/0", NetworkInterface: eth0},
		{Type: IPv6, Default: true, Destination: "::/0", NetworkInterface: eth1},
		{Type: IPv4, Destination: "192.168.0.0/16", NetworkInterface: wlan},
	}

	v4Route, err := FindRouteForIp(net.ParseIP("192.168.1.1"), routes)
	require.NoError(t, err)
	assert.Equal(t, wlan, v4Route.NetworkInterface)

	v6Route, err := FindRouteForIp(net.ParseIP("2001:db8::1"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth1, v6Route.NetworkInterface)
}

func TestFindRouteForIp_DefaultRouteNotCountedAsCIDRMatch(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Default: true, Destination: "0.0.0.0/0", NetworkInterface: eth0},
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth1},
	}

	route, err := FindRouteForIp(net.ParseIP("10.5.5.5"), routes)
	require.NoError(t, err)
	assert.Equal(t, eth1, route.NetworkInterface)

	// 0.0.0.0/0 technically contains all IPs, but the /8 is more specific
	// and should win via LPM. Default route is LPM /0 which is < /8.
	// Since 0.0.0.0/0 is a valid CIDR, it enters the CIDR branch with ones=0.
	// The /8 has ones=8, so /8 wins via LPM. Good.
}

// --- Regression: ensure 0.0.0.0/0 CIDR doesn't outrank specific routes ---

func TestFindRouteForIp_DefaultCIDRvsSpecific(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Default: true, Destination: "0.0.0.0/0", NetworkInterface: eth0, Gateway: "10.0.0.1"},
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth1, Gateway: "10.0.0.2"},
		{Type: IPv4, Destination: "10.1.0.0/16", NetworkInterface: wlan, Gateway: "10.1.0.1"},
	}

	// 10.1.5.5 matches /8 (ones=8) and /16 (ones=16), and also 0.0.0.0/0 (ones=0).
	// LPM should pick /16.
	route, err := FindRouteForIp(net.ParseIP("10.1.5.5"), routes)
	require.NoError(t, err)
	assert.Equal(t, wlan, route.NetworkInterface)
	assert.Equal(t, "10.1.0.1", route.Gateway)
}

// --- Integration-style: baseRouter with realistic route table ---

func TestBaseRouter_RealisticRouteTable(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.50")

	routes := []*Route{
		{Type: IPv4, Default: true, Destination: "0.0.0.0/0", Gateway: "192.168.1.1", NetworkInterface: eth0},
		{Type: IPv4, Destination: "192.168.1.0/24", Gateway: "", NetworkInterface: eth0},
		{Type: IPv4, Destination: "10.10.0.0/16", Gateway: "192.168.1.254", NetworkInterface: eth1},
		{Type: IPv6, Default: true, Destination: "::/0", Gateway: "fe80::1", NetworkInterface: eth0},
	}

	router := &baseRouter{Routes: routes}

	t.Run("LAN address uses /24", func(t *testing.T) {
		route, err := FindRouteForIp(net.ParseIP("192.168.1.100"), routes)
		require.NoError(t, err)
		assert.Equal(t, eth0, route.NetworkInterface)
		assert.Empty(t, route.Gateway)
	})

	t.Run("VPN address uses /16", func(t *testing.T) {
		route, err := FindRouteForIp(net.ParseIP("10.10.5.5"), routes)
		require.NoError(t, err)
		assert.Equal(t, eth1, route.NetworkInterface)
		assert.Equal(t, "192.168.1.254", route.Gateway)
	})

	t.Run("Internet address uses default", func(t *testing.T) {
		route, err := FindRouteForIp(net.ParseIP("8.8.8.8"), routes)
		require.NoError(t, err)
		assert.Equal(t, eth0, route.NetworkInterface)
		assert.Equal(t, "192.168.1.1", route.Gateway)
	})

	t.Run("IPv6 unknown uses default", func(t *testing.T) {
		route, err := FindRouteForIp(net.ParseIP("2001:db8::1"), routes)
		require.NoError(t, err)
		assert.Equal(t, eth0, route.NetworkInterface)
	})

	_ = router
	_ = srcIP
}

// --- FindRouteWithHwAndIp advanced ---

func TestFindRouteWithHwAndIp_MatchByHWOnly_MultipleRoutes(t *testing.T) {
	routes := []*Route{
		{Type: IPv4, Destination: "10.0.0.0/8", NetworkInterface: eth0},
		{Type: IPv4, Destination: "10.1.0.0/16", NetworkInterface: eth0},
		{Type: IPv4, Destination: "192.168.0.0/16", NetworkInterface: eth1},
	}

	route, err := FindRouteWithHwAndIp(eth0.HardwareAddr, nil, routes)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.0/8", route.Destination, "first match by HW should be returned")
}

func TestFindRouteWithHwAndIp_EmptyRoutes(t *testing.T) {
	_, err := FindRouteWithHwAndIp(eth0.HardwareAddr, nil, nil)
	assert.Error(t, err)
}
