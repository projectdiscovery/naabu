//go:build windows

package routing

import (
	"net"
	"net/netip"
	"unsafe"

	"github.com/projectdiscovery/gologger"
	"golang.org/x/sys/windows"
)

// New creates a routing engine for windows
func New() (Router, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	var routes []*Route
	for _, row := range table.Rows() {
		dest, ok := sockaddrInetToAddr(row.DestinationPrefix.Prefix)
		if !ok {
			gologger.Debug().Msgf("invalid destination address: '%v'", row.DestinationPrefix.Prefix)
			continue
		}

		var routeType RouteType
		var maxPrefixLen int
		switch row.DestinationPrefix.Prefix.Family {
		case windows.AF_INET:
			routeType = IPv4
			maxPrefixLen = 32
		case windows.AF_INET6:
			routeType = IPv6
			maxPrefixLen = 128
		default:
			gologger.Debug().Msgf("unknown route type: '%d'", row.DestinationPrefix.Prefix.Family)
			continue
		}

		prefixLen := int(row.DestinationPrefix.PrefixLength)
		if prefixLen < 0 || prefixLen > maxPrefixLen {
			gologger.Debug().Msgf("invalid prefix length '%d' for family '%d'", row.DestinationPrefix.PrefixLength, row.DestinationPrefix.Prefix.Family)
			continue
		}

		route := &Route{
			Type:        routeType,
			Default:     prefixLen == 0,
			Destination: netip.PrefixFrom(dest, prefixLen).String(),
		}

		if gateway, ok := sockaddrInetToAddr(row.NextHop); ok && !gateway.IsUnspecified() {
			route.Gateway = gateway.String()
		}

		if row.InterfaceIndex != 0 {
			iface, err := net.InterfaceByIndex(int(row.InterfaceIndex))
			if err == nil {
				route.NetworkInterface = iface
			}
		}

		routes = append(routes, route)
	}

	return &baseRouter{Routes: routes}, nil
}

func sockaddrInetToAddr(addr windows.RawSockaddrInet) (netip.Addr, bool) {
	switch addr.Family {
	case windows.AF_INET:
		addr4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&addr))
		return netip.AddrFrom4(addr4.Addr), true
	case windows.AF_INET6:
		addr6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&addr))
		return netip.AddrFrom16(addr6.Addr), true
	default:
		return netip.Addr{}, false
	}
}
