//go:build windows

package routing

import (
	"bufio"
	"bytes"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/gologger"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"golang.org/x/sys/windows"
)

// New creates a routing engine for Windows.
// It tries the native GetIpForwardTable2 API first, then falls back to
// netsh output parsing.
func New() (Router, error) {
	routes, err := fetchRoutesNative()
	if err != nil {
		gologger.Debug().Msgf("native Windows routing API failed, falling back to netsh: %v", err)
		routes, err = fetchRoutesNetsh()
	}
	if err != nil {
		return nil, err
	}
	return &baseRouter{Routes: routes}, nil
}

// fetchRoutesNative reads the kernel routing table via GetIpForwardTable2.
func fetchRoutesNative() ([]*Route, error) {
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
		if prefixLen > maxPrefixLen {
			gologger.Debug().Msgf("invalid prefix length '%d' for family '%d'", row.DestinationPrefix.PrefixLength, row.DestinationPrefix.Prefix.Family)
			continue
		}

		route := &Route{
			Type:        routeType,
			Default:     prefixLen == 0,
			Destination: netip.PrefixFrom(dest, prefixLen).String(),
		}

		if gateway, gwOk := sockaddrInetToAddr(row.NextHop); gwOk && !gateway.IsUnspecified() {
			route.Gateway = gateway.String()
		}

		if row.InterfaceIndex != 0 {
			iface, ifErr := net.InterfaceByIndex(int(row.InterfaceIndex))
			if ifErr == nil {
				route.NetworkInterface = iface
			}
		}

		routes = append(routes, route)
	}

	return routes, nil
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

// fetchRoutesNetsh parses the output of `netsh interface ipv4/ipv6 show route` as a fallback.
func fetchRoutesNetsh() ([]*Route, error) {
	var routes []*Route

	for _, iptype := range []RouteType{IPv4, IPv6} {
		netshCmd := exec.Command("netsh", "interface", iptype.String(), "show", "route")
		netshOutput, err := netshCmd.Output()
		if err != nil {
			return nil, err
		}

		scanner := bufio.NewScanner(bytes.NewReader(netshOutput))
		for scanner.Scan() {
			outputLine := strings.TrimSpace(scanner.Text())
			if outputLine == "" {
				continue
			}

			parts := stringsutil.SplitAny(outputLine, " \t")
			if len(parts) < 6 || !govalidator.IsNumeric(parts[4]) {
				continue
			}

			prefix := parts[3]
			if _, _, err := net.ParseCIDR(prefix); err != nil {
				continue
			}
			gateway := parts[5]
			interfaceIndex, err := strconv.Atoi(parts[4])
			if err != nil {
				continue
			}

			networkInterface, err := net.InterfaceByIndex(interfaceIndex)
			if err != nil {
				continue
			}
			isDefault := stringsutil.EqualFoldAny(prefix, "0.0.0.0/0", "::/0")

			route := &Route{
				Type:             iptype,
				Default:          isDefault,
				Destination:      prefix,
				Gateway:          gateway,
				NetworkInterface: networkInterface,
			}

			routes = append(routes, route)
		}
	}

	return routes, nil
}
