//go:build windows

package routing

import (
	"bufio"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/executil"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/naabu/v2/pkg/util"
	"github.com/projectdiscovery/sliceutil"
	"github.com/projectdiscovery/stringsutil"
)

// New creates a routing engine for Darwin
func New() (Router, error) {
	var routes []*Route

	netstatOutput, err := executil.Run("netstat -nr")
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(netstatOutput))
	for scanner.Scan() {
		outputLine := strings.TrimSpace(scanner.Text())
		if outputLine == "" {
			continue
		}

		parts := stringsutil.SplitAny(outputLine, " \t")
		if len(parts) == 5 && !sliceutil.Contains(parts, "Destination") {
			route := &Route{
				Default:          stringsutil.EqualFoldAny(parts[1], "default"),
				NetworkInterface: parts[4],
				Destination:      parts[1],
				Gateway:          parts[2],
				Flags:            parts[3],
				Expire:           parts[5],
			}

			hasDots := stringsutil.ContainsAny(route.Destination, ".") || stringsutil.ContainsAny(route.Gateway, ".")
			hasSemicolon := stringsutil.ContainsAny(route.Destination, ":") || stringsutil.ContainsAny(route.Gateway, ":")
			switch {
			case hasDots:
				route.Type = IPv4
			case hasSemicolon:
				route.Type = IPv6
			default:
				return nil, errors.New("unknown route type")
			}

			routes = append(routes, route)
		}
	}

	// collect default outbound ipv4 and ipv6
	srcIP4, err := iputil.GetSourceIP("8.8.8.8")
	if err != nil {
		return nil, err
	}
	// ignores errors on ipv6 routing
	srcIP6, err := iputil.GetSourceIP("2001:4860:4860::8888")
	if err != nil {
		err = errors.Wrap(err, "couldn't determine ipv6 routing interface")
	}

	return &RouterDarwin{Routes: routes, DefaultSourceIP4: srcIP4, DefaultSourceIP6: srcIP6}, err
}

type RouterDarwin struct {
	Routes           []*Route
	DefaultSourceIP4 net.IP
	DefaultSourceIP6 net.IP
}

func (r *RouterDarwin) Route(dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	switch {
	case dst.To4() != nil:
		return nil, nil, r.DefaultSourceIP4, nil
	case dst.To16() != nil:
		return nil, nil, r.DefaultSourceIP6, nil
	}
	return nil, nil, nil, errors.New("could not find route")
}

func (r *RouterDarwin) RouteWithSrc(input net.HardwareAddr, src, dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	return nil, nil, nil, errors.New("not implemented")
}

func (r *RouterDarwin) FindSourceIP(ip net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	var foundRoute *Route
	// first we need to find the interface associated to the destination
	for _, route := range r.Routes {
		// the destination can be an ip or cidr
		if itfDestIP := net.ParseIP(route.Destination); itfDestIP != nil {
			// if it's an ip compare it with our dest
			if itfDestIP.Equal(ip) {
				foundRoute = route
				break
			}
		}

		// if it's a cidr, verify that the destination ip is contained
		if _, itfDrstCidr, err := net.ParseCIDR(route.Destination); err == nil {
			if itfDrstCidr.Contains(ip) {
				foundRoute = route
				break
			}
		}
	}

	// find the ip associated with the found network interface
	networkInterface, err := net.InterfaceByName(foundRoute.NetworkInterface)
	if err != nil {
		return nil, err
	}
	addresses, err := networkInterface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		addressString := address.String()
		addressIP := net.ParseIP(addressString)
		switch {
		case ip.To4() != nil && iputil.IsIPv4(addressString):
			return addressIP, nil
		case ip.To16() != nil && iputil.IsIPv6(addressString):
			return addressIP, nil
		}
	}

	switch {
	case ip.To4() != nil && r.DefaultSourceIP4 != nil:
		return r.DefaultSourceIP4, nil
	case ip.To16() != nil && r.DefaultSourceIP6 != nil:
		return r.DefaultSourceIP6, nil
	default:
		return nil, errors.New("couldn't find source ip")
	}
}
