//go:build darwin

package routing

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/sliceutil"
	"github.com/projectdiscovery/stringsutil"
	"go.uber.org/multierr"
)

// New creates a routing engine for Darwin
func New() (Router, error) {
	var routes []*Route

	netstatCmd := exec.Command("netstat", "-nr")
	netstatOutput, err := netstatCmd.Output()
	if err != nil {
		// create default routes with outgoing ips
		ip4, ip6, errOutboundIps := GetOutboundIPs()
		if ip4 != nil {
			route4 := &Route{
				Type:            IPv4,
				Default:         true,
				DefaultSourceIP: ip4,
			}
			routes = append(routes, route4)
		}
		if ip6 != nil {
			route6 := &Route{
				Type:            IPv6,
				Default:         true,
				DefaultSourceIP: ip6,
			}
			routes = append(routes, route6)
		}
		if len(routes) > 0 {
			return &RouterDarwin{Routes: routes}, nil
		}
		return nil, multierr.Combine(err, errOutboundIps)
	}

	scanner := bufio.NewScanner(bytes.NewReader(netstatOutput))
	for scanner.Scan() {
		outputLine := strings.TrimSpace(scanner.Text())
		if outputLine == "" {
			continue
		}

		parts := stringsutil.SplitAny(outputLine, " \t")
		if len(parts) >= 4 && !sliceutil.Contains(parts, "Destination") {
			expire := "-1"
			if len(parts) > 4 {
				expire = parts[4]
			}

			route := &Route{
				Default:     stringsutil.EqualFoldAny(parts[0], "default"),
				Destination: parts[0],
				Gateway:     parts[1],
				Flags:       parts[2],
				Expire:      expire,
			}

			if networkInterface, err := net.InterfaceByName(parts[3]); err == nil {
				route.NetworkInterface = networkInterface
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

	return &RouterDarwin{Routes: routes}, err
}

type RouterDarwin struct {
	Routes []*Route
}

func (r *RouterDarwin) Route(dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	route, err := FindRouteForIp(dst, r.Routes)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "could not find route")
	}

	if route.DefaultSourceIP != nil {
		return nil, nil, route.DefaultSourceIP, nil
	}

	if route.NetworkInterface == nil {
		return nil, nil, nil, errors.Wrap(err, "could not find network interface")
	}
	ip, err := FindSourceIpForIp(route, dst)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "could not find source ip")
	}

	return route.NetworkInterface, net.IP(route.Gateway), ip, nil
}

func (r *RouterDarwin) RouteWithSrc(input net.HardwareAddr, src, dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	route, err := FindRouteWithHwAndIp(input, src, r.Routes)
	if err != nil {
		return nil, nil, nil, err
	}

	return route.NetworkInterface, net.IP(route.Gateway), src, nil
}
