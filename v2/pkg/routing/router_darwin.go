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
)

// New creates a routing engine for Darwin
func New() (Router, error) {
	var routes []*Route

	netstatCmd := exec.Command("netstat", "-nr")
	netstatOutput, err := netstatCmd.Output()
	if err != nil {
		return nil, err
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
