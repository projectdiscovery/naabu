//go:build darwin

package routing

import (
	"fmt"
	"net"
	"syscall"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/route"
)

// New creates a routing engine for Darwin
func New() (Router, error) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch routing table: %w", err)
	}

	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("failed to parse routing table: %w", err)
	}

	var routes []*Route
	for _, msg := range msgs {
		routeMsg, ok := msg.(*route.RouteMessage)
		if !ok {
			gologger.Debug().Msgf("invalid route message: '%T'\n", msg)
			continue
		}

		// Skip if route is down
		if routeMsg.Flags&syscall.RTF_UP == 0 {
			gologger.Debug().Msgf("route is down (seq: %d)", routeMsg.Seq)
			continue
		}

		// Try to get destination address
		if len(routeMsg.Addrs) <= syscall.RTAX_DST || routeMsg.Addrs[syscall.RTAX_DST] == nil {
			gologger.Debug().Msgf("no destination address found (seq: %d)", routeMsg.Seq)
			continue
		}
		dstAddr := routeMsg.Addrs[syscall.RTAX_DST]

		// Try to get gateway address
		if len(routeMsg.Addrs) <= syscall.RTAX_GATEWAY || routeMsg.Addrs[syscall.RTAX_GATEWAY] == nil {
			gologger.Debug().Msgf("no gateway address found (seq: %d)", routeMsg.Seq)
			continue
		}
		gwAddr := routeMsg.Addrs[syscall.RTAX_GATEWAY]

		r := &Route{Expire: "-1"}
		switch t := gwAddr.(type) {
		case *route.Inet4Addr:
			r.Gateway = net.IP(t.IP[:]).String()
		case *route.Inet6Addr:
			r.Gateway = net.IP(t.IP[:]).String()
		case *route.LinkAddr:
			r.Gateway = ""
		default:
			gologger.Debug().Msgf("unknown gateway type: '%T' (seq: %d)", gwAddr, routeMsg.Seq)
			continue
		}

		var mask net.IPMask
		if len(routeMsg.Addrs) > syscall.RTAX_NETMASK && routeMsg.Addrs[syscall.RTAX_NETMASK] != nil {
			switch t := routeMsg.Addrs[syscall.RTAX_NETMASK].(type) {
			case *route.Inet4Addr:
				mask = net.IPv4Mask(t.IP[0], t.IP[1], t.IP[2], t.IP[3])
			case *route.Inet6Addr:
				mask = net.IPMask(t.IP[:])
			}
		}

		switch t := dstAddr.(type) {
		case *route.Inet4Addr:
			r.Type = IPv4
			dstIP := net.IP(t.IP[:])
			if mask != nil {
				ones, _ := mask.Size()
				r.Destination = fmt.Sprintf("%s/%d", dstIP.String(), ones)
			} else {
				r.Destination = fmt.Sprintf("%s/32", dstIP.String())
			}
			r.Default = dstIP.Equal(net.IPv4(0, 0, 0, 0))
		case *route.Inet6Addr:
			r.Type = IPv6
			dstIP := net.IP(t.IP[:])
			if mask != nil {
				ones, _ := mask.Size()
				r.Destination = fmt.Sprintf("%s/%d", dstIP.String(), ones)
			} else {
				r.Destination = fmt.Sprintf("%s/128", dstIP.String())
			}
			r.Default = dstIP.Equal(net.ParseIP("::"))
		default:
			gologger.Debug().Msgf("unknown route type: '%T' (seq: %d)", dstAddr, routeMsg.Seq)
			continue
		}

		// Try to get network interface
		if routeMsg.Index > 0 {
			if iface, err := net.InterfaceByIndex(routeMsg.Index); err == nil {
				r.NetworkInterface = iface
			}
		}

		// Handle flags string
		flags := ""
		if routeMsg.Flags&syscall.RTF_UP != 0 {
			flags += "U"
		}
		if routeMsg.Flags&syscall.RTF_GATEWAY != 0 {
			flags += "G"
		}
		if routeMsg.Flags&syscall.RTF_HOST != 0 {
			flags += "H"
		}
		if routeMsg.Flags&syscall.RTF_REJECT != 0 {
			flags += "R"
		}
		if routeMsg.Flags&syscall.RTF_DYNAMIC != 0 {
			flags += "D"
		}
		if routeMsg.Flags&syscall.RTF_MODIFIED != 0 {
			flags += "M"
		}
		if routeMsg.Flags&syscall.RTF_STATIC != 0 {
			flags += "S"
		}
		r.Flags = flags

		routes = append(routes, r)
	}
	return &RouterDarwin{Routes: routes}, nil
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

	return route.NetworkInterface, net.ParseIP(route.Gateway), ip, nil
}

func (r *RouterDarwin) RouteWithSrc(input net.HardwareAddr, src, dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	route, err := FindRouteWithHwAndIp(input, src, r.Routes)
	if err != nil {
		return nil, nil, nil, err
	}
	return route.NetworkInterface, net.ParseIP(route.Gateway), src, nil
}
