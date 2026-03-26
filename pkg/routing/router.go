package routing

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	iputil "github.com/projectdiscovery/utils/ip"
)

type RouteType string

const (
	IPv4 RouteType = "IPv4"
	IPv6 RouteType = "IPv6"
)

func (routeType RouteType) String() string {
	return strings.ToLower(string(routeType))
}

type Route struct {
	Type             RouteType
	Default          bool
	NetworkInterface *net.Interface
	Destination      string
	Gateway          string
	Flags            string
	Expire           string
	DefaultSourceIP  net.IP
}

// Router shares the same interface described in https://github.com/Mzack9999/gopacket
type Router interface {
	// Route returns where to route a packet based on the packet's source
	// and destination IP address.
	//
	// Callers may pass in nil for src, in which case the src is treated as
	// either 0.0.0.0 or ::, depending on whether dst is a v4 or v6 address.
	//
	// It returns the interface on which to send the packet, the gateway IP
	// to send the packet to (if necessary), the preferred src IP to use (if
	// available).  If the preferred src address is not given in the routing
	// table, the first IP address of the interface is provided.
	//
	// If an error is encountered, iface, geteway, and
	// preferredSrc will be nil, and err will be set.
	Route(dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error)

	// RouteWithSrc routes based on source information as well as destination
	// information.  Either or both of input/src can be nil.  If both are, this
	// should behave exactly like Route(dst)
	RouteWithSrc(input net.HardwareAddr, src, dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error)
}

// baseRouter implements the common logic for all platforms
type baseRouter struct {
	Routes []*Route
}

func (r *baseRouter) Route(dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	route, err := FindRouteForIp(dst, r.Routes)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "could not find route")
	}

	if route.DefaultSourceIP != nil {
		return nil, nil, route.DefaultSourceIP, nil
	}

	if route.NetworkInterface == nil {
		return nil, nil, nil, errors.New("could not find network interface")
	}
	ip, err := FindSourceIpForIp(route, dst)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "could not find source ip")
	}

	return route.NetworkInterface, net.ParseIP(route.Gateway), ip, nil
}

func (r *baseRouter) RouteWithSrc(input net.HardwareAddr, src, dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	if len(input) == 0 && src == nil {
		return r.Route(dst)
	}

	if len(input) == 0 && src != nil {
		route, routeErr := FindRouteForIp(dst, r.Routes)
		if routeErr != nil {
			return nil, nil, nil, errors.Wrap(routeErr, "could not find route")
		}
		if route.NetworkInterface == nil {
			return nil, nil, nil, errors.New("could not find network interface")
		}
		return route.NetworkInterface, net.ParseIP(route.Gateway), src, nil
	}

	route, err := FindRouteWithHwAndIp(input, src, r.Routes)
	if err != nil {
		return nil, nil, nil, err
	}
	if route.NetworkInterface == nil {
		return nil, nil, nil, errors.New("could not find network interface")
	}
	return route.NetworkInterface, net.ParseIP(route.Gateway), src, nil
}

func FindRouteForIp(ip net.IP, routes []*Route) (*Route, error) {
	var defaultRoute4, defaultRoute6 *Route
	var bestRoute *Route
	bestMaskSize := -1

	for _, route := range routes {
		if route == nil {
			continue
		}
		if defaultRoute4 == nil && route.Default && route.Type == IPv4 {
			defaultRoute4 = route
		}
		if defaultRoute6 == nil && route.Default && route.Type == IPv6 {
			defaultRoute6 = route
		}

		// exact host IP match — treat as most-specific (/32 or /128)
		if itfDestIP := net.ParseIP(route.Destination); itfDestIP != nil {
			if itfDestIP.Equal(ip) {
				hostBits := 128
				if iputil.IsIPv4(itfDestIP) {
					hostBits = 32
				}
				if hostBits > bestMaskSize {
					bestMaskSize = hostBits
					bestRoute = route
				}
			}
			continue
		}

		if _, itfDrstCidr, err := net.ParseCIDR(route.Destination); err == nil {
			if itfDrstCidr.Contains(ip) {
				ones, _ := itfDrstCidr.Mask.Size()
				if ones > bestMaskSize {
					bestMaskSize = ones
					bestRoute = route
				}
			}
		}
	}

	if bestRoute != nil {
		return bestRoute, nil
	}

	switch {
	case iputil.IsIPv4(ip) && defaultRoute4 != nil:
		return defaultRoute4, nil
	case iputil.IsIPv6(ip) && defaultRoute6 != nil:
		return defaultRoute6, nil
	}

	return nil, fmt.Errorf("route not found for %s", ip)
}

func FindSourceIpForIp(route *Route, ip net.IP) (net.IP, error) {
	addresses, err := route.NetworkInterface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		ipNet, ok := address.(*net.IPNet)
		if !ok || ipNet == nil {
			continue
		}
		ipAddress := ipNet.IP
		switch {
		case iputil.IsIPv4(ip, ipAddress):
			return ipAddress, nil
		case iputil.IsIPv6(ip, ipAddress) && !ipAddress.IsLinkLocalUnicast(): // link local unicast are not routeable
			return ipAddress, nil
		}
	}

	return nil, fmt.Errorf("could not find source ip for target \"%s\" with interface %s", ip, route.NetworkInterface.Name)
}

func GetOutboundIPs() (net.IP, net.IP, error) {
	// collect default outbound ipv4 and ipv6
	srcIPv4, err := iputil.GetSourceIP("128.199.158.128") // scanme.sh
	if err != nil {
		return nil, nil, errors.Wrap(err, "couldn't determine ipv4 routing interface")
	}

	// ignores errors on ipv6 routing
	srcIPv6, err := iputil.GetSourceIP("2400:6180:0:d0::91:1001") // scanme.sh
	if err != nil {
		return srcIPv4, nil, errors.Wrap(err, "couldn't determine ipv6 routing interface")
	}

	return srcIPv4, srcIPv6, nil
}

func FindRouteWithHwAndIp(hardwareAddr net.HardwareAddr, src net.IP, routes []*Route) (*Route, error) {
	if len(hardwareAddr) == 0 && src == nil {
		return nil, errors.New("hardware address and source ip are both empty")
	}

	for _, route := range routes {
		if route == nil || route.NetworkInterface == nil {
			continue
		}

		hwMatch := len(hardwareAddr) > 0 && bytes.EqualFold(route.NetworkInterface.HardwareAddr, hardwareAddr)
		if len(hardwareAddr) > 0 && !hwMatch {
			continue
		}

		if src != nil {
			addresses, err := route.NetworkInterface.Addrs()
			if err != nil {
				return nil, err
			}
			for _, address := range addresses {
				if addressIP, ok := address.(*net.IPNet); ok {
					if addressIP.IP.Equal(src) {
						return route, nil
					}
				}
			}
		} else {
			return route, nil
		}
	}

	return nil, errors.New("route not found")
}

func FindInterfaceByIp(ip net.IP) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, itf := range interfaces {
		addresses, err := itf.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			ipNet, ok := address.(*net.IPNet)
			if !ok || ipNet == nil {
				continue
			}
			ipAddress := ipNet.IP
			// check if they are equal
			areEqual := ipAddress.Equal(ip)
			if !areEqual {
				continue
			}
			// double check if they belongs to the same family as go standard library is faulty
			switch {
			case iputil.IsIPv4(ip, ipAddress):
				return &itf, nil
			case iputil.IsIPv6(ip, ipAddress):
				return &itf, nil
			}
		}
	}

	return nil, errors.New("interface not found")
}
