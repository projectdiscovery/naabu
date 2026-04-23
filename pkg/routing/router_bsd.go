//go:build (darwin || dragonfly || freebsd || netbsd || openbsd) && !linux

package routing

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"

	"github.com/projectdiscovery/gologger"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"go.uber.org/multierr"
	"golang.org/x/net/route"
)

// New creates a routing engine for BSD (Darwin, FreeBSD, NetBSD, OpenBSD, DragonFly).
// It tries the native route API first, then falls back to netstat output parsing,
// and finally to outbound IP detection.
func New() (Router, error) {
	routes, err := fetchRoutesNative()
	if err != nil {
		gologger.Debug().Msgf("native route API failed, falling back to netstat: %v", err)
		routes, err = fetchRoutesNetstat()
	}
	if err != nil {
		gologger.Debug().Msgf("netstat fallback failed, falling back to outbound IPs: %v", err)
		return fallbackOutboundRoutes()
	}
	if len(routes) == 0 {
		return fallbackOutboundRoutes()
	}
	return &baseRouter{Routes: routes}, nil
}

// fetchRoutesNative reads the kernel routing table via golang.org/x/net/route.
func fetchRoutesNative() ([]*Route, error) {
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

		if routeMsg.Flags&syscall.RTF_UP == 0 {
			continue
		}
		if routeMsg.Flags&syscall.RTF_REJECT != 0 {
			continue
		}

		if len(routeMsg.Addrs) <= syscall.RTAX_DST || routeMsg.Addrs[syscall.RTAX_DST] == nil {
			continue
		}
		dstAddr := routeMsg.Addrs[syscall.RTAX_DST]

		if len(routeMsg.Addrs) <= syscall.RTAX_GATEWAY || routeMsg.Addrs[syscall.RTAX_GATEWAY] == nil {
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
			isDefault := dstIP.Equal(net.IPv4zero)
			r.Default = isDefault
			if isDefault && mask == nil {
				r.Destination = "0.0.0.0/0"
			} else if mask != nil {
				ones, _ := mask.Size()
				r.Destination = fmt.Sprintf("%s/%d", dstIP.Mask(mask).String(), ones)
			} else {
				r.Destination = fmt.Sprintf("%s/32", dstIP.String())
			}
		case *route.Inet6Addr:
			r.Type = IPv6
			dstIP := net.IP(t.IP[:])
			isDefault := dstIP.Equal(net.IPv6zero)
			r.Default = isDefault
			if isDefault && mask == nil {
				r.Destination = "::/0"
			} else if mask != nil {
				ones, _ := mask.Size()
				r.Destination = fmt.Sprintf("%s/%d", dstIP.Mask(mask).String(), ones)
			} else {
				r.Destination = fmt.Sprintf("%s/128", dstIP.String())
			}
		default:
			gologger.Debug().Msgf("unknown route type: '%T' (seq: %d)", dstAddr, routeMsg.Seq)
			continue
		}

		if routeMsg.Index > 0 {
			if iface, err := net.InterfaceByIndex(routeMsg.Index); err == nil {
				r.NetworkInterface = iface
			}
		}

		r.Flags = buildFlagsString(routeMsg.Flags)
		routes = append(routes, r)
	}
	return routes, nil
}

func buildFlagsString(flags int) string {
	var b strings.Builder
	type flagEntry struct {
		mask int
		char byte
	}
	for _, f := range []flagEntry{
		{syscall.RTF_UP, 'U'},
		{syscall.RTF_GATEWAY, 'G'},
		{syscall.RTF_HOST, 'H'},
		{syscall.RTF_REJECT, 'R'},
		{syscall.RTF_DYNAMIC, 'D'},
		{syscall.RTF_MODIFIED, 'M'},
		{syscall.RTF_STATIC, 'S'},
	} {
		if flags&f.mask != 0 {
			b.WriteByte(f.char)
		}
	}
	return b.String()
}

// fetchRoutesNetstat parses the output of `netstat -nr` as a fallback.
func fetchRoutesNetstat() ([]*Route, error) {
	netstatCmd := exec.Command("netstat", "-nr")
	netstatOutput, err := netstatCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat command failed: %w", err)
	}

	var routes []*Route
	var lastType RouteType

	scanner := bufio.NewScanner(bytes.NewReader(netstatOutput))
	for scanner.Scan() {
		outputLine := strings.TrimSpace(scanner.Text())
		if outputLine == "" {
			continue
		}

		parts := stringsutil.SplitAny(outputLine, " \t")
		if len(parts) < 4 || sliceutil.Contains(parts, "Destination") {
			continue
		}

		expire := "-1"
		if len(parts) > 4 {
			expire = parts[4]
		}

		r := &Route{
			Default:     stringsutil.EqualFoldAny(parts[0], "default"),
			Destination: parts[0],
			Gateway:     parts[1],
			Flags:       parts[2],
			Expire:      expire,
		}

		if networkInterface, ifErr := net.InterfaceByName(parts[3]); ifErr == nil {
			r.NetworkInterface = networkInterface
		}

		hasDots := stringsutil.ContainsAny(r.Destination, ".") || stringsutil.ContainsAny(r.Gateway, ".")
		hasColon := stringsutil.ContainsAny(r.Destination, ":") || stringsutil.ContainsAny(r.Gateway, ":")
		switch {
		case hasDots:
			r.Type = IPv4
		case hasColon:
			r.Type = IPv6
		default:
			if lastType != "" {
				gologger.Debug().Msgf("using '%s' for unknown route type: '%s'\n", lastType, outputLine)
				r.Type = lastType
			} else {
				return nil, fmt.Errorf("could not determine route type for: '%s'", outputLine)
			}
		}
		lastType = r.Type
		routes = append(routes, r)
	}

	return routes, nil
}

// fallbackOutboundRoutes creates minimal default routes from outbound IP detection.
func fallbackOutboundRoutes() (Router, error) {
	var routes []*Route

	ip4, ip6, errOutboundIps := GetOutboundIPs()
	if ip4 != nil {
		interface4, err := FindInterfaceByIp(ip4)
		if err != nil {
			return nil, err
		}
		routes = append(routes, &Route{
			Type:             IPv4,
			Default:          true,
			DefaultSourceIP:  ip4,
			NetworkInterface: interface4,
		})
	}

	if ip6 != nil {
		interface6, _ := FindInterfaceByIp(ip6)
		routes = append(routes, &Route{
			Type:             IPv6,
			Default:          true,
			DefaultSourceIP:  ip6,
			NetworkInterface: interface6,
		})
	} else if len(routes) > 0 {
		// Only add an IPv6 fallback if the IPv4 interface has an IPv6 address,
		// otherwise FindSourceIpForIp will fail with a confusing error.
		if iface := routes[0].NetworkInterface; iface != nil {
			if addrs, err := iface.Addrs(); err == nil {
				for _, a := range addrs {
					if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.To4() == nil {
						routes = append(routes, &Route{
							Type:             IPv6,
							Default:          true,
							DefaultSourceIP:  ipNet.IP,
							NetworkInterface: iface,
						})
						break
					}
				}
			}
		}
	}

	if len(routes) > 0 {
		return &baseRouter{Routes: routes}, nil
	}
	return nil, multierr.Combine(fmt.Errorf("all routing methods failed"), errOutboundIps)
}
