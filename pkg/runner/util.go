package runner

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	iputil "github.com/projectdiscovery/utils/ip"
	osutil "github.com/projectdiscovery/utils/os"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

func (r *Runner) host2ips(target string) (targetIPsV4 []string, targetIPsV6 []string, err error) {
	// If the host is a Domain, then perform resolution and discover all IP
	// addresses for a given host. Else use that host for port scanning
	if !iputil.IsIP(target) {
		dnsData, dnsErr := r.dnsclient.QueryMultiple(target)
		if dnsErr == nil && dnsData != nil {
			if len(r.options.IPVersion) > 0 {
				if sliceutil.Contains(r.options.IPVersion, scan.IPv4) {
					targetIPsV4 = append(targetIPsV4, dnsData.A...)
				}
				if sliceutil.Contains(r.options.IPVersion, scan.IPv6) {
					targetIPsV6 = append(targetIPsV6, dnsData.AAAA...)
				}
			} else {
				targetIPsV4 = append(targetIPsV4, dnsData.A...)
				targetIPsV6 = append(targetIPsV6, dnsData.AAAA...)
			}
		}

		if len(targetIPsV4) == 0 && len(targetIPsV6) == 0 {
			// Fallback to system resolver for split-DNS / VPN setups
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ipAddrs, sysErr := net.DefaultResolver.LookupIPAddr(ctx, target)
			if sysErr == nil && len(ipAddrs) > 0 {
				for _, ipAddr := range ipAddrs {
					ip := ipAddr.IP
					if ip == nil {
						continue
					}
					if ip.To4() != nil {
						if len(r.options.IPVersion) == 0 || sliceutil.Contains(r.options.IPVersion, scan.IPv4) {
							targetIPsV4 = append(targetIPsV4, ip.String())
						}
					} else if ip.To16() != nil {
						if len(r.options.IPVersion) == 0 || sliceutil.Contains(r.options.IPVersion, scan.IPv6) {
							targetIPsV6 = append(targetIPsV6, ip.String())
						}
					}
				}
			}
			if len(targetIPsV4) == 0 && len(targetIPsV6) == 0 {
				if dnsErr != nil {
					gologger.Warning().Msgf("Could not get IP for host: %s\n", target)
					return nil, nil, dnsErr
				}
				return targetIPsV4, targetIPsV6, fmt.Errorf("no IP addresses found for host: %s", target)
			}
		}
	} else {
		if iputil.IsIPv4(target) {
			targetIPsV4 = append(targetIPsV4, target)
		} else if iputil.IsIPv6(target) {
			targetIPsV6 = append(targetIPsV6, target)
		}
		gologger.Debug().Msgf("Found %d IPv4 and %d IPv6 addresses for %s\n", len(targetIPsV4), len(targetIPsV6), target)
	}

	return
}

func isOSSupported() bool {
	return osutil.IsLinux() || osutil.IsOSX()
}

func getPort(target string) (string, string, bool) {
	host, port, err := net.SplitHostPort(target)
	if err == nil && iputil.IsPort(port) {
		return host, port, true
	}

	return target, "", false
}
