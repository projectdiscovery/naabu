package runner

import (
	"fmt"
	"net"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/projectdiscovery/retryabledns"
	iputil "github.com/projectdiscovery/utils/ip"
	osutil "github.com/projectdiscovery/utils/os"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

func (r *Runner) host2ips(target string) (targetIPsV4 []string, targetIPsV6 []string, err error) {
	// If the host is a Domain, then perform resolution and discover all IP
	// addresses for a given host. Else use that host for port scanning
	if !iputil.IsIP(target) {
		var dnsData *retryabledns.DNSData

		for _, order := range r.options.DnsOrder {
			if order == 'l' && r.dnsclient != nil {
				dnsData, err = r.dnsclient.QueryMultiple(target)
				if err == nil && dnsData != nil {
					break
				}
			} else if order == 'p' && r.dnsclientProxy != nil {
				dnsData, err = r.dnsclientProxy.QueryMultiple(target)
				if err == nil && dnsData != nil {
					break
				}
			}
		}

		if err != nil || dnsData == nil {
			gologger.Warning().Msgf("Could not get IP for host: %s\n", target)
			if err == nil {
				err = fmt.Errorf("could not resolve host: %s", target)
			}
			return nil, nil, err
		}
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
		if len(targetIPsV4) == 0 && len(targetIPsV6) == 0 {
			return targetIPsV4, targetIPsV6, fmt.Errorf("no IP addresses found for host: %s", target)
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
