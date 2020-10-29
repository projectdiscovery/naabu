package runner

import (
	"fmt"
	"net"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
)

func isRoot() bool {
	return os.Geteuid() == 0
}

func (r *Runner) host2ips(target string) (targetIPs []string, err error) {
	// If the host is a Domain, then perform resolution and discover all IP
	// addresses for a given host. Else use that host for port scanning
	if net.ParseIP(target) == nil {
		var ips []string
		ips, err = r.dnsprobe.Lookup(target)
		if err != nil {
			gologger.Warningf("Could not get IP for host: %s\n", target)
			return
		}
		for _, ip := range ips {
			if mapcidr.IsIPv4(net.ParseIP(ip)) {
				targetIPs = append(targetIPs, ip)
			}
		}

		if len(targetIPs) == 0 {
			return targetIPs, fmt.Errorf("no IP addresses found for host: %s", target)
		}
	} else {
		targetIPs = append(targetIPs, target)
		gologger.Debugf("Found %d addresses for %s\n", len(targetIPs), target)
	}

	return
}
