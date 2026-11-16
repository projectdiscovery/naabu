package runner

import (
	"strings"

	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
)

// nonUnicastRanges can never be a scan target, so they are always excluded.
// Dialing 0.0.0.0/8 or :: reaches the scanning host itself and reports its own
// services as the target's, and multicast/reserved space only wastes probes
// (1/8 of IPv4, so a 0.0.0.0/0 scan spent 12.5% of its packets on it).
// Private, loopback and link-local ranges stay scannable on purpose.
var nonUnicastRanges = []string{
	"0.0.0.0/8",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"ff00::/8",
}

func (r *Runner) parseExcludedIps(options *Options) ([]string, error) {
	var excludedIps []string
	if options.ExcludeIps != "" {
		for _, host := range strings.Split(options.ExcludeIps, ",") {
			ips, err := r.getExcludeItems(host)
			if err != nil {
				return nil, err
			}
			excludedIps = append(excludedIps, ips...)
		}
	}

	if options.ExcludeIpsFile != "" {
		for host, err := range fileutil.Lines(options.ExcludeIpsFile) {
			if err != nil {
				return excludedIps, err
			}
			ips, err := r.getExcludeItems(host)
			if err != nil {
				return nil, err
			}
			excludedIps = append(excludedIps, ips...)
		}
	}

	return excludedIps, nil
}

// isExcluded reports whether ip matches the user supplied exclude list
// (-exclude-hosts / -exclude-file) or nonUnicastRanges.
func (r *Runner) isExcluded(ip string) bool {
	return r.excludedIpsNP != nil && !r.excludedIpsNP.ValidateAddress(ip)
}

func (r *Runner) getExcludeItems(s string) ([]string, error) {
	if isIpOrCidr(s) {
		return []string{s}, nil
	}

	ips4, ips6, err := r.host2ips(s)
	if err != nil {
		return nil, err
	}
	return append(ips4, ips6...), nil
}

func isIpOrCidr(s string) bool {
	return iputil.IsIP(s) || iputil.IsCIDR(s)
}
