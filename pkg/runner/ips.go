package runner

import (
	"strings"

	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
)

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
		cdata, err := fileutil.ReadFile(options.ExcludeIpsFile)
		if err != nil {
			return excludedIps, err
		}
		for host := range cdata {
			ips, err := r.getExcludeItems(host)
			if err != nil {
				return nil, err
			}
			excludedIps = append(excludedIps, ips...)
		}
	}

	return excludedIps, nil
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
