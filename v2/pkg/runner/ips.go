package runner

import (
	"strings"

	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
)

func parseExcludedIps(options *Options) ([]string, error) {
	var excludedIps []string
	if options.ExcludeIps != "" {
		excludedIps = append(excludedIps, strings.Split(options.ExcludeIps, ",")...)
	}

	if options.ExcludeIpsFile != "" {
		cdata, err := fileutil.ReadFile(options.ExcludeIpsFile)
		if err != nil {
			return excludedIps, err
		}
		for ip := range cdata {
			if isIpOrCidr(ip) {
				excludedIps = append(excludedIps, ip)
			}
		}
	}

	return excludedIps, nil
}

func isIpOrCidr(s string) bool {
	return iputil.IsIP(s) || iputil.IsCIDR(s)
}
