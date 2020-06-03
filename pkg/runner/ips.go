package runner

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/projectdiscovery/naabu/pkg/scan"
)

func parseExcludedIps(options *Options) (map[string]struct{}, error) {
	excludeIps := make(map[string]struct{})
	var allIps []string
	if options.ExcludeIps != "" {
		allIps = append(allIps, strings.Split(options.ExcludeIps, ",")...)
	}

	if options.ExcludeIpsFile != "" {
		data, err := ioutil.ReadFile(options.ExcludeIpsFile)
		if err != nil {
			return nil, fmt.Errorf("could not read ips: %s", err)
		}
		allIps = append(allIps, strings.Split(string(data), "\n")...)
	}

	for _, ip := range allIps {
		if ip == "" {
			continue
		} else if scan.IsCidr(ip) {
			cidrIps, err := scan.Ips(ip)
			if err != nil {
				return nil, err
			}
			for _, i := range cidrIps {
				excludeIps[i] = struct{}{}
			}
		} else if scan.IsIP(ip) {
			excludeIps[ip] = struct{}{}
		} else {
			return nil, fmt.Errorf("exclude element not ip or range")
		}
	}

	return excludeIps, nil
}
