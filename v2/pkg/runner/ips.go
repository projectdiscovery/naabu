package runner

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/yl2chen/cidranger"
)

func parseExcludedIps(options *Options) (cidranger.Ranger, error) {
	excludeipRanger := cidranger.NewPCTrieRanger()
	var allIps []string
	if options.ExcludeIps != "" {
		for _, ip := range strings.Split(options.ExcludeIps, ",") {
			err := scan.AddToRanger(excludeipRanger, ip)
			if err != nil {
				return nil, err
			}
		}
	}

	if options.ExcludeIpsFile != "" {
		data, err := ioutil.ReadFile(options.ExcludeIpsFile)
		if err != nil {
			return nil, fmt.Errorf("could not read ips: %s", err)
		}
		for _, ip := range strings.Split(string(data), "\n") {
			err := scan.AddToRanger(excludeipRanger, ip)
			if err != nil {
				return nil, err
			}
		}
	}

	if options.config != nil {
		for _, excludeIP := range options.config.ExcludeIps {
			for _, ip := range strings.Split(excludeIP, ",") {
				err := scan.AddToRanger(excludeipRanger, ip)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	for _, ip := range allIps {
		if ip == "" {
			continue
		} else if scan.IsCidr(ip) || scan.IsIP(ip) {
			err := scan.AddToRanger(excludeipRanger, ip)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("exclude element not ip or range")
		}
	}

	return excludeipRanger, nil
}
