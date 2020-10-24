package runner

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/yl2chen/cidranger"
)

func parseExcludedIps(options *Options) (cidranger.Ranger, error) {
	excludeipRanger := cidranger.NewPCTrieRanger()
	var allIps []string
	if options.ExcludeIps != "" {
		for _, ip := range strings.Split(options.ExcludeIps, ",") {
			err := addToRanger(excludeipRanger, ip)
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
			err := addToRanger(excludeipRanger, ip)
			if err != nil {
				return nil, err
			}
		}
	}

	if options.config != nil {
		for _, excludeIP := range options.config.ExcludeIps {
			for _, ip := range strings.Split(excludeIP, ",") {
				err := addToRanger(excludeipRanger, ip)
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
			err := addToRanger(excludeipRanger, ip)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("exclude element not ip or range")
		}
	}

	return excludeipRanger, nil
}

func addToRanger(ipranger cidranger.Ranger, ipcidr string) error {
	// if it's an ip convert it to cidr representation
	if scan.IsIP(ipcidr) {
		ipcidr += "/32"
	}
	// Check if it's a cidr
	_, network, err := net.ParseCIDR(ipcidr)
	if err != nil {
		return err
	}
	return ipranger.Insert(cidranger.NewBasicRangerEntry(*network))
}
