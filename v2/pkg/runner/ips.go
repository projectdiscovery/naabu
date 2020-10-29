package runner

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/projectdiscovery/naabu/v2/pkg/ipranger"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
)

func parseExcludedIps(options *Options, scanner *scan.Scanner) error {
	var allIps []string
	if options.ExcludeIps != "" {
		for _, ip := range strings.Split(options.ExcludeIps, ",") {
			err := scanner.IPRanger.Exclude(ip)
			if err != nil {
				return err
			}
		}
	}

	if options.ExcludeIpsFile != "" {
		data, err := ioutil.ReadFile(options.ExcludeIpsFile)
		if err != nil {
			return fmt.Errorf("could not read ips: %s", err)
		}
		for _, ip := range strings.Split(string(data), "\n") {
			err := scanner.IPRanger.Exclude(ip)
			if err != nil {
				return err
			}
		}
	}

	if options.config != nil {
		for _, excludeIP := range options.config.ExcludeIps {
			for _, ip := range strings.Split(excludeIP, ",") {
				err := scanner.IPRanger.Exclude(ip)
				if err != nil {
					return err
				}
			}
		}
	}

	for _, ip := range allIps {
		if ip == "" {
			continue
		} else if ipranger.IsCidr(ip) || ipranger.IsIP(ip) {
			err := scanner.IPRanger.Exclude(ip)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("exclude element not ip or range")
		}
	}

	return nil
}
