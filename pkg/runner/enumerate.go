package runner

import (
	"net"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/pkg/log"
	"github.com/projectdiscovery/naabu/pkg/scan"
)

// EnumerateSingleHost performs port enumeration against a single host
func (r *Runner) EnumerateSingleHost(host string, ports map[int]struct{}, output string, add bool) {
	var hosts []string

	// If the host is a Domain, then perform resolution and discover all IP
	// addresses for a given host. Else use that host for port scanning
	if net.ParseIP(host) == nil {
		var initialHosts []string

		ips, err := net.LookupIP(host)
		if err != nil {
			log.Warningf("Could not get IP for host: %s\n", host)
			return
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				initialHosts = append(initialHosts, ip.String())
			}
		}

		if len(initialHosts) == 0 {
			log.Warningf("No IP addresses found for host: %s\n", host)
			return
		}

		if r.options.AllIPs {
			hosts = append(hosts, initialHosts...)
		} else {
			hosts = append(hosts, initialHosts[0])
		}

		log.Infof("Resolved domain %s to [%s] for enumeration", strings.Join(hosts, ","))
	} else {
		hosts = append(hosts, host)
		log.Infof("Using IP %s for enumeration\n", host)
	}

	foundPorts := make(map[int]struct{})

	for _, ip := range hosts {
		log.Infof("Starting scan on host %s (%s)\n", host, ip)

		scanner, err := scan.NewScanner(net.ParseIP(ip), time.Duration(r.options.Timeout)*time.Millisecond, r.options.Retries, r.options.Rate)
		if err != nil {
			log.Warningf("Could not start scan on host %s (%s): %s\n", host, ip, err)
			return
		}
		found, err := scanner.Scan(ports)
		if err != nil {
			log.Warningf("Could not scan on host %s (%s): %s\n", host, ip, err)
			return
		}

		log.Infof("Found %d ports on host %s (%s) with latency %s\n", len(found), host, ip, scanner.Latency)
		for p := range found {
			if _, ok := foundPorts[p]; !ok {
				foundPorts[p] = struct{}{}
			}
		}
	}

	if len(foundPorts) < 0 {
		log.Warningf("Could not scan on host %s (%s)\n", host)
		return
	}

	// If verbose mode was used, then now print all the ports together
	if r.options.Verbose {
		for port := range foundPorts {
			log.Silentf("%s:%d\n", host, port)
		}
	}

	// In case the user has given an output file, write all the found
	// ports to the output file.
	if output != "" {
		// If the output format is json, append .json
		// else append .txt
		if r.options.OutputDirectory != "" {
			if r.options.JSON {
				output = output + ".json"
			} else {
				output = output + ".txt"
			}
		}

		var file *os.File
		var err error
		if add {
			file, err = os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		} else {
			file, err = os.Create(output)
		}
		if err != nil {
			log.Errorf("Could not create file %s for %s: %s\n", output, host, err)
			return
		}

		// Write the output to the file depending upon user requirement
		if r.options.JSON {
			err = WriteJSONOutput(host, foundPorts, file)
		} else {
			err = WriteHostOutput(host, foundPorts, file)
		}
		if err != nil {
			log.Errorf("Could not write results to file %s for %s: %s\n", output, host, err)
		}
		file.Close()
		return
	}
	return
}
