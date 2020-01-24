package runner

import (
	"net"
	"os"
	"time"

	"github.com/projectdiscovery/naabu/pkg/log"
	"github.com/projectdiscovery/naabu/pkg/scan"
)

// EnumerateSingleHost performs port enumeration against a single host
func (r *Runner) EnumerateSingleHost(host string, ports map[int]struct{}, output string, add bool) {
	var hostIP string

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

		hostIP = initialHosts[0]
		log.Infof("Resolved domain %s to %s for enumeration", host, hostIP)
	} else {
		hostIP = host
		log.Infof("Using IP %s for enumeration\n", host)
	}

	log.Infof("Starting scan on host %s (%s)\n", host, hostIP)

	scanner, err := scan.NewScanner(net.ParseIP(hostIP), time.Duration(r.options.Timeout)*time.Millisecond, r.options.Retries, r.options.Rate)
	if err != nil {
		log.Warningf("Could not start scan on host %s (%s): %s\n", host, hostIP, err)
		return
	}
	results, err := scanner.Scan(ports)
	if err != nil {
		log.Warningf("Could not scan on host %s (%s): %s\n", host, hostIP, err)
		return
	}

	if results.Latency == -1 {
		log.Infof("No ports found on %s (%s). Host seems down\n", host, hostIP)
		return
	}

	// Validate the host if the user has asked for second step validation
	if r.options.Verify {
		results.Ports = scanner.ConnectVerify(host, results.Ports)
	}
	log.Infof("Found %d ports on host %s (%s) with latency %s\n", len(results.Ports), host, hostIP, results.Latency)

	if len(results.Ports) <= 0 {
		log.Warningf("Could not scan on host %s (%s)\n", host)
		return
	}

	for port := range results.Ports {
		log.Silentf("%s:%d\n", host, port)
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
			err = WriteJSONOutput(host, results.Ports, file)
		} else {
			err = WriteHostOutput(host, results.Ports, file)
		}
		if err != nil {
			log.Errorf("Could not write results to file %s for %s: %s\n", output, host, err)
		}
		file.Close()
		return
	}
	return
}
