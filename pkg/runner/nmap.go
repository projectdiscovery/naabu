package runner

import (
	"context"
	"fmt"
	"strings"

	"github.com/Ullaakut/nmap/v3"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
)

func (r *Runner) handleNmap() error {
	// Only run nmap if custom CLI arguments are provided
	if r.options.NmapCLI == "" {
		return nil
	}

	var ipsPorts []*result.HostResult
	// build a list of all targets
	for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
		ipsPorts = append(ipsPorts, hostResult)
	}

	if len(ipsPorts) == 0 {
		gologger.Info().Msg("No hosts with open ports found for nmap scan")
		return nil
	}

	// Group hosts by port count for efficient scanning
	ranges := make(map[int][]*result.HostResult)
	for _, ipPorts := range ipsPorts {
		length := len(ipPorts.Ports)
		var index int
		switch {
		case length > 100 && length < 1000:
			index = 1
		case length >= 1000 && length < 10000:
			index = 2
		case length >= 10000:
			index = 3
		default:
			index = 0
		}
		ranges[index] = append(ranges[index], ipPorts)
	}

	for rangeIndex, rang := range ranges {
		if len(rang) == 0 {
			continue
		}

		var (
			ips   []string
			ports []string
		)
		allports := make(map[int]struct{})
		for _, ipPorts := range rang {
			ips = append(ips, ipPorts.IP)
			for _, pp := range ipPorts.Ports {
				allports[pp.Port] = struct{}{}
			}
		}
		for p := range allports {
			ports = append(ports, fmt.Sprint(p))
		}

		// if we have no open ports we avoid running nmap
		if len(ports) == 0 {
			continue
		}

		portsStr := strings.Join(ports, ",")
		ipsStr := strings.Join(ips, " ")

		gologger.Info().Msgf("Running nmap scan on range %d: %s -p %s", rangeIndex, ipsStr, portsStr)

		// Create scanner options
		var scannerOptions []nmap.Option

		// Add targets and ports
		scannerOptions = append(scannerOptions, nmap.WithTargets(ips...))
		scannerOptions = append(scannerOptions, nmap.WithPorts(portsStr))

		// Parse the custom CLI command
		args := strings.Fields(r.options.NmapCLI)

		// Remove "nmap" from the beginning if present
		if len(args) > 0 && (args[0] == "nmap" || args[0] == "nmap.exe") {
			args = args[1:]
		}

		// Extract and remove -oX arguments since the library handles XML output internally
		var outputFile string
		filteredArgs := make([]string, 0, len(args))
		for i := 0; i < len(args); i++ {
			if args[i] == "-oX" {
				// Check if there's a filename after -oX
				if i+1 < len(args) {
					nextArg := args[i+1]
					// If next arg is "-", it means stdout (library handles this by default)
					// Otherwise, it's a filename
					if nextArg != "-" {
						outputFile = nextArg
						i++ // Skip the filename in the next iteration
					} else {
						i++ // Skip the "-" argument
					}
				}
				// Skip -oX itself (and filename/stdout marker if present)
				continue
			}
			filteredArgs = append(filteredArgs, args[i])
		}

		// Add custom arguments (without -oX)
		scannerOptions = append(scannerOptions, nmap.WithCustomArguments(filteredArgs...)) //nolint
		gologger.Info().Msgf("Using custom nmap arguments: %s", strings.Join(filteredArgs, " "))

		// Create nmap scanner
		scanner, err := nmap.NewScanner(context.TODO(), scannerOptions...)
		if err != nil {
			gologger.Error().Msgf("Could not create nmap scanner: %s", err)
			continue
		}

		if outputFile != "" {
			scanner.ToFile(outputFile)
		}

		// Run the scan
		result, warnings, err := scanner.Run()
		if err != nil {
			gologger.Error().Msgf("Could not run nmap scan: %s", err)
			continue
		}

		// Log warnings if any
		if warnings != nil && len(*warnings) > 0 {
			for _, warning := range *warnings {
				gologger.Warning().Msgf("Nmap warning: %s", warning)
			}
		}

		// Process and integrate results back into naabu scan results
		r.integrateNmapResults(result)
	}

	return nil
}

// Helper to convert nmap.Host OS info to our OSFingerprint struct
func nmapOS2Fingerprint(host nmap.Host) *result.OSFingerprint {
	if len(host.OS.Matches) == 0 {
		return nil
	}
	best := host.OS.Matches[0]
	osfp := &result.OSFingerprint{
		Target:     host.Addresses[0].Addr,
		DeviceType: "",
		Running:    best.Name,
		OSCPE:      "",
		OSDetails:  best.Name,
	}
	if len(best.Classes) > 0 {
		osfp.DeviceType = best.Classes[0].Type
		osfp.OSCPE = ""
		if len(best.Classes[0].CPEs) > 0 {
			osfp.OSCPE = string(best.Classes[0].CPEs[0])
		}
		osfp.OSDetails = best.Classes[0].Vendor + " " + best.Classes[0].OSGeneration
	}
	return osfp
}

// integrateNmapResults processes nmap results and integrates them back into naabu scan results
func (r *Runner) integrateNmapResults(nmapResult *nmap.Run) {
	if nmapResult == nil || len(nmapResult.Hosts) == 0 {
		gologger.Info().Msg("No nmap results to integrate")
		return
	}

	for _, host := range nmapResult.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}

		ip := host.Addresses[0].Addr
		gologger.Info().Msgf("Integrating nmap results for %s:", ip)

		osfp := nmapOS2Fingerprint(host)

		for _, nmapPort := range host.Ports {
			if nmapPort.State.State == "open" {
				// Convert nmap port to naabu port with enhanced service information
				naabuPort := r.convertNmapPortToNaabuPort(nmapPort)

				// Update the existing port in scan results with enhanced service information
				r.updatePortWithServiceInfo(ip, naabuPort)

				// Log the enhanced information
				serviceInfo := ""
				if naabuPort.Service != nil && naabuPort.Service.Name != "" {
					serviceInfo = fmt.Sprintf(" (%s", naabuPort.Service.Name)
					if naabuPort.Service.Version != "" {
						serviceInfo += fmt.Sprintf(" %s", naabuPort.Service.Version)
					}
					if naabuPort.Service.Product != "" {
						serviceInfo += fmt.Sprintf(" %s", naabuPort.Service.Product)
					}
					serviceInfo += ")"
				}

				gologger.Silent().Msgf("  %d/%s%s", naabuPort.Port, naabuPort.Protocol, serviceInfo)
			}
		}

		// After updating ports, update the OS info for this host
		r.scanner.ScanResults.UpdateHostOS(ip, osfp)
	}
}

// updatePortWithServiceInfo updates an existing port in scan results with enhanced service information
func (r *Runner) updatePortWithServiceInfo(ip string, enhancedPort *port.Port) {
	// Check if the port already exists in scan results
	if r.scanner.ScanResults.IPHasPort(ip, enhancedPort) {
		// Get all ports for this IP and update the matching one
		for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
			if hostResult.IP == ip {
				for _, existingPort := range hostResult.Ports {
					if existingPort.Port == enhancedPort.Port && existingPort.Protocol == enhancedPort.Protocol {
						// Update the existing port with service information
						if enhancedPort.Service != nil {
							existingPort.Service = enhancedPort.Service
						}
						return
					}
				}
			}
		}
	} else {
		// Port doesn't exist, add it
		r.scanner.ScanResults.AddPort(ip, enhancedPort)
	}
}

// convertNmapPortToNaabuPort converts an nmap port to a naabu port with service information
func (r *Runner) convertNmapPortToNaabuPort(nmapPort nmap.Port) *port.Port {
	// Determine protocol
	var proto protocol.Protocol
	switch nmapPort.Protocol {
	case "tcp":
		proto = protocol.TCP
	case "udp":
		proto = protocol.UDP
	default:
		proto = protocol.TCP // default to TCP
	}

	// Create naabu port
	naabuPort := &port.Port{
		Port:     int(nmapPort.ID), // Convert uint16 to int
		Protocol: proto,
	}

	// Convert service information if available
	if nmapPort.Service.Name != "" {
		cpes := make([]string, 0, len(nmapPort.Service.CPEs))
		for _, cpe := range nmapPort.Service.CPEs {
			cpes = append(cpes, string(cpe))
		}

		naabuPort.Service = &port.Service{
			Name:        nmapPort.Service.Name,
			Product:     nmapPort.Service.Product,
			Version:     nmapPort.Service.Version,
			ExtraInfo:   nmapPort.Service.ExtraInfo,
			Hostname:    nmapPort.Service.Hostname,
			OSType:      nmapPort.Service.OSType,
			DeviceType:  nmapPort.Service.DeviceType,
			Method:      nmapPort.Service.Method,
			Proto:       nmapPort.Service.Proto,
			RPCNum:      nmapPort.Service.RPCNum,
			ServiceFP:   nmapPort.Service.ServiceFP,
			Tunnel:      nmapPort.Service.Tunnel,
			LowVersion:  nmapPort.Service.LowVersion,
			HighVersion: nmapPort.Service.HighVersion,
			CPEs:        cpes,
		}
	}

	return naabuPort
}
