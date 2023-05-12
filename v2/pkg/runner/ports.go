package runner

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

const portListStrParts = 2

// List of default ports
const (
	Full = "1-65535"
)

// ParsePorts parses the list of ports and creates a port map
func ParsePorts(options *Options) ([]*port.Port, error) {
	var portsFileMap, portsCLIMap, topPortsCLIMap, portsConfigList []*port.Port

	// If the user has specfied a ports file, use it
	if options.PortsFile != "" {
		data, err := os.ReadFile(options.PortsFile)
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
		ports, err := parsePortsList(string(data))
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
		portsFileMap, err = excludePorts(options, ports)
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
	}

	// If the user has specfied top ports, use them as well
	topPorts := strings.ToLower(options.TopPorts)
	if topPorts == "full" {
		var err error
		ports, err := parsePortsList(Full)
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
		topPortsCLIMap, err = excludePorts(options, ports)
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
	} else if topPorts != "" {
		portsAmount, err := strconv.ParseInt(topPorts, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid top ports option: %s", err)
		}
		if portsAmount > int64(len(port.TopTcpPorts)) {
			return nil, fmt.Errorf("not enough ports")
		}
		topPortsCLIMap, err = excludePorts(options, port.TopTcpPorts[:portsAmount])
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
	}

	// If the user has specfied ports option, use them too
	if options.Ports != "" {
		// "-" equals to all ports
		if options.Ports == "-" {
			// Parse the custom ports list provided by the user
			options.Ports = "1-65535"
		}
		ports, err := parsePortsList(options.Ports)
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
		portsCLIMap, err = excludePorts(options, ports)
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
	}

	// merge all the specified ports (meaningless if "all" is used)
	ports := merge(portsFileMap, portsCLIMap, topPortsCLIMap, portsConfigList)

	// default to scan top 100 ports only
	if len(ports) == 0 {
		portsList := port.TopTcpPorts[:100]
		m, err := excludePorts(options, portsList)
		if err != nil {
			return nil, err
		}
		return m, nil
	}

	return ports, nil
}

// excludePorts excludes the list of ports from the exclusion list
func excludePorts(options *Options, ports []*port.Port) ([]*port.Port, error) {
	if options.ExcludePorts == "" {
		return ports, nil
	}

	var filteredPorts []*port.Port

	// Exclude the ports specified by the user in exclusion list
	excludedPortsCLI, err := parsePortsList(options.ExcludePorts)
	if err != nil {
		return nil, fmt.Errorf("could not read exclusion ports: %s", err)
	}

	for _, p := range ports {
		found := false
		for _, excludedPort := range excludedPortsCLI {
			if excludedPort.Port == p.Port && excludedPort.Protocol == p.Protocol {
				found = true
				break
			}
		}
		if !found {
			filteredPorts = append(filteredPorts, p)
		}
	}
	return filteredPorts, nil
}

func parsePortsSlice(ranges []string) ([]*port.Port, error) {
	var ports []*port.Port
	for _, r := range ranges {
		r = strings.TrimSpace(r)

		portProtocol := protocol.TCP
		if strings.HasPrefix(r, "u:") {
			portProtocol = protocol.UDP
			r = strings.TrimPrefix(r, "u:")
		}

		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != portListStrParts {
				return nil, fmt.Errorf("invalid port selection segment: '%s'", r)
			}

			p1, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", parts[0])
			}

			p2, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", parts[1])
			}

			if p1 > p2 {
				return nil, fmt.Errorf("invalid port range: %d-%d", p1, p2)
			}

			for i := p1; i <= p2; i++ {
				p := &port.Port{Port: i, Protocol: portProtocol}
				ports = append(ports, p)
			}
		} else {
			portNumber, err := strconv.Atoi(r)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", r)
			}
			p := &port.Port{Port: portNumber, Protocol: portProtocol}
			ports = append(ports, p)
		}
	}

	// dedupe ports
	seen := make(map[string]struct{})
	var dedupedPorts []*port.Port
	for _, p := range ports {
		if _, ok := seen[p.String()]; ok {
			continue
		}
		seen[p.String()] = struct{}{}
		dedupedPorts = append(dedupedPorts, p)
	}

	return dedupedPorts, nil
}

func parsePortsList(data string) ([]*port.Port, error) {
	return parsePortsSlice(strings.Split(data, ","))
}

func merge(slices ...[]*port.Port) []*port.Port {
	var result []*port.Port
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return result
}
