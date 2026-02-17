//go:build windows

package routing

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// New creates a routing engine for windows
func New() (Router, error) {
	var routes []*Route

	for _, iptype := range []RouteType{IPv4, IPv6} {
		netshCmd := exec.Command("netsh", "interface", iptype.String(), "show", "route")
		netshOutput, err := netshCmd.Output()
		if err != nil {
			return nil, err
		}

		scanner := bufio.NewScanner(bytes.NewReader(netshOutput))
		for scanner.Scan() {
			outputLine := strings.TrimSpace(scanner.Text())
			if outputLine == "" {
				continue
			}

			parts := stringsutil.SplitAny(outputLine, " \t")
			if len(parts) >= 6 && govalidator.IsNumeric(parts[4]) {
				prefix := parts[3]
				_, _, err := net.ParseCIDR(prefix)
				if err != nil {
					return nil, err
				}
				gateway := parts[5]
				interfaceIndex, err := strconv.Atoi(parts[4])
				if err != nil {
					return nil, err
				}

				networkInterface, err := net.InterfaceByIndex(interfaceIndex)
				if err != nil {
					return nil, err
				}
				isDefault := stringsutil.EqualFoldAny(prefix, "0.0.0.0/0", "::/0")

				route := &Route{
					Type:             iptype,
					Default:          isDefault,
					Destination:      prefix,
					Gateway:          gateway,
					NetworkInterface: networkInterface,
				}

				routes = append(routes, route)
			}
		}
	}

	return &baseRouter{Routes: routes}, nil
}
