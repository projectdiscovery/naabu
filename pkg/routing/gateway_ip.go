package routing

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var (
	GatewayMac = make(map[string]net.HardwareAddr)
)

func GetGatewayMac(gateway string) (net.HardwareAddr, error) {
	if gateway == "" {
		return nil, errors.New("gateway mac not found")
	}
	if IP, ok := GatewayMac[gateway]; ok {
		return IP, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// Windows arp has no -n; -a dumps the table (optionally filtered by IP).
		cmd = exec.CommandContext(ctx, "arp", "-a", gateway)
	} else {
		cmd = exec.CommandContext(ctx, "arp", "-n", gateway)
	}
	output, err := cmd.CombinedOutput()
	if err != nil && runtime.GOOS != "windows" {
		return nil, err
	}

	mac, parseErr := parseARPHardwareAddr(gateway, string(output))
	if parseErr != nil {
		// Some Windows builds ignore the IP filter; fall back to the full table.
		if runtime.GOOS == "windows" {
			fbCtx, fbCancel := context.WithTimeout(context.Background(), 3*time.Second)
			cmd = exec.CommandContext(fbCtx, "arp", "-a")
			fullOut, fullErr := cmd.CombinedOutput()
			fbCancel()
			if fullErr == nil {
				mac, parseErr = parseARPHardwareAddr(gateway, string(fullOut))
			}
		}
		if parseErr != nil {
			if err != nil {
				return nil, err
			}
			return nil, parseErr
		}
	}

	GatewayMac[gateway] = mac
	return mac, nil
}

// parseARPHardwareAddr extracts the MAC for ip from arp command output.
// Supports Linux `arp -n`, macOS `arp -n`, and Windows `arp -a` formats.
func parseARPHardwareAddr(ip, output string) (net.HardwareAddr, error) {
	target := net.ParseIP(ip)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if target != nil {
			// Match the IP as a whole field so 192.168.1.1 does not hit 192.168.1.10.
			hasIP := false
			for _, f := range fields {
				f = strings.Trim(f, "[](),")
				if f == ip || (target.To4() != nil && f == target.String()) {
					hasIP = true
					break
				}
			}
			if !hasIP {
				continue
			}
		}
		for _, part := range fields {
			part = strings.Trim(part, "[](),")
			mc, err := net.ParseMAC(part)
			if err != nil {
				continue
			}
			return mc, nil
		}
	}
	return nil, errors.New("gateway mac not found")
}
