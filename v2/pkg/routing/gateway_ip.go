package routing

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"time"
)

var (
	GatewayMac = make(map[string]net.HardwareAddr)
)

func GetGatewayMac(gateway string) (net.HardwareAddr, error) {
	if IP, ok := GatewayMac[gateway]; ok {
		return IP, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "arp", "-n", gateway)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Fields(string(output)) {
		mc, err := net.ParseMAC(part)
		if err != nil {
			continue
		}

		GatewayMac[gateway] = mc
		return mc, nil
	}

	return nil, errors.New("gateway mac not found")
}
