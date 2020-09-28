package runner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/projectdiscovery/gologger"
)

func (r *Runner) handleNmap() {
	if r.options.config != nil && r.options.config.NMapCommand != "" {
		args := strings.Split(r.options.config.NMapCommand, " ")
		var (
			ips   []string
			ports []string
		)
		allports := make(map[int]struct{})
		for ip, p := range r.scanner.ScanResults.M {
			ips = append(ips, ip)
			for pp := range p {
				allports[pp] = struct{}{}
			}
		}
		for p := range allports {
			ports = append(ports, fmt.Sprintf("%d", p))
		}

		portsStr := strings.Join(ports, ",")
		ipsStr := strings.Join(ips, ",")

		args = append(args, "-p", portsStr)
		args = append(args, ips...)

		if r.options.Nmap {
			gologger.Infof("Running nmap command: %s -p %s %s", r.options.config.NMapCommand, portsStr, ipsStr)
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Stdout = os.Stdout
			err := cmd.Run()
			if err != nil {
				gologger.Errorf("Could not get network interfaces: %s\n", err)
				return
			}
		} else {
			gologger.Infof("Suggested nmap command: %s -p %s %s", r.options.config.NMapCommand, portsStr, ipsStr)
		}
	}
}
