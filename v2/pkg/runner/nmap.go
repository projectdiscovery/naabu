package runner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/projectdiscovery/gologger"
)

func (r *Runner) handleNmap() {
	// command from CLI
	command := r.options.NmapCLI
	hasCLI := r.options.NmapCLI != ""
	// If empty load the one from config file
	if command == "" && r.options.config != nil {
		command = r.options.config.NMapCommand
	}
	// If at least one is defined handle it
	if command != "" {
		args := strings.Split(command, " ")
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

		// if requested via config file or via cli
		if r.options.Nmap || hasCLI {
			gologger.Infof("Running nmap command: %s -p %s %s", command, portsStr, ipsStr)
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Stdout = os.Stdout
			err := cmd.Run()
			if err != nil {
				gologger.Errorf("Could not get network interfaces: %s\n", err)
				return
			}
		} else {
			gologger.Infof("Suggested nmap command: %s -p %s %s", command, portsStr, ipsStr)
		}
	}
}
