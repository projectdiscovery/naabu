package runner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
)

func (r *Runner) handleNmap() error {
	// command from CLI
	command := r.options.NmapCLI
	hasCLI := r.options.NmapCLI != ""
	// If at least one is defined handle it
	if command != "" {
		args := strings.Split(command, " ")
		var (
			ips   []string
			ports []string
		)
		allports := make(map[int]struct{})
		for ip, p := range r.scanner.ScanResults.IPPorts {
			ips = append(ips, ip)
			for pp := range p {
				allports[pp] = struct{}{}
			}
		}
		for p := range allports {
			ports = append(ports, fmt.Sprintf("%d", p))
		}

		// if we have no open ports we avoid running nmap
		if len(ports) == 0 {
			errMsg := errors.New("Skipping nmap scan as no open ports were found")
			gologger.Info().Msgf(errMsg.Error())
			return errMsg
		}

		portsStr := strings.Join(ports, ",")
		ipsStr := strings.Join(ips, ",")

		args = append(args, "-p", portsStr)
		args = append(args, ips...)

		// if requested via config file or via cli
		if r.options.Nmap || hasCLI {
			gologger.Info().Msgf("Running nmap command: %s -p %s %s", command, portsStr, ipsStr)
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Stdout = os.Stdout
			err := cmd.Run()
			if err != nil {
				errMsg := errors.Wrap(err, "Could not run nmap command")
				gologger.Error().Msgf(errMsg.Error())
				return errMsg
			}
		} else {
			gologger.Info().Msgf("Suggested nmap command: %s -p %s %s", command, portsStr, ipsStr)
		}
	}

	return nil
}
