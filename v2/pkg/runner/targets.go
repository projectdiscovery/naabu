package runner

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/remeh/sizedwaitgroup"
)

func (r *Runner) Load() error {
	r.scanner.State = scan.Init

	// merge all target sources into a file
	targetfile, err := r.mergeToFile()
	if err != nil {
		return err
	}
	r.targetsFile = targetfile

	// pre-process all targets (resolves all non fqdn targets to ip address)
	err = r.PreProcessTargets()
	if err != nil {
		gologger.Warning().Msgf("%s\n", err)
	}

	return nil
}

func (r *Runner) mergeToFile() (string, error) {
	// merge all targets in a unique file
	tempInput, err := ioutil.TempFile("", "stdin-input-*")
	if err != nil {
		return "", err
	}
	defer tempInput.Close()

	// target defined via CLI argument
	if len(r.options.Host) > 0 {
		for _, v := range r.options.Host {
			fmt.Fprintf(tempInput, "%s\n", v)
		}
	}

	// Targets from file
	if r.options.HostsFile != "" {
		f, err := os.Open(r.options.HostsFile)
		if err != nil {
			return "", err
		}
		defer f.Close()
		if _, err := io.Copy(tempInput, f); err != nil {
			return "", err
		}
	}

	// targets from STDIN
	if r.options.Stdin {
		if _, err := io.Copy(tempInput, os.Stdin); err != nil {
			return "", err
		}
	}

	// all additional non-named cli arguments are interpreted as targets
	for _, target := range flag.Args() {
		fmt.Fprintf(tempInput, "%s\n", target)
	}

	filename := tempInput.Name()
	return filename, nil
}

func (r *Runner) PreProcessTargets() error {
	wg := sizedwaitgroup.New(r.options.Threads)
	f, err := os.Open(r.targetsFile)
	if err != nil {
		return err
	}
	s := bufio.NewScanner(f)
	if r.options.Stream {
		go func() {
			defer f.Close()
			defer close(r.streamChannel)
			for s.Scan() {
				func(target string) {
					if err := r.AddTarget(target); err != nil {
						gologger.Warning().Msgf("%s\n", err)
					}
				}(s.Text())
			}
		}()

	} else {
		defer f.Close()
		for s.Scan() {
			wg.Add()
			func(target string) {
				defer wg.Done()
				if err := r.AddTarget(target); err != nil {
					gologger.Warning().Msgf("%s\n", err)
				}
			}(s.Text())
		}
		wg.Wait()
	}
	return nil
}

func (r *Runner) AddTarget(target string) error {
	target = strings.TrimSpace(target)
	invokeStreamChannel := func(ip string) {
		if r.options.Stream {
			r.streamChannel <- ipranger.ToCidr(ip)
		}
	}
	if target == "" {
		return nil
	} else if ipranger.IsCidr(target) {
		invokeStreamChannel(target)
		// Add cidr directly to ranger, as single ips would allocate more resources later
		if err := r.scanner.IPRanger.AddHostWithMetadata(target, "cidr"); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	} else if ipranger.IsIP(target) && !r.scanner.IPRanger.Contains(target) {
		invokeStreamChannel(target)
		if err := r.scanner.IPRanger.AddHostWithMetadata(target, "ip"); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	} else {
		ips, err := r.resolveFQDN(target)
		if err != nil {
			return err
		}
		for _, ip := range ips {
			invokeStreamChannel(ip)
			if err := r.scanner.IPRanger.AddHostWithMetadata(ip, target); err != nil {
				gologger.Warning().Msgf("%s\n", err)
			}
		}
	}

	return nil
}

func (r *Runner) resolveFQDN(target string) ([]string, error) {
	ips, err := r.host2ips(target)
	if err != nil {
		return []string{}, err
	}

	var (
		initialHosts []string
		hostIPS      []string
	)
	for _, ip := range ips {
		if !r.scanner.IPRanger.Np.ValidateAddress(ip) {
			gologger.Warning().Msgf("Skipping host %s as ip %s was excluded\n", target, ip)
			continue
		}

		initialHosts = append(initialHosts, ip)
	}

	if len(initialHosts) == 0 {
		return []string{}, nil
	}

	// If the user has specified ping probes, perform ping on addresses
	if privileges.IsPrivileged && r.options.Ping && len(initialHosts) > 1 {
		// Scan the hosts found for ping probes
		pingResults, err := scan.PingHosts(initialHosts)
		if err != nil {
			gologger.Warning().Msgf("Could not perform ping scan on %s: %s\n", target, err)
			return []string{}, err
		}
		for _, result := range pingResults.Hosts {
			if result.Type == scan.HostActive {
				gologger.Debug().Msgf("Ping probe succeed for %s: latency=%s\n", result.Host, result.Latency)
			} else {
				gologger.Debug().Msgf("Ping probe failed for %s: error=%s\n", result.Host, result.Error)
			}
		}

		// Get the fastest host in the list of hosts
		fastestHost, err := pingResults.GetFastestHost()
		if err != nil {
			gologger.Warning().Msgf("No active host found for %s: %s\n", target, err)
			return []string{}, err
		}
		gologger.Info().Msgf("Fastest host found for target: %s (%s)\n", fastestHost.Host, fastestHost.Latency)
		hostIPS = append(hostIPS, fastestHost.Host)
	} else if r.options.ScanAllIPS {
		hostIPS = initialHosts
	} else {
		hostIPS = append(hostIPS, initialHosts[0])
	}

	for _, hostIP := range hostIPS {
		gologger.Debug().Msgf("Using host %s for enumeration\n", hostIP)
		// dedupe all the hosts and also keep track of ip => host for the output - just append new hostname
		if err := r.scanner.IPRanger.AddHostWithMetadata(hostIP, target); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	}

	return hostIPS, nil
}
