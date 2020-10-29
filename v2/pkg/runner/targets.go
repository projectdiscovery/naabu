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
	"github.com/projectdiscovery/naabu/v2/pkg/ipranger"
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
		gologger.Warningf("%s\n", err)
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
	if r.options.Host != "" {
		fmt.Fprintf(tempInput, "%s\n", r.options.Host)
		if _, err := tempInput.WriteString(r.options.Host + "\n"); err != nil {
			gologger.Warningf("%s\n", err)
		}
		err := r.AddTarget(r.options.Host)
		if err != nil {
			return "", err
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

	// handles targets from config file if provided
	if r.options.config != nil {
		for _, target := range r.options.config.Host {
			fmt.Fprintf(tempInput, "%s\n", target)
		}
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
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		wg.Add()
		func(target string) {
			defer wg.Done()
			if err := r.AddTarget(target); err != nil {
				gologger.Warningf("%s\n", err)
			}
		}(s.Text())
	}

	wg.Wait()
	return nil
}

func (r *Runner) AddTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	} else if ipranger.IsCidr(target) {
		// Add cidr directly to ranger, as single ips would allocate more resources later
		if err := r.scanner.IPRanger.AddFqdn(target, "cidr"); err != nil {
			gologger.Warningf("%s\n", err)
		}
	} else if ipranger.IsIP(target) && !r.scanner.IPRanger.Contains(target) {
		if err := r.scanner.IPRanger.AddFqdn(target, "ip"); err != nil {
			gologger.Warningf("%s\n", err)
		}
	} else {
		ip, err := r.resolveFQDN(target)
		if err != nil {
			return err
		}
		if err := r.scanner.IPRanger.AddFqdn(ip, target); err != nil {
			gologger.Warningf("%s\n", err)
		}
	}

	return nil
}

func (r *Runner) resolveFQDN(target string) (string, error) {
	ips, err := r.host2ips(target)
	if err != nil {
		return "", err
	}

	var (
		initialHosts []string
		hostIP       string
	)
	for _, ip := range ips {
		if r.scanner.IPRanger.IsExcluded(ip) {
			gologger.Warningf("Skipping host %s as ip %s was excluded\n", target, ip)
			continue
		}

		initialHosts = append(initialHosts, ip)
	}

	if len(initialHosts) == 0 {
		return "", nil
	}

	// If the user has specified ping probes, perform ping on addresses
	if isRoot() && r.options.Ping && len(initialHosts) > 1 {
		// Scan the hosts found for ping probes
		pingResults, err := scan.PingHosts(initialHosts)
		if err != nil {
			gologger.Warningf("Could not perform ping scan on %s: %s\n", target, err)
			return "", err
		}
		for _, result := range pingResults.Hosts {
			if result.Type == scan.HostActive {
				gologger.Debugf("Ping probe succeed for %s: latency=%s\n", result.Host, result.Latency)
			} else {
				gologger.Debugf("Ping probe failed for %s: error=%s\n", result.Host, result.Error)
			}
		}

		// Get the fastest host in the list of hosts
		fastestHost, err := pingResults.GetFastestHost()
		if err != nil {
			gologger.Warningf("No active host found for %s: %s\n", target, err)
			return "", err
		}
		gologger.Infof("Fastest host found for target: %s (%s)\n", fastestHost.Host, fastestHost.Latency)
		hostIP = fastestHost.Host
	} else {
		hostIP = initialHosts[0]
		gologger.Debugf("Using host %s for enumeration\n", hostIP)
	}

	// dedupe all the hosts and also keep track of ip => host for the output - just append new hostname
	if err := r.scanner.IPRanger.AddFqdn(hostIP, target); err != nil {
		gologger.Warningf("%s\n", err)
	}

	if err := r.scanner.IPRanger.Add(hostIP); err != nil {
		gologger.Warningf("%s\n", err)
	}

	return hostIP, nil
}
