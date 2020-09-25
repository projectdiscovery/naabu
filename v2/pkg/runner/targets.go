package runner

import (
	"bufio"
	"errors"
	"flag"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
)

func (r *Runner) Load() error {
	r.scanner.State = scan.Init
	// target defined via CLI argument
	if r.options.Host != "" {
		err := r.AddTarget(r.options.Host)
		if err != nil {
			return err
		}
	}

	// Targets from file
	if r.options.HostsFile != "" {
		f, err := os.Open(r.options.HostsFile)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			err := r.AddTarget(scanner.Text())
			if err != nil {
				f.Close()
				return err
			}
		}
		f.Close()
	}

	// targets from STDIN
	if r.options.Stdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			err := r.AddTarget(scanner.Text())
			if err != nil {
				return err
			}
		}
	}

	// all additional non-named cli arguments are interpreted as targets
	for _, target := range flag.Args() {
		err := r.AddTarget(target)
		if err != nil {
			return err
		}
	}

	// handles targets from config file if provided
	if r.options.config != nil {
		for _, target := range r.options.config.Host {
			err := r.AddTarget(target)
			if err != nil {
				return err
			}
		}
	}

	if len(r.scanner.Targets) == 0 {
		return errors.New("no targets specified")
	}

	return nil
}

func (r *Runner) AddTarget(target string) error {
	if target == "" {
		return nil
	}
	if scan.IsCidr(target) {
		ips, err := scan.Ips(target)
		if err != nil {
			return err
		}
		for _, ip := range ips {
			err := r.addOrExpand(ip)
			if err != nil {
				return err
			}
		}
		return nil
	}
	err := r.addOrExpand(target)
	if err != nil {
		return err
	}

	return nil
}

func (r *Runner) addOrExpand(target string) error {
	ips, err := r.host2ips(target)
	if err != nil {
		return err
	}

	var (
		initialHosts []string
		hostIP       string
	)
	for _, ip := range ips {
		_, toExclude := r.scanner.ExcludedIps[ip]
		if toExclude {
			gologger.Warningf("Skipping host %s as ip %s was excluded\n", target, ip)
			continue
		}

		initialHosts = append(initialHosts, ip)
	}

	if len(initialHosts) == 0 {
		return nil
	}

	// If the user has specified ping probes, perform ping on addresses
	if isRoot() && r.options.Ping && len(initialHosts) > 1 {
		// Scan the hosts found for ping probes
		pingResults, err := scan.PingHosts(initialHosts)
		if err != nil {
			gologger.Warningf("Could not perform ping scan on %s: %s\n", target, err)
			return err
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
			return err
		}
		gologger.Infof("Fastest host found for target: %s (%s)\n", fastestHost.Host, fastestHost.Latency)
		hostIP = fastestHost.Host
	} else {
		hostIP = initialHosts[0]
		gologger.Debugf("Using host %s for enumeration\n", hostIP)
	}

	// we also keep track of ip => host for the output
	if _, ok := r.scanner.Targets[hostIP]; !ok {
		r.scanner.Targets[hostIP] = make(map[string]struct{})
	}
	r.scanner.Targets[hostIP][target] = struct{}{}

	return nil
}
