package runner

import (
	"bufio"
	"errors"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/pkg/scan"
)

func (r *Runner) Load() error {
	r.scanner.State = scan.Init
	// target defined via CLI argument
	if r.options.Host != "" {
		r.AddTarget(r.options.Host)
	}

	// Targets from file
	if r.options.HostsFile != "" {
		f, err := os.Open(r.options.HostsFile)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			r.AddTarget(scanner.Text())
		}
		f.Close()
	}

	// targets from STDIN
	if r.options.Stdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			r.AddTarget(scanner.Text())
		}
	}

	if len(r.scanner.Targets) == 0 {
		return errors.New("No targets specified")
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
			r.addOrExpand(ip)
		}
		return nil
	}
	r.addOrExpand(target)
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

	// If the user has specified ping probes, perform ping on addresses
	if r.options.Ping && len(initialHosts) > 1 {
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
		gologger.Infof("Using host %s for enumeration\n", target)
	}

	// we also keep track of ip => host for the output
	if _, ok := r.scanner.Targets[hostIP]; !ok {
		r.scanner.Targets[hostIP] = make(map[string]struct{})
	}
	r.scanner.Targets[hostIP][target] = struct{}{}

	return nil
}
