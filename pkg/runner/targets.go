package runner

import (
	"bufio"
	"errors"
	"os"

	"github.com/projectdiscovery/naabu/pkg/scan"
)

func (r *Runner) Load() error {
	r.scanner.State = scan.Init
	// target defined via CLI argument
	if r.options.Host != "" {
		r.scanner.Targets[r.options.Host] = struct{}{}
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

	for _, ip := range ips {
		_, toExclude := r.scanner.ExcludedIps[ip]
		if toExclude {
			continue
		}

		r.scanner.Targets[ip] = struct{}{}
	}

	return nil
}
