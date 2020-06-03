package runner

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"sync"

	"github.com/projectdiscovery/naabu/pkg/scan"
	"github.com/remeh/sizedwaitgroup"
)

// Runner is an instance of the port enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options *Options
	scanner *scan.Scanner

	ports       map[int]struct{}
	excludedIps map[string]struct{}
	wg          sync.WaitGroup
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists, etc
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

	var err error
	runner.ports, err = ParsePorts(options)
	if err != nil {
		return nil, err
	}

	runner.excludedIps, err = parseExcludedIps(options)
	if err != nil {
		return nil, err
	}

	return runner, nil
}

// RunEnumeration runs the ports enumeration flow on the targets specified
func (r *Runner) RunEnumeration() error {
	// Get the ports as specified by the user
	ports, err := ParsePorts(r.options)
	if err != nil {
		return fmt.Errorf("could not parse ports: %s", err)
	}

	targets := make(chan string)
	// start listener
	r.wg.Add(1)
	go r.EnumerateMultipleHosts(targets, ports)

	// Check if only a single host is sent as input. Process the host now.
	if r.options.Host != "" {
		targets <- r.options.Host
		close(targets)

		r.wg.Wait()
		return nil
	}

	// If we have multiple hosts as input,
	if r.options.HostsFile != "" {
		f, err := os.Open(r.options.HostsFile)
		if err != nil {
			return err
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			targets <- scanner.Text()
		}

		close(targets)

		r.wg.Wait()
		return nil
	}

	// If we have STDIN input, treat it as multiple hosts
	if r.options.Stdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			targets <- scanner.Text()
		}

		close(targets)

		r.wg.Wait()
	}
	return nil
}

// EnumerateMultipleHosts enumerates hosts for ports.
// We keep enumerating ports for a given host until we reach an error
func (r *Runner) EnumerateMultipleHosts(targets chan string, ports map[int]struct{}) {
	defer r.wg.Done()

	swg := sizedwaitgroup.New(r.options.Threads)

	for host := range targets {
		if host == "" {
			continue
		}

		// Check if the host is a cidr
		if scan.IsCidr(host) {
			ips, err := scan.Ips(host)
			if err != nil {
				return
			}

			for _, ip := range ips {
				swg.Add()
				go r.handleHost(&swg, ip, ports)
			}

		} else {
			swg.Add()
			go r.handleHost(&swg, host, ports)
		}
	}

	swg.Wait()
}

func (r *Runner) handleHost(swg *sizedwaitgroup.SizedWaitGroup, host string, ports map[int]struct{}) {
	defer swg.Done()

	// If the user has specifed an output file, use that output file instead
	// of creating a new output file for each domain. Else create a new file
	// for each domain in the directory.
	if r.options.Output != "" {
		r.EnumerateSingleHost(host, ports, r.options.Output, true)
	} else if r.options.OutputDirectory != "" {
		outputFile := path.Join(r.options.OutputDirectory, host)
		r.EnumerateSingleHost(host, ports, outputFile, false)
	} else {
		r.EnumerateSingleHost(host, ports, "", true)
	}
}
