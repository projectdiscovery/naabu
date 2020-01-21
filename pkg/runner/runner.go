package runner

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/projectdiscovery/naabu/pkg/scan"
	"github.com/remeh/sizedwaitgroup"
)

// Runner is an instance of the port enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options *Options
	scanner *scan.Scanner

	ports map[int]struct{}
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

	return runner, nil
}

// RunEnumeration runs the ports enumeration flow on the targets specified
func (r *Runner) RunEnumeration() error {
	// Get the ports as specified by the user
	ports, err := ParsePorts(r.options)
	if err != nil {
		return fmt.Errorf("could not parse ports: %s", err)
	}

	// Check if only a single host is sent as input. Process the host now.
	if r.options.Host != "" {
		r.EnumerateSingleHost(r.options.Host, ports, r.options.Output, false)
		return nil
	}

	// If we have multiple hosts as input,
	if r.options.HostsFile != "" {
		f, err := os.Open(r.options.HostsFile)
		if err != nil {
			return err
		}
		r.EnumerateMultipleHosts(f, ports)
		f.Close()
		return nil
	}

	// If we have STDIN input, treat it as multiple hosts
	if r.options.Stdin {
		r.EnumerateMultipleHosts(os.Stdin, ports)
	}
	return nil
}

// EnumerateMultipleHosts enumerates hosts for ports.
// We keep enumerating ports for a given host until we reach an error
func (r *Runner) EnumerateMultipleHosts(reader io.Reader, ports map[int]struct{}) {
	scanner := bufio.NewScanner(reader)
	swg := sizedwaitgroup.New(r.options.Threads)

	for scanner.Scan() {
		host := scanner.Text()
		if host == "" {
			continue
		}

		swg.Add()
		go func(host string) {
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
			swg.Done()
		}(host)
	}
	swg.Wait()

	return
}
