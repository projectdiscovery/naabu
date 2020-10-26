package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/yl2chen/cidranger"
	"go.uber.org/ratelimit"
)

// Runner is an instance of the port enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options *Options
	scanner *scan.Scanner
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists, etc
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

	scanner, err := scan.NewScanner(&scan.Options{
		Timeout: time.Duration(options.Timeout) * time.Millisecond,
		Retries: options.Retries,
		Rate:    options.Rate,
		Debug:   options.Debug,
		Root:    isRoot(),
		Cdn:     !options.ExcludeCDN,
	})
	if err != nil {
		return nil, err
	}
	runner.scanner = scanner

	runner.scanner.Ports, err = ParsePorts(options)
	if err != nil {
		return nil, fmt.Errorf("could not parse ports: %s", err)
	}

	err = runner.parseProbesPorts(options)
	if err != nil {
		return nil, fmt.Errorf("could not parse probes: %s", err)
	}

	runner.scanner.ExcludedIps, err = parseExcludedIps(options)
	if err != nil {
		return nil, err
	}

	runner.scanner.Targets, err = hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}

	runner.scanner.TargetsIps = cidranger.NewPCTrieRanger()

	return runner, nil
}

func (r *Runner) SetSourceIPAndInterface() error {
	if r.options.SourceIP != "" && r.options.Interface != "" {
		r.scanner.SourceIP = net.ParseIP(r.options.SourceIP)
		var err error
		r.scanner.NetworkInterface, err = net.InterfaceByName(r.options.Interface)
		if err != nil {
			return err
		}
	}

	return fmt.Errorf("source Ip and Interface not specified")
}

// RunEnumeration runs the ports enumeration flow on the targets specified
func (r *Runner) RunEnumeration() error {
	err := r.Load()
	if err != nil {
		return err
	}

	if !isRoot() {
		// Connect Scan - perform ports spray scan
		r.ConnectEnumeration()
		r.scanner.State = scan.Done
	} else {
		r.BackgroundWorkers()

		if err := r.SetSourceIPAndInterface(); err != nil {
			tuneSourceErr := r.scanner.TuneSource(ExternalTargetForTune)
			if tuneSourceErr != nil {
				return tuneSourceErr
			}
		}

		r.scanner.State = scan.Probe
		r.ProbeOrSkip()

		if r.options.WarmUpTime > 0 {
			time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
		}

		r.scanner.State = scan.Guard

		// update targets
		if len(r.scanner.ProbeResults.M) > 0 {
			r.scanner.Targets.Scan(func(ip, _ []byte) error {
				if _, ok := r.scanner.ProbeResults.M[string(ip)]; !ok {
					// TODO: just temporary
					r.scanner.Targets.Del(string(ip))
				}
				return nil
			})
		}

		r.scanner.State = scan.Scan

		// Syn Scan - Perform scan with raw sockets
		r.RawSocketEnumeration()

		if r.options.WarmUpTime > 0 {
			time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
		}

		r.scanner.State = scan.Done

		// Validate the hosts if the user has asked for second step validation
		if r.options.Verify {
			r.ConnectVerification()
		}
	}

	r.handleOutput()

	// handle nmap
	r.handleNmap()

	return nil
}

func (r *Runner) ConnectVerification() {
	r.scanner.State = scan.Scan
	var swg sync.WaitGroup
	limiter := ratelimit.New(r.options.Rate)

	for host, ports := range r.scanner.ScanResults.M {
		limiter.Take()
		swg.Add(1)
		go func(host string, ports map[int]struct{}) {
			defer swg.Done()
			results := r.scanner.ConnectVerify(host, ports)
			r.scanner.ScanResults.SetPorts(host, results)
		}(host, ports)
	}

	swg.Wait()
}

func (r *Runner) BackgroundWorkers() {
	r.scanner.StartWorkers()
}

func (r *Runner) RawSocketEnumeration() {
	limiter := ratelimit.New(r.options.Rate)

	for retry := 0; retry < r.options.Retries; retry++ {
		for port := range r.scanner.Ports {
			r.scanner.Targets.Scan(func(target, _ []byte) error {
				limiter.Take()
				r.handleHostPortSyn(string(target), port)
				return nil
			})
		}
	}
}

func (r *Runner) ConnectEnumeration() {
	r.scanner.State = scan.Scan
	// naive algorithm - ports spray
	var swg sync.WaitGroup
	limiter := ratelimit.New(r.options.Rate)

	for retry := 0; retry < r.options.Retries; retry++ {
		for port := range r.scanner.Ports {
			r.scanner.Targets.Scan(func(target, _ []byte) error {
				limiter.Take()
				swg.Add(1)
				go r.handleHostPort(&swg, string(target), port)
				return nil
			})
		}
	}

	swg.Wait()
}

// check if an ip can be scanned in case CDN exclusions are enabled
func (r *Runner) canIScanIfCDN(host string, port int) bool {
	// if CDN ips are not excluded all scans are allowed
	if !r.options.ExcludeCDN {
		return true
	}

	// if exclusion is enabled, but the ip is not part of the CDN ips range we can scan
	if ok, err := r.scanner.CdnCheck(host); err == nil && !ok {
		return true
	}

	// If the cdn is part of the CDN ips range - only ports 80 and 443 are allowed
	return port == 80 || port == 443
}

func (r *Runner) handleHostPort(swg *sync.WaitGroup, host string, port int) {
	defer swg.Done()

	// performs cdn scan exclusions checks
	if !r.canIScanIfCDN(host, port) {
		gologger.Debugf("Skipping cdn target: %s:%d\n", host, port)
		return
	}

	if r.scanner.ScanResults.Has(host, port) {
		return
	}

	open, err := scan.ConnectPort(host, port, time.Duration(r.options.Timeout)*time.Millisecond)
	if open && err == nil {
		r.scanner.ScanResults.AddPort(host, port)
	}
}

func (r *Runner) handleHostPortSyn(host string, port int) {
	// performs cdn scan exclusions checks
	if !r.canIScanIfCDN(host, port) {
		gologger.Debugf("Skipping cdn target: %s:%d\n", host, port)
		return
	}

	r.scanner.EnqueueTCP(host, port, scan.SYN)
}

func (r *Runner) handleOutput() {
	var (
		file   *os.File
		err    error
		output string
	)
	// In case the user has given an output file, write all the found
	// ports to the output file.
	if r.options.Output != "" {
		output = r.options.Output
		// If the output format is json, append .json
		// else append .txt
		if r.options.JSON && !strings.HasSuffix(output, ".json") {
			output += ".json"
		}

		// create path if not existing
		outputFolder := filepath.Dir(output)
		if _, statErr := os.Stat(outputFolder); os.IsNotExist(statErr) {
			mkdirErr := os.MkdirAll(outputFolder, 0700)
			if mkdirErr != nil {
				gologger.Errorf("Could not create output folder %s: %s\n", outputFolder, mkdirErr)
				return
			}
		}

		file, err = os.Create(output)
		if err != nil {
			gologger.Errorf("Could not create file %s: %s\n", output, err)
			return
		}
		defer file.Close()
	}

	for hostIP, ports := range r.scanner.ScanResults.M {
		dt, ok := r.scanner.Targets.Get(hostIP)
		if !ok {
			continue
		}

		for _, host := range bytes.Split(dt, []byte(",")) {
			hostStr := string(host)
			gologger.Infof("Found %d ports on host %s (%s)\n", len(ports), hostStr, hostIP)

			// console output
			if r.options.JSON {
				data := JSONResult{IP: hostIP}
				if hostStr != hostIP {
					data.Host = hostStr
				}
				for port := range ports {
					data.Port = port
					b, marshallErr := json.Marshal(data)
					if marshallErr != nil {
						continue
					}
					gologger.Silentf("%s\n", string(b))
				}
			} else {
				for port := range ports {
					gologger.Silentf("%s:%d\n", hostStr, port)
				}
			}

			// file output
			if file != nil {
				if r.options.JSON {
					err = WriteJSONOutput(hostStr, hostIP, ports, file)
				} else {
					err = WriteHostOutput(hostStr, ports, file)
				}
				if err != nil {
					gologger.Errorf("Could not write results to file %s for %s: %s\n", output, hostStr, err)
				}
			}
		}
	}
}
