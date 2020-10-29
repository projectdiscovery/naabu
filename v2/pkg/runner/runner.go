package runner

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	dnsprobe "github.com/projectdiscovery/dnsprobe/lib"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/naabu/v2/pkg/ipranger"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/ratelimit"
)

const (
	DNSQueryTypeA = "A"
)

// Runner is an instance of the port enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options     *Options
	targetsFile string
	scanner     *scan.Scanner
	limiter     ratelimit.Limiter
	wgscan      sizedwaitgroup.SizedWaitGroup
	dnsprobe    *dnsprobe.DnsProbe
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

	err = parseExcludedIps(options, scanner)
	if err != nil {
		return nil, err
	}

	dnsOptions := dnsprobe.DefaultOptions
	dnsOptions.MaxRetries = runner.options.Retries
	dnsOptions.QuestionType, err = dnsprobe.StringToRequestType(DNSQueryTypeA)
	if err != nil {
		return nil, err
	}
	dnsProbe, err := dnsprobe.New(dnsOptions)
	if err != nil {
		return nil, err
	}
	runner.dnsprobe = dnsProbe

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

	// Scan workers
	r.wgscan = sizedwaitgroup.New(r.options.Rate)
	r.limiter = ratelimit.New(r.options.Rate)

	if isRoot() {
		if err := r.SetSourceIPAndInterface(); err != nil {
			tuneSourceErr := r.scanner.TuneSource(ExternalTargetForTune)
			if tuneSourceErr != nil {
				return tuneSourceErr
			}
		}
		r.BackgroundWorkers()
	}

	// shrinks the ips to the minimum amount of cidr
	var targets []*net.IPNet
	r.scanner.IPRanger.Targets.Scan(func(k, v []byte) error {
		targets = append(targets, ipranger.ToCidr(string(k)))
		return nil
	})
	targets, _ = mapcidr.CoalesceCIDRs(targets)
	// add targets to ranger
	for _, target := range targets {
		err := r.scanner.IPRanger.AddIPNet(target)
		if err != nil {
			gologger.Warningf("%s\n", err)
		}
	}

	r.scanner.State = scan.Scan

	targetsCount := int64(r.scanner.IPRanger.CountIPS())
	portsCount := int64(len(r.scanner.Ports))
	Range := targetsCount * portsCount
	b := ipranger.NewBlackRock(Range, 43)
	for index := int64(0); index < Range; index++ {
		xxx := b.Shuffle(index)
		ipIndex := xxx / portsCount
		portIndex := int(xxx % portsCount)
		ip := r.PickIP(targets, ipIndex)
		port := r.PickPort(portIndex)

		if ip == "" || port <= 0 {
			continue
		}

		r.limiter.Take()
		// connect scan
		if !isRoot() {
			r.wgscan.Add()
			go r.handleHostPort(ip, port)
		} else {
			r.RawSocketEnumeration(ip, port)
		}
	}

	r.wgscan.Wait()

	if r.options.WarmUpTime > 0 {
		time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
	}

	r.scanner.State = scan.Done

	// Validate the hosts if the user has asked for second step validation
	if r.options.Verify {
		r.ConnectVerification()
	}

	r.handleOutput()

	// handle nmap
	r.handleNmap()

	return nil
}

func (r *Runner) Close() {
	os.RemoveAll(r.targetsFile)
	r.scanner.IPRanger.Targets.Close()
}

func (r *Runner) PickIP(targets []*net.IPNet, index int64) string {
	for _, target := range targets {
		subnetIpsCount := int64(mapcidr.AddressCountIpnet(target))
		if index < subnetIpsCount {
			return r.PickSubnetIP(target, index)
		}
		index -= subnetIpsCount
	}

	return ""
}

func (r *Runner) PickSubnetIP(network *net.IPNet, index int64) string {
	return mapcidr.Inet_ntoa(mapcidr.Inet_aton(network.IP) + index).String()
}

func (r *Runner) PickPort(index int) int {
	return r.scanner.Ports[index]
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

func (r *Runner) RawSocketEnumeration(ip string, port int) {
	// skip invalid combinations
	r.handleHostPortSyn(ip, port)
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

func (r *Runner) handleHostPort(host string, port int) {
	defer r.wgscan.Done()

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
		dt, err := r.scanner.IPRanger.GetFQDNByIP(hostIP)
		if err != nil {
			continue
		}

		for _, host := range dt {
			gologger.Infof("Found %d ports on host %s (%s)\n", len(ports), host, hostIP)

			// console output
			if r.options.JSON {
				data := JSONResult{IP: hostIP}
				if host != hostIP {
					data.Host = host
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
					gologger.Silentf("%s:%d\n", host, port)
				}
			}

			// file output
			if file != nil {
				if r.options.JSON {
					err = WriteJSONOutput(host, hostIP, ports, file)
				} else {
					err = WriteHostOutput(host, ports, file)
				}
				if err != nil {
					gologger.Errorf("Could not write results to file %s for %s: %s\n", output, host, err)
				}
			}
		}
	}
}
