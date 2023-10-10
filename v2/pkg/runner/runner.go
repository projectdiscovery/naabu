package runner

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/uncover/sources/agent/shodanidb"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/remeh/sizedwaitgroup"
)

// Runner is an instance of the port enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options       *Options
	targetsFile   string
	scanner       *scan.Scanner
	limiter       *ratelimit.Limiter
	wgscan        sizedwaitgroup.SizedWaitGroup
	dnsclient     *dnsx.DNSX
	stats         *clistats.Statistics
	streamChannel chan Target
}

type Target struct {
	Ip   string
	Cidr string
	Fqdn string
	Port string
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists, etc
func NewRunner(options *Options) (*Runner, error) {
	if options.Retries == 0 {
		options.Retries = DefaultRetriesSynScan
	}
	if options.ResumeCfg == nil {
		options.ResumeCfg = NewResumeCfg()
	}
	runner := &Runner{
		options: options,
	}

	dnsOptions := dnsx.DefaultOptions
	dnsOptions.MaxRetries = runner.options.Retries
	dnsOptions.Hostsfile = true
	if sliceutil.Contains(options.IPVersion, "6") {
		dnsOptions.QuestionTypes = append(dnsOptions.QuestionTypes, dns.TypeAAAA)
	}
	if len(runner.options.baseResolvers) > 0 {
		dnsOptions.BaseResolvers = runner.options.baseResolvers
	}
	dnsclient, err := dnsx.New(dnsOptions)
	if err != nil {
		return nil, err
	}
	runner.dnsclient = dnsclient

	excludedIps, err := runner.parseExcludedIps(options)
	if err != nil {
		return nil, err
	}

	runner.streamChannel = make(chan Target)

	scanner, err := scan.NewScanner(&scan.Options{
		Timeout:       time.Duration(options.Timeout) * time.Millisecond,
		Retries:       options.Retries,
		Rate:          options.Rate,
		PortThreshold: options.PortThreshold,
		Debug:         options.Debug,
		ExcludeCdn:    options.ExcludeCDN,
		OutputCdn:     options.OutputCDN,
		ExcludedIps:   excludedIps,
		Proxy:         options.Proxy,
		ProxyAuth:     options.ProxyAuth,
		Stream:        options.Stream,
	})
	if err != nil {
		return nil, err
	}
	runner.scanner = scanner

	runner.scanner.Ports, err = ParsePorts(options)
	if err != nil {
		return nil, fmt.Errorf("could not parse ports: %s", err)
	}

	if options.EnableProgressBar {
		defaultOptions := &clistats.DefaultOptions
		defaultOptions.ListenPort = options.MetricsPort
		stats, err := clistats.NewWithOptions(context.Background(), defaultOptions)
		if err != nil {
			gologger.Warning().Msgf("Couldn't create progress engine: %s\n", err)
		} else {
			runner.stats = stats
		}
	}

	return runner, nil
}

// RunEnumeration runs the ports enumeration flow on the targets specified
func (r *Runner) RunEnumeration() error {
	defer r.Close()

	if privileges.IsPrivileged && r.options.ScanType == SynScan {
		// Set values if those were specified via cli, errors are fatal
		if r.options.SourceIP != "" {
			err := r.SetSourceIP(r.options.SourceIP)
			if err != nil {
				return err
			}
		}
		if r.options.Interface != "" {
			err := r.SetInterface(r.options.Interface)
			if err != nil {
				return err
			}
		}
		if r.options.SourcePort != "" {
			err := r.SetSourcePort(r.options.SourcePort)
			if err != nil {
				return err
			}
		}

		err := r.scanner.SetupHandlers()
		if err != nil {
			return err
		}
		r.BackgroundWorkers()
	}

	if r.options.Stream {
		go r.Load() //nolint
	} else {
		err := r.Load()
		if err != nil {
			return err
		}
	}

	// Scan workers
	r.wgscan = sizedwaitgroup.New(r.options.Rate)
	r.limiter = ratelimit.New(context.Background(), uint(r.options.Rate), time.Second)

	shouldDiscoverHosts := r.options.shouldDiscoverHosts()
	shouldUseRawPackets := r.options.shouldUseRawPackets()

	if shouldDiscoverHosts && shouldUseRawPackets {
		// perform host discovery
		showHostDiscoveryInfo()
		r.scanner.Phase.Set(scan.HostDiscovery)
		// shrinks the ips to the minimum amount of cidr
		_, targetsV4, targetsv6, _, err := r.GetTargetIps(r.getPreprocessedIps)
		if err != nil {
			return err
		}

		// get excluded ips
		excludedIPs, err := r.parseExcludedIps(r.options)
		if err != nil {
			return err
		}

		// store exclued ips to a map
		excludedIPsMap := make(map[string]struct{})
		for _, ipString := range excludedIPs {
			excludedIPsMap[ipString] = struct{}{}
		}

		discoverCidr := func(cidr *net.IPNet) {
			ipStream, _ := mapcidr.IPAddressesAsStream(cidr.String())
			for ip := range ipStream {
				// only run host discovery if the ip is not present in the excludedIPsMap
				if _, exists := excludedIPsMap[ip]; !exists {
					r.handleHostDiscovery(ip)
				}
			}
		}

		for _, target4 := range targetsV4 {
			discoverCidr(target4)
		}
		for _, target6 := range targetsv6 {
			discoverCidr(target6)
		}

		if r.options.WarmUpTime > 0 {
			time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
		}

		// check if we should stop here or continue with full scan
		if r.options.OnlyHostDiscovery {
			r.handleOutput(r.scanner.HostDiscoveryResults)
			return nil
		}
	}

	switch {
	case r.options.Stream && !r.options.Passive: // stream active
		showNetworkCapabilities(r.options)
		r.scanner.Phase.Set(scan.Scan)

		handleStreamIp := func(target string, port *port.Port) bool {
			if r.scanner.ScanResults.HasSkipped(target) {
				return false
			}
			if r.options.PortThreshold > 0 && r.scanner.ScanResults.GetPortCount(target) >= r.options.PortThreshold {
				hosts, _ := r.scanner.IPRanger.GetHostsByIP(target)
				gologger.Info().Msgf("Skipping %s %v, Threshold reached \n", target, hosts)
				r.scanner.ScanResults.AddSkipped(target)
				return false
			}
			if shouldUseRawPackets {
				r.RawSocketEnumeration(target, port)
			} else {
				r.wgscan.Add()
				go r.handleHostPort(target, port)
			}
			return true
		}

		for target := range r.streamChannel {
			if err := r.scanner.IPRanger.Add(target.Cidr); err != nil {
				gologger.Warning().Msgf("Couldn't track %s in scan results: %s\n", target, err)
			}
			if ipStream, err := mapcidr.IPAddressesAsStream(target.Cidr); err == nil {
				for ip := range ipStream {
					for _, port := range r.scanner.Ports {
						if !handleStreamIp(ip, port) {
							break
						}
					}
				}
			} else if target.Ip != "" && target.Port != "" {
				pp, _ := strconv.Atoi(target.Port)
				handleStreamIp(target.Ip, &port.Port{Port: pp, Protocol: protocol.TCP})
			}
		}
		r.wgscan.Wait()
		r.handleOutput(r.scanner.ScanResults)
		return nil
	case r.options.Stream && r.options.Passive: // stream passive
		showNetworkCapabilities(r.options)
		// create retryablehttp instance
		httpClient := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
		r.scanner.Phase.Set(scan.Scan)
		for target := range r.streamChannel {
			if err := r.scanner.IPRanger.Add(target.Cidr); err != nil {
				gologger.Warning().Msgf("Couldn't track %s in scan results: %s\n", target, err)
			}
			ipStream, _ := mapcidr.IPAddressesAsStream(target.Cidr)
			for ip := range ipStream {
				r.wgscan.Add()
				go func(ip string) {
					defer r.wgscan.Done()

					// obtain ports from shodan idb
					shodanURL := fmt.Sprintf(shodanidb.URL, url.QueryEscape(ip))
					request, err := retryablehttp.NewRequest(http.MethodGet, shodanURL, nil)
					if err != nil {
						gologger.Warning().Msgf("Couldn't create http request for %s: %s\n", ip, err)
						return
					}
					r.limiter.Take()
					response, err := httpClient.Do(request)
					if err != nil {
						gologger.Warning().Msgf("Couldn't retrieve http response for %s: %s\n", ip, err)
						return
					}
					if response.StatusCode != http.StatusOK {
						gologger.Warning().Msgf("Couldn't retrieve data for %s, server replied with status code: %d\n", ip, response.StatusCode)
						return
					}

					// unmarshal the response
					data := &shodanidb.ShodanResponse{}
					if err := json.NewDecoder(response.Body).Decode(data); err != nil {
						gologger.Warning().Msgf("Couldn't unmarshal json data for %s: %s\n", ip, err)
						return
					}

					for _, p := range data.Ports {
						r.scanner.ScanResults.AddPort(ip, &port.Port{Port: p, Protocol: protocol.TCP})
					}
				}(ip)
			}
		}
		r.wgscan.Wait()

		// Validate the hosts if the user has asked for second step validation
		if r.options.Verify {
			r.ConnectVerification()
		}

		r.handleOutput(r.scanner.ScanResults)

		// handle nmap
		return r.handleNmap()
	default:
		showNetworkCapabilities(r.options)

		ipsCallback := r.getPreprocessedIps
		if shouldDiscoverHosts && shouldUseRawPackets {
			ipsCallback = r.getHostDiscoveryIps
		}

		// shrinks the ips to the minimum amount of cidr
		targets, targetsV4, targetsv6, targetsWithPort, err := r.GetTargetIps(ipsCallback)
		if err != nil {
			return err
		}
		var targetsCount, portsCount, targetsWithPortCount uint64
		for _, target := range append(targetsV4, targetsv6...) {
			if target == nil {
				continue
			}
			targetsCount += mapcidr.AddressCountIpnet(target)
		}
		portsCount = uint64(len(r.scanner.Ports))
		targetsWithPortCount = uint64(len(targetsWithPort))

		r.scanner.Phase.Set(scan.Scan)
		Range := targetsCount * portsCount
		if r.options.EnableProgressBar {
			r.stats.AddStatic("ports", portsCount)
			r.stats.AddStatic("hosts", targetsCount)
			r.stats.AddStatic("retries", r.options.Retries)
			r.stats.AddStatic("startedAt", time.Now())
			r.stats.AddCounter("packets", uint64(0))
			r.stats.AddCounter("errors", uint64(0))
			r.stats.AddCounter("total", Range*uint64(r.options.Retries)+targetsWithPortCount)
			r.stats.AddStatic("hosts_with_port", targetsWithPortCount)
			if err := r.stats.Start(); err != nil {
				gologger.Warning().Msgf("Couldn't start statistics: %s\n", err)
			}
		}

		// Retries are performed regardless of the previous scan results due to network unreliability
		for currentRetry := 0; currentRetry < r.options.Retries; currentRetry++ {
			if currentRetry < r.options.ResumeCfg.Retry {
				gologger.Debug().Msgf("Skipping Retry: %d\n", currentRetry)
				continue
			}

			// Use current time as seed
			currentSeed := time.Now().UnixNano()
			r.options.ResumeCfg.RLock()
			if r.options.ResumeCfg.Seed > 0 {
				currentSeed = r.options.ResumeCfg.Seed
			}
			r.options.ResumeCfg.RUnlock()

			// keep track of current retry and seed for resume
			r.options.ResumeCfg.Lock()
			r.options.ResumeCfg.Retry = currentRetry
			r.options.ResumeCfg.Seed = currentSeed
			r.options.ResumeCfg.Unlock()

			b := blackrock.New(int64(Range), currentSeed)
			for index := int64(0); index < int64(Range); index++ {
				xxx := b.Shuffle(index)
				ipIndex := xxx / int64(portsCount)
				portIndex := int(xxx % int64(portsCount))
				ip := r.PickIP(targets, ipIndex)
				port := r.PickPort(portIndex)

				r.options.ResumeCfg.RLock()
				resumeCfgIndex := r.options.ResumeCfg.Index
				r.options.ResumeCfg.RUnlock()
				if index < resumeCfgIndex {
					gologger.Debug().Msgf("Skipping \"%s:%d\": Resume - Port scan already completed\n", ip, port.Port)
					continue
				}

				r.limiter.Take()
				//resume cfg logic
				r.options.ResumeCfg.Lock()
				r.options.ResumeCfg.Index = index
				r.options.ResumeCfg.Unlock()

				if r.scanner.ScanResults.HasSkipped(ip) {
					continue
				}
				if r.options.PortThreshold > 0 && r.scanner.ScanResults.GetPortCount(ip) >= r.options.PortThreshold {
					hosts, _ := r.scanner.IPRanger.GetHostsByIP(ip)
					gologger.Info().Msgf("Skipping %s %v, Threshold reached \n", ip, hosts)
					r.scanner.ScanResults.AddSkipped(ip)
					continue
				}

				// connect scan
				if shouldUseRawPackets {
					r.RawSocketEnumeration(ip, port)
				} else {
					r.wgscan.Add()
					go r.handleHostPort(ip, port)
				}
				if r.options.EnableProgressBar {
					r.stats.IncrementCounter("packets", 1)
				}
			}

			// handle the ip:port combination
			for _, targetWithPort := range targetsWithPort {
				ip, p, err := net.SplitHostPort(targetWithPort)
				if err != nil {
					gologger.Debug().Msgf("Skipping %s: %v\n", targetWithPort, err)
					continue
				}

				// naive port find
				pp, err := strconv.Atoi(p)
				if err != nil {
					gologger.Debug().Msgf("Skipping %s, could not cast port %s: %v\n", targetWithPort, p, err)
					continue
				}
				var portWithMetadata = port.Port{
					Port:     pp,
					Protocol: protocol.TCP,
				}

				// connect scan
				if shouldUseRawPackets {
					r.RawSocketEnumeration(ip, &portWithMetadata)
				} else {
					r.wgscan.Add()
					go r.handleHostPort(ip, &portWithMetadata)
				}
				if r.options.EnableProgressBar {
					r.stats.IncrementCounter("packets", 1)
				}
			}

			r.wgscan.Wait()

			r.options.ResumeCfg.Lock()
			if r.options.ResumeCfg.Seed > 0 {
				r.options.ResumeCfg.Seed = 0
			}
			if r.options.ResumeCfg.Index > 0 {
				// zero also the current index as we are restarting the scan
				r.options.ResumeCfg.Index = 0
			}
			r.options.ResumeCfg.Unlock()
		}

		if r.options.WarmUpTime > 0 {
			time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
		}

		r.scanner.Phase.Set(scan.Done)

		// Validate the hosts if the user has asked for second step validation
		if r.options.Verify {
			r.ConnectVerification()
		}

		r.handleOutput(r.scanner.ScanResults)

		// handle nmap
		return r.handleNmap()
	}
}

func (r *Runner) getHostDiscoveryIps() (ips []*net.IPNet, ipsWithPort []string) {
	for ip := range r.scanner.HostDiscoveryResults.GetIPs() {
		ips = append(ips, iputil.ToCidr(string(ip)))
	}

	r.scanner.IPRanger.Hosts.Scan(func(ip, _ []byte) error {
		// ips with port are ignored during host discovery phase
		if cidr := iputil.ToCidr(string(ip)); cidr == nil {
			ipsWithPort = append(ipsWithPort, string(ip))
		}
		return nil
	})

	return
}

func (r *Runner) getPreprocessedIps() (cidrs []*net.IPNet, ipsWithPort []string) {
	r.scanner.IPRanger.Hosts.Scan(func(ip, _ []byte) error {
		if cidr := iputil.ToCidr(string(ip)); cidr != nil {
			cidrs = append(cidrs, cidr)
		} else {
			ipsWithPort = append(ipsWithPort, string(ip))
		}

		return nil
	})
	return
}

func (r *Runner) GetTargetIps(ipsCallback func() ([]*net.IPNet, []string)) (targets, targetsV4, targetsv6 []*net.IPNet, targetsWithPort []string, err error) {
	targets, targetsWithPort = ipsCallback()

	// shrinks the ips to the minimum amount of cidr
	targetsV4, targetsv6 = mapcidr.CoalesceCIDRs(targets)
	if len(targetsV4) == 0 && len(targetsv6) == 0 && len(targetsWithPort) == 0 {
		return nil, nil, nil, nil, errors.New("no valid ipv4 or ipv6 targets were found")
	}
	return targets, targetsV4, targetsv6, targetsWithPort, nil
}

func (r *Runner) ShowScanResultOnExit() {
	r.handleOutput(r.scanner.ScanResults)
	err := r.handleNmap()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
}

// Close runner instance
func (r *Runner) Close() {
	_ = os.RemoveAll(r.targetsFile)
	_ = r.scanner.IPRanger.Hosts.Close()
	if r.options.EnableProgressBar {
		_ = r.stats.Stop()
	}
}

// PickIP randomly
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
	ipInt, bits, err := mapcidr.IPToInteger(network.IP)
	if err != nil {
		gologger.Warning().Msgf("%s\n", err)
		return ""
	}
	subnetIpInt := big.NewInt(0).Add(ipInt, big.NewInt(index))
	ip := mapcidr.IntegerToIP(subnetIpInt, bits)
	return ip.String()
}

func (r *Runner) PickPort(index int) *port.Port {
	return r.scanner.Ports[index]
}

func (r *Runner) ConnectVerification() {
	r.scanner.Phase.Set(scan.Scan)
	var swg sync.WaitGroup
	limiter := ratelimit.New(context.Background(), uint(r.options.Rate), time.Second)

	verifiedResult := result.NewResult()

	for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
		limiter.Take()
		swg.Add(1)
		go func(hostResult *result.HostResult) {
			defer swg.Done()
			results := r.scanner.ConnectVerify(hostResult.IP, hostResult.Ports)
			verifiedResult.SetPorts(hostResult.IP, results)
		}(hostResult)
	}

	r.scanner.ScanResults = verifiedResult

	swg.Wait()
}

func (r *Runner) BackgroundWorkers() {
	r.scanner.StartWorkers()
}

func (r *Runner) RawSocketHostDiscovery(ip string) {
	r.handleHostDiscovery(ip)
}

func (r *Runner) RawSocketEnumeration(ip string, p *port.Port) {
	// performs cdn/waf scan exclusions checks
	if !r.canIScanIfCDN(ip, p) {
		gologger.Debug().Msgf("Skipping cdn target: %s:%d\n", ip, p.Port)
		return
	}
	r.limiter.Take()
	switch p.Protocol {
	case protocol.TCP:
		r.scanner.EnqueueTCP(ip, scan.Syn, p)
	case protocol.UDP:
		r.scanner.EnqueueUDP(ip, p)
	}
}

// check if an ip can be scanned in case CDN/WAF exclusions are enabled
func (r *Runner) canIScanIfCDN(host string, port *port.Port) bool {
	// if CDN ips are not excluded all scans are allowed
	if !r.options.ExcludeCDN {
		return true
	}

	// if exclusion is enabled, but the ip is not part of the CDN/WAF ips range we can scan
	if ok, _, err := r.scanner.CdnCheck(host); err == nil && !ok {
		return true
	}

	// If the cdn is part of the CDN ips range - only ports 80 and 443 are allowed
	return port.Port == 80 || port.Port == 443
}

func (r *Runner) handleHostPort(host string, p *port.Port) {
	defer r.wgscan.Done()

	// performs cdn scan exclusions checks
	if !r.canIScanIfCDN(host, p) {
		gologger.Debug().Msgf("Skipping cdn target: %s:%d\n", host, p.Port)
		return
	}

	if r.scanner.ScanResults.IPHasPort(host, p) {
		return
	}

	r.limiter.Take()
	open, err := r.scanner.ConnectPort(host, p, time.Duration(r.options.Timeout)*time.Millisecond)
	if open && err == nil {
		r.scanner.ScanResults.AddPort(host, p)
	}
}

func (r *Runner) handleHostDiscovery(host string) {
	r.limiter.Take()
	// Pings
	// - Icmp Echo Request
	if r.options.IcmpEchoRequestProbe {
		r.scanner.EnqueueICMP(host, scan.IcmpEchoRequest)
	}
	// - Icmp Timestamp Request
	if r.options.IcmpTimestampRequestProbe {
		r.scanner.EnqueueICMP(host, scan.IcmpTimestampRequest)
	}
	// - Icmp Netmask Request
	if r.options.IcmpAddressMaskRequestProbe {
		r.scanner.EnqueueICMP(host, scan.IcmpAddressMaskRequest)
	}
	// ARP scan
	if r.options.ArpPing {
		r.scanner.EnqueueEthernet(host, scan.Arp)
	}
	// Syn Probes
	if len(r.options.TcpSynPingProbes) > 0 {
		ports, _ := parsePortsSlice(r.options.TcpSynPingProbes)
		r.scanner.EnqueueTCP(host, scan.Syn, ports...)
	}
	// Ack Probes
	if len(r.options.TcpAckPingProbes) > 0 {
		ports, _ := parsePortsSlice(r.options.TcpAckPingProbes)
		r.scanner.EnqueueTCP(host, scan.Ack, ports...)
	}
	// IPv6-ND (for now we broadcast ICMPv6 to ff02::1)
	if r.options.IPv6NeighborDiscoveryPing {
		r.scanner.EnqueueICMP("ff02::1", scan.Ndp)
	}
}

func (r *Runner) SetSourceIP(sourceIP string) error {
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return errors.New("invalid source ip")
	}

	switch {
	case iputil.IsIPv4(sourceIP):
		r.scanner.SourceIP4 = ip
	case iputil.IsIPv6(sourceIP):
		r.scanner.SourceIP6 = ip
	default:
		return errors.New("invalid ip type")
	}

	return nil
}

func (r *Runner) SetSourcePort(sourcePort string) error {
	isValidPort := iputil.IsPort(sourcePort)
	if !isValidPort {
		return errors.New("invalid source port")
	}

	port, err := strconv.Atoi(sourcePort)
	if err != nil {
		return err
	}

	r.scanner.SourcePort = port

	return nil
}

func (r *Runner) SetInterface(interfaceName string) error {
	networkInterface, err := net.InterfaceByName(r.options.Interface)
	if err != nil {
		return err
	}

	r.scanner.NetworkInterface = networkInterface
	return nil
}

func (r *Runner) handleOutput(scanResults *result.Result) {
	var (
		file   *os.File
		err    error
		output string
	)

	// In case the user has given an output file, write all the found
	// ports to the output file.
	if r.options.Output != "" {
		output = r.options.Output

		// create path if not existing
		outputFolder := filepath.Dir(output)
		if fileutil.FolderExists(outputFolder) {
			mkdirErr := os.MkdirAll(outputFolder, 0700)
			if mkdirErr != nil {
				gologger.Error().Msgf("Could not create output folder %s: %s\n", outputFolder, mkdirErr)
				return
			}
		}

		file, err = os.Create(output)
		if err != nil {
			gologger.Error().Msgf("Could not create file %s: %s\n", output, err)
			return
		}
		defer file.Close()
	}
	csvFileHeaderEnabled := true

	switch {
	case scanResults.HasIPsPorts():
		for hostResult := range scanResults.GetIPsPorts() {
			csvHeaderEnabled := true
			dt, err := r.scanner.IPRanger.GetHostsByIP(hostResult.IP)
			if err != nil {
				continue
			}

			// recover hostnames from ip:port combination
			for _, p := range hostResult.Ports {
				ipPort := net.JoinHostPort(hostResult.IP, fmt.Sprint(p.Port))
				if dtOthers, ok := r.scanner.IPRanger.Hosts.Get(ipPort); ok {
					if otherName, _, err := net.SplitHostPort(string(dtOthers)); err == nil {
						// replace bare ip:port with host
						for idx, ipCandidate := range dt {
							if iputil.IsIP(ipCandidate) {
								dt[idx] = otherName
							}
						}
					}
				}
			}

			buffer := bytes.Buffer{}
			writer := csv.NewWriter(&buffer)
			for _, host := range dt {
				buffer.Reset()
				if host == "ip" {
					host = hostResult.IP
				}
				isCDNIP, cdnName, _ := r.scanner.CdnCheck(hostResult.IP)
				gologger.Info().Msgf("Found %d ports on host %s (%s)\n", len(hostResult.Ports), host, hostResult.IP)
				// console output
				if r.options.JSON || r.options.CSV {
					data := &Result{IP: hostResult.IP, TimeStamp: time.Now().UTC()}
					if r.options.OutputCDN {
						data.IsCDNIP = isCDNIP
						data.CDNName = cdnName
					}
					if host != hostResult.IP {
						data.Host = host
					}
					for _, p := range hostResult.Ports {
						data.Port = p
						if r.options.JSON {
							b, marshallErr := data.JSON()
							if marshallErr != nil {
								continue
							}
							buffer.Write([]byte(fmt.Sprintf("%s\n", b)))
						} else if r.options.CSV {
							if csvHeaderEnabled {
								writeCSVHeaders(data, writer)
								csvHeaderEnabled = false
							}
							writeCSVRow(data, writer)
						}
					}
				}
				if r.options.JSON {
					gologger.Silent().Msgf("%s", buffer.String())
				} else if r.options.CSV {
					writer.Flush()
					gologger.Silent().Msgf("%s", buffer.String())
				} else {
					for _, p := range hostResult.Ports {
						if r.options.OutputCDN && isCDNIP {
							gologger.Silent().Msgf("%s:%d [%s]\n", host, p.Port, cdnName)
						} else {
							gologger.Silent().Msgf("%s:%d\n", host, p.Port)
						}
					}
				}
				// file output
				if file != nil {
					if r.options.JSON {
						err = WriteJSONOutput(host, hostResult.IP, hostResult.Ports, r.options.OutputCDN, isCDNIP, cdnName, file)
					} else if r.options.CSV {
						err = WriteCsvOutput(host, hostResult.IP, hostResult.Ports, r.options.OutputCDN, isCDNIP, cdnName, csvFileHeaderEnabled, file)
					} else {
						err = WriteHostOutput(host, hostResult.Ports, r.options.OutputCDN, cdnName, file)
					}
					if err != nil {
						gologger.Error().Msgf("Could not write results to file %s for %s: %s\n", output, host, err)
					}
				}

				if r.options.OnResult != nil {
					r.options.OnResult(&result.HostResult{Host: host, IP: hostResult.IP, Ports: hostResult.Ports})
				}
			}
			csvFileHeaderEnabled = false
		}
	case scanResults.HasIPS():
		for hostIP := range scanResults.GetIPs() {
			dt, err := r.scanner.IPRanger.GetHostsByIP(hostIP)
			if err != nil {
				continue
			}
			buffer := bytes.Buffer{}
			writer := csv.NewWriter(&buffer)
			for _, host := range dt {
				buffer.Reset()
				if host == "ip" {
					host = hostIP
				}
				isCDNIP, cdnName, _ := r.scanner.CdnCheck(hostIP)
				gologger.Info().Msgf("Found alive host %s (%s)\n", host, hostIP)
				// console output
				if r.options.JSON || r.options.CSV {
					data := &Result{IP: hostIP, TimeStamp: time.Now().UTC()}
					if r.options.OutputCDN {
						data.IsCDNIP = isCDNIP
						data.CDNName = cdnName
					}
					if host != hostIP {
						data.Host = host
					}
				}
				if r.options.JSON {
					gologger.Silent().Msgf("%s", buffer.String())
				} else if r.options.CSV {
					writer.Flush()
					gologger.Silent().Msgf("%s", buffer.String())
				} else {
					if r.options.OutputCDN && isCDNIP {
						gologger.Silent().Msgf("%s [%s]\n", host, cdnName)
					} else {
						gologger.Silent().Msgf("%s\n", host)
					}
				}
				// file output
				if file != nil {
					if r.options.JSON {
						err = WriteJSONOutput(host, hostIP, nil, r.options.OutputCDN, isCDNIP, cdnName, file)
					} else if r.options.CSV {
						err = WriteCsvOutput(host, hostIP, nil, r.options.OutputCDN, isCDNIP, cdnName, csvFileHeaderEnabled, file)
					} else {
						err = WriteHostOutput(host, nil, r.options.OutputCDN, cdnName, file)
					}
					if err != nil {
						gologger.Error().Msgf("Could not write results to file %s for %s: %s\n", output, host, err)
					}
				}

				if r.options.OnResult != nil {
					r.options.OnResult(&result.HostResult{Host: host, IP: hostIP})
				}
			}
			csvFileHeaderEnabled = false
		}
	}

}

func writeCSVHeaders(data *Result, writer *csv.Writer) {
	headers, err := data.CSVHeaders()
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}

	if err := writer.Write(headers); err != nil {
		errMsg := errors.Wrap(err, "Could not write headers")
		gologger.Error().Msgf(errMsg.Error())
	}
}

func writeCSVRow(data *Result, writer *csv.Writer) {
	rowData, err := data.CSVFields()
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
	if err := writer.Write(rowData); err != nil {
		errMsg := errors.Wrap(err, "Could not write row")
		gologger.Error().Msgf(errMsg.Error())
	}
}
