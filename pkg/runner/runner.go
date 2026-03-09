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

	"github.com/Mzack9999/gcache"
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
	"github.com/projectdiscovery/naabu/v2/pkg/result/confidence"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/projectdiscovery/naabu/v2/pkg/utils/limits"
	"github.com/projectdiscovery/networkpolicy"
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
	excludedIpsNP *networkpolicy.NetworkPolicy

	unique gcache.Cache[string, struct{}]
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
	options.configureOutput()

	// automatically disable host discovery when less than two ports for scan are provided
	ports, err := ParsePorts(options)
	if err != nil {
		return nil, fmt.Errorf("could not parse ports: %s", err)
	}

	options.configureHostDiscovery(ports)

	// default to ipv4 and ipv6 if no ipversion was specified
	if len(options.IPVersion) == 0 {
		options.IPVersion = []string{scan.IPv4, scan.IPv6}
	}

	if options.Retries == 0 {
		options.Retries = DefaultRetriesSynScan
	}
	if options.ResumeCfg == nil {
		options.ResumeCfg = NewResumeCfg()
	}
	if options.Threads == 0 {
		options.Threads = DefaultThreadsNum
	}
	runner := &Runner{
		options: options,
	}

	dnsOptions := dnsx.DefaultOptions
	dnsOptions.MaxRetries = runner.options.Retries
	dnsOptions.Hostsfile = true
	if sliceutil.Contains(options.IPVersion, scan.IPv6) {
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

	if len(excludedIps) > 0 {
		excludedIpsNP, err := networkpolicy.New(networkpolicy.Options{
			DenyList: excludedIps,
		})
		if err != nil {
			return nil, err
		}
		runner.excludedIpsNP = excludedIpsNP
	}
	runner.streamChannel = make(chan Target)

	uniqueCache := gcache.New[string, struct{}](1500).Build()
	runner.unique = uniqueCache

	scanOpts := &scan.Options{
		Timeout:              options.GetTimeout(),
		Retries:              options.Retries,
		Rate:                 options.Rate,
		PortThreshold:        options.PortThreshold,
		ExcludeCdn:           options.ExcludeCDN,
		OutputCdn:            options.OutputCDN,
		ExcludedIps:          excludedIps,
		Proxy:                options.Proxy,
		ProxyAuth:            options.ProxyAuth,
		Stream:               options.Stream,
		OnReceive:            options.OnReceive,
		ScanType:             options.ScanType,
		NetworkPolicyOptions: options.NetworkPolicyOptions,
	}

	if scanOpts.OnReceive == nil {
		scanOpts.OnReceive = runner.onReceive
	}

	scanner, err := scan.NewScanner(scanOpts)
	if err != nil {
		return nil, err
	}
	runner.scanner = scanner

	runner.scanner.Ports = ports

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

func (r *Runner) onReceive(hostResult *result.HostResult) {
	if !ipMatchesIpVersions(hostResult.IP, r.options.IPVersion...) {
		return
	}

	dt, err := r.scanner.IPRanger.GetHostsByIP(hostResult.IP)
	if err != nil {
		return
	}

	// receive event has only one port
	for _, p := range hostResult.Ports {
		ipPort := net.JoinHostPort(hostResult.IP, fmt.Sprint(p.Port))
		if r.unique.Has(ipPort) {
			return
		}
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
		_ = r.unique.Set(ipPort, struct{}{})
	}

	// Skip immediate JSON/CSV output if nmap CLI is specified to postpone until after nmap integration
	if r.options.NmapCLI != "" && (r.options.JSON || r.options.CSV) {
		return
	}

	csvHeaderEnabled := true

	buffer := bytes.Buffer{}
	writer := csv.NewWriter(&buffer)
	for _, host := range dt {
		buffer.Reset()
		if host == "ip" {
			host = hostResult.IP
		}

		isCDNIP, cdnName, _ := r.scanner.CdnCheck(hostResult.IP)
		// console output
		if r.options.JSON || r.options.CSV {
			data := &Result{IP: hostResult.IP, TimeStamp: time.Now().UTC(), MacAddress: hostResult.MacAddress}
			if r.options.OutputCDN {
				data.IsCDNIP = isCDNIP
				data.CDNName = cdnName
			}
			if host != hostResult.IP {
				data.Host = host
			}
			for _, p := range hostResult.Ports {
				data.Port = p.Port
				data.Protocol = p.Protocol.String()
				//nolint
				data.TLS = p.TLS
				if r.options.JSON {
					b, err := data.JSON(r.options.ExcludeOutputFields)
					if err != nil {
						continue
					}
					buffer.Write([]byte(fmt.Sprintf("%s\n", b)))
				} else if r.options.CSV {
					if csvHeaderEnabled {
						writeCSVHeaders(data, writer, r.options.ExcludeOutputFields)
						csvHeaderEnabled = false
					}
					writeCSVRow(data, writer, r.options.ExcludeOutputFields)
				}
			}
		}
		if !r.options.DisableStdout {
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
		}
	}
}

// RunEnumeration runs the ports enumeration flow on the targets specified
func (r *Runner) RunEnumeration(pctx context.Context) error {
	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

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
		r.BackgroundWorkers(ctx)
	}

	if r.options.Stream {
		go r.Load() //nolint
	} else {
		err := r.Load()
		if err != nil {
			return err
		}
	}

	// automatically adjust rate limit if proxy is used
	if r.options.Proxy != "" {
		r.options.Rate = limits.RateLimitWithProxy(r.options.Rate)
	}

	// Scan workers
	r.wgscan = sizedwaitgroup.New(r.options.Rate)
	r.limiter = ratelimit.New(context.Background(), uint(r.options.Rate), time.Second)

	shouldDiscoverHosts := r.options.shouldDiscoverHosts()
	shouldUseRawPackets := r.options.shouldUseRawPackets()

	if shouldDiscoverHosts && shouldUseRawPackets {
		// perform host discovery
		showHostDiscoveryInfo()
		r.scanner.ListenHandler.Phase.Set(scan.HostDiscovery)
		// shrinks the ips to the minimum amount of cidr
		_, targetsV4, targetsv6, _, err := r.GetTargetIps(r.getPreprocessedIps)
		if err != nil {
			return err
		}

		discoverCidr := func(cidr *net.IPNet) {
			ipStream, _ := mapcidr.IPAddressesAsStream(cidr.String())
			for ip := range ipStream {
				if r.excludedIpsNP == nil || r.excludedIpsNP.ValidateAddress(ip) {
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
	payload := r.options.ConnectPayload
	switch {
	case r.options.Stream && !r.options.Passive: // stream active
		showNetworkCapabilities(r.options)
		r.scanner.ListenHandler.Phase.Set(scan.Scan)

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
				r.RawSocketEnumeration(ctx, target, port)
			} else {
				r.wgscan.Add()
				go r.handleHostPort(ctx, target, payload, port)
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

		time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)

		r.handleOutput(r.scanner.ScanResults)
		return nil
	case r.options.Stream && r.options.Passive: // stream passive
		showNetworkCapabilities(r.options)
		// create retryablehttp instance
		httpClient := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
		r.scanner.ListenHandler.Phase.Set(scan.Scan)
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

					var passivePorts []*port.Port
					for _, p := range data.Ports {
						pp := &port.Port{Port: p, Protocol: protocol.TCP}
						passivePorts = append(passivePorts, pp)
					}

					filteredPorts, err := excludePorts(r.options, passivePorts)
					if err != nil {
						gologger.Warning().Msgf("Couldn't exclude ports for %s: %s\n", ip, err)
						return
					}
					for _, p := range filteredPorts {
						r.scanner.ScanResults.AddPort(ip, p)
						// ignore OnReceive when verification is enabled
						if r.options.Verify {
							continue
						}
						if r.scanner.OnReceive != nil {
							r.scanner.OnReceive(&result.HostResult{IP: ip, Ports: []*port.Port{p}})
						}

					}
				}(ip)
			}
		}
		r.wgscan.Wait()

		// Validate the hosts if the user has asked for second step validation
		if r.options.Verify {
			r.ConnectVerification()
		}

		// handle nmap first to integrate service information
		if err := r.handleNmap(); err != nil {
			return err
		}

		// then handle output with enhanced service information
		r.handleOutput(r.scanner.ScanResults)
		return nil
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

		r.scanner.ListenHandler.Phase.Set(scan.Scan)
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

				if r.excludedIpsNP != nil && !r.excludedIpsNP.ValidateAddress(ip) {
					continue
				}

				port := r.PickPort(portIndex)

				r.options.ResumeCfg.RLock()
				resumeCfgIndex := r.options.ResumeCfg.Index
				r.options.ResumeCfg.RUnlock()
				if index < resumeCfgIndex {
					gologger.Debug().Msgf("Skipping \"%s:%d\": Resume - Port scan already completed\n", ip, port.Port)
					continue
				}

				// resume cfg logic
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
					r.RawSocketEnumeration(ctx, ip, port)
				} else {
					r.wgscan.Add()
					go r.handleHostPort(ctx, ip, payload, port)
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
					r.RawSocketEnumeration(ctx, ip, &portWithMetadata)
				} else {
					r.wgscan.Add()
					go r.handleHostPort(ctx, ip, payload, &portWithMetadata)
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

		warmUpTime := 2 * time.Second
		if r.options.WarmUpTime > 0 {
			warmUpTime = time.Duration(r.options.WarmUpTime) * time.Second
		}

		time.Sleep(warmUpTime)

		r.scanner.ListenHandler.Phase.Set(scan.Done)

		// Validate the hosts if the user has asked for second step validation
		if r.options.Verify {
			r.ConnectVerification()
		}

		// handle nmap first to integrate service information
		if err := r.handleNmap(); err != nil {
			return err
		}

		// then handle output with enhanced service information
		r.handleOutput(r.scanner.ScanResults)
		return nil
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

func (r *Runner) GetTargetIps(ipsCallback func() ([]*net.IPNet, []string)) (targets, targetsV4, targetsV6 []*net.IPNet, targetsWithPort []string, err error) {
	targets, targetsWithPort = ipsCallback()

	// shrinks the ips to the minimum amount of cidr
	targetsV4, targetsV6 = mapcidr.CoalesceCIDRs(targets)
	if len(targetsV4) == 0 && len(targetsV6) == 0 && len(targetsWithPort) == 0 {
		return nil, nil, nil, nil, errors.New("no valid ipv4 or ipv6 targets were found")
	}

	targets = make([]*net.IPNet, 0, len(targets))
	if r.options.ShouldScanIPv4() {
		targets = append(targets, targetsV4...)
	} else {
		targetsV4 = make([]*net.IPNet, 0)
	}

	if r.options.ShouldScanIPv6() {
		targets = append(targets, targetsV6...)
	} else {
		targetsV6 = make([]*net.IPNet, 0)
	}

	return targets, targetsV4, targetsV6, targetsWithPort, nil
}

func (r *Runner) ShowScanResultOnExit() {
	// handle nmap first to integrate service information
	if err := r.handleNmap(); err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}

	// then handle output with enhanced service information
	r.handleOutput(r.scanner.ScanResults)
}

// Close runner instance
func (r *Runner) Close() error {
	if err := os.RemoveAll(r.targetsFile); err != nil {
		return err
	}
	if err := r.scanner.IPRanger.Hosts.Close(); err != nil {
		return err
	}
	if r.options.EnableProgressBar {
		if err := r.stats.Stop(); err != nil {
			return err
		}
	}
	if r.scanner != nil {
		if err := r.scanner.Close(); err != nil {
			return err
		}
	}
	if r.limiter != nil {
		r.limiter.Stop()
	}
	if r.options.OnClose != nil {
		r.options.OnClose()
	}

	return nil
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
	r.scanner.ListenHandler.Phase.Set(scan.Scan)
	var swg sync.WaitGroup
	limiter := ratelimit.New(context.Background(), uint(r.options.Rate), time.Second)
	defer limiter.Stop()

	verifiedResult := result.NewResult()

	for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
		limiter.Take()

		swg.Add(1)
		go func(hostResult *result.HostResult) {
			defer swg.Done()

			// skip low confidence
			if hostResult.Confidence == confidence.Low {
				return
			}

			results := r.scanner.ConnectVerify(hostResult.IP, hostResult.Ports)
			verifiedResult.SetPorts(hostResult.IP, results)
		}(hostResult)
	}

	swg.Wait()

	r.scanner.ScanResults = verifiedResult
}

func (r *Runner) BackgroundWorkers(ctx context.Context) {
	r.scanner.StartWorkers(ctx)
}

func (r *Runner) RawSocketHostDiscovery(ip string) {
	r.handleHostDiscovery(ip)
}

func (r *Runner) RawSocketEnumeration(ctx context.Context, ip string, p *port.Port) {
	select {
	case <-ctx.Done():
		return
	default:
		// performs cdn/waf scan exclusions checks
		if !r.canIScanIfCDN(ip, p) {
			gologger.Debug().Msgf("Skipping cdn target: %s:%d\n", ip, p.Port)
			return
		}

		if r.scanner.ScanResults.IPHasPort(ip, p) {
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

func (r *Runner) handleHostPort(ctx context.Context, host, payload string, p *port.Port) {
	defer r.wgscan.Done()

	select {
	case <-ctx.Done():
		return
	default:
		// performs cdn scan exclusions checks
		if !r.canIScanIfCDN(host, p) {
			gologger.Debug().Msgf("Skipping cdn target: %s:%d\n", host, p.Port)
			return
		}

		if r.scanner.ScanResults.IPHasPort(host, p) {
			return
		}

		r.limiter.Take()
		open, err := r.scanner.ConnectPort(host, payload, p, r.options.GetTimeout())
		if open && err == nil {
			r.scanner.ScanResults.AddPort(host, p)
			// ignore OnReceive when verification is enabled
			if r.options.Verify {
				return
			}
			if r.scanner.OnReceive != nil {
				r.scanner.OnReceive(&result.HostResult{IP: host, Ports: []*port.Port{p}})
			}
		}
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
		r.scanner.ListenHandler.SourceIp4 = ip
	case iputil.IsIPv6(sourceIP):
		r.scanner.ListenHandler.SourceIP6 = ip
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

	r.scanner.ListenHandler.Port = port

	return nil
}

func (r *Runner) SetInterface(interfaceName string) error {
	networkInterface, err := net.InterfaceByName(r.options.Interface)
	if err != nil {
		return err
	}

	r.scanner.NetworkInterface = networkInterface
	r.scanner.ListenHandler.SourceHW = networkInterface.HardwareAddr
	return nil
}

func (r *Runner) handleOutput(scanResults *result.Result) {
	var (
		file   *os.File
		err    error
		output string
	)

	if r.options.Verify {
		for hostResult := range scanResults.GetIPsPorts() {
			r.scanner.OnReceive(hostResult)
		}
	}

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
		defer func() {
			if err := file.Close(); err != nil {
				gologger.Error().Msgf("Could not close file %s: %s\n", output, err)
			}
		}()
	}
	csvFileHeaderEnabled := true

	switch {
	case scanResults.HasIPsPorts():
		for hostResult := range scanResults.GetIPsPorts() {
			dt, err := r.scanner.IPRanger.GetHostsByIP(hostResult.IP)
			if err != nil {
				continue
			}

			if !ipMatchesIpVersions(hostResult.IP, r.options.IPVersion...) {
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
			for _, host := range dt {
				buffer.Reset()
				if host == "ip" {
					host = hostResult.IP
				}
				isCDNIP, cdnName, _ := r.scanner.CdnCheck(hostResult.IP)
				gologger.Info().Msgf("Found %d ports on host %s (%s)\n", len(hostResult.Ports), host, hostResult.IP)

				// console output
				if r.options.JSON || r.options.CSV {
					for _, p := range hostResult.Ports {
						data := &Result{IP: hostResult.IP, TimeStamp: time.Now().UTC(), MacAddress: hostResult.MacAddress}
						if r.options.OutputCDN {
							data.IsCDNIP = isCDNIP
							data.CDNName = cdnName
						}
						if host != hostResult.IP {
							data.Host = host
						}
						data.Port = p.Port
						data.Protocol = p.Protocol.String()
						//nolint
						data.TLS = p.TLS

						// copy service information if available
						if p.Service != nil {
							data.DeviceType = p.Service.DeviceType
							data.ExtraInfo = p.Service.ExtraInfo
							data.HighVersion = p.Service.HighVersion
							data.Hostname = p.Service.Hostname
							data.LowVersion = p.Service.LowVersion
							data.Method = p.Service.Method
							data.Name = p.Service.Name
							data.OSType = p.Service.OSType
							data.Product = p.Service.Product
							data.Proto = p.Service.Proto
							data.RPCNum = p.Service.RPCNum
							data.ServiceFP = p.Service.ServiceFP
							data.Tunnel = p.Service.Tunnel
							data.Version = p.Service.Version
							data.Confidence = p.Service.Confidence
						}
						if r.options.JSON {
							b, err := data.JSON(r.options.ExcludeOutputFields)
							if err != nil {
								continue
							}
							buffer.Write([]byte(fmt.Sprintf("%s\n", b)))
						} else if r.options.CSV {
							writer := csv.NewWriter(&buffer)
							if csvFileHeaderEnabled {
								writeCSVHeaders(data, writer, r.options.ExcludeOutputFields)
								csvFileHeaderEnabled = false
							}
							writeCSVRow(data, writer, r.options.ExcludeOutputFields)
						}
					}
				}

				if !r.options.DisableStdout {
					if r.options.JSON {
						gologger.Silent().Msgf("%s", buffer.String())
					} else if r.options.CSV {
						writer := csv.NewWriter(&buffer)
						writer.Flush()
						gologger.Silent().Msgf("%s", buffer.String())
					}
				}

				// file output
				if file != nil {
					if r.options.JSON {
						err = WriteJSONOutputWithMac(host, hostResult.IP, hostResult.MacAddress, hostResult.Ports, r.options.OutputCDN, isCDNIP, cdnName, r.options.ExcludeOutputFields, file)
					} else if r.options.CSV {
						err = WriteCsvOutputWithMac(host, hostResult.IP, hostResult.MacAddress, hostResult.Ports, r.options.OutputCDN, isCDNIP, cdnName, csvFileHeaderEnabled, r.options.ExcludeOutputFields, file)
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
			if !ipMatchesIpVersions(hostIP, r.options.IPVersion...) {
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
				var macAddress string
				if parsedIP := net.ParseIP(hostIP); parsedIP != nil && parsedIP.IsPrivate() {
					if mac, err := result.GetMacAddress(hostIP); err == nil {
						macAddress = mac
					}
				}
				if r.options.JSON || r.options.CSV {
					data := &Result{IP: hostIP, TimeStamp: time.Now().UTC(), MacAddress: macAddress}
					if r.options.OutputCDN {
						data.IsCDNIP = isCDNIP
						data.CDNName = cdnName
					}
					if host != hostIP {
						data.Host = host
					}
					if r.options.JSON {
						b, err := data.JSON(r.options.ExcludeOutputFields)
						if err != nil {
							continue
						}
						buffer.Write([]byte(fmt.Sprintf("%s\n", b)))
						gologger.Silent().Msgf("%s", buffer.String())
					} else {
						if csvFileHeaderEnabled {
							writeCSVHeaders(data, writer, r.options.ExcludeOutputFields)
							csvFileHeaderEnabled = false
						}
						writeCSVRow(data, writer, r.options.ExcludeOutputFields)
						writer.Flush()
						gologger.Silent().Msgf("%s", buffer.String())
					}
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
						err = WriteJSONOutputWithMac(host, hostIP, macAddress, nil, r.options.OutputCDN, isCDNIP, cdnName, r.options.ExcludeOutputFields, file)
					} else if r.options.CSV {
						err = WriteCsvOutputWithMac(host, hostIP, macAddress, nil, r.options.OutputCDN, isCDNIP, cdnName, csvFileHeaderEnabled, r.options.ExcludeOutputFields, file)
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

func ipMatchesIpVersions(ip string, ipVersions ...string) bool {
	for _, ipVersion := range ipVersions {
		if ipVersion == scan.IPv4 && iputil.IsIPv4(ip) {
			return true
		}
		if ipVersion == scan.IPv6 && iputil.IsIPv6(ip) {
			return true
		}
	}
	return false
}
