package runner

import (
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	osutil "github.com/projectdiscovery/utils/os"
	sliceutil "github.com/projectdiscovery/utils/slice"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	errNoInputList   = errors.New("no input list provided")
	errOutputMode    = errors.New("both verbose and silent mode specified")
	errZeroValue     = errors.New("cannot be zero")
	errTwoOutputMode = errors.New("both json and csv mode specified")
)

// ValidateOptions validates the configuration options passed
func (options *Options) ValidateOptions() error {
	// Check if Host, list of domains, or stdin info was provided.
	// If none was provided, then return.
	if options.Host == nil && options.HostsFile == "" && !options.Stdin && len(flag.Args()) == 0 {
		return errNoInputList
	}

	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errOutputMode
	}

	if options.JSON && options.CSV {
		return errTwoOutputMode
	}

	if options.Timeout == 0 {
		return errors.Wrap(errZeroValue, "timeout")
	} else if !privileges.IsPrivileged && options.Timeout == DefaultPortTimeoutSynScan {
		options.Timeout = DefaultPortTimeoutConnectScan
	}

	if options.Rate == 0 {
		return errors.Wrap(errZeroValue, "rate")
	} else if !privileges.IsPrivileged && options.Rate == DefaultRateSynScan {
		options.Rate = DefaultRateConnectScan
	}

	if !privileges.IsPrivileged && options.Retries == DefaultRetriesSynScan {
		options.Retries = DefaultRetriesConnectScan
	}

	if options.Interface != "" {
		if _, err := net.InterfaceByName(options.Interface); err != nil {
			return fmt.Errorf("interface %s not found", options.Interface)
		}
	}

	if fileutil.FileExists(options.Resolvers) {
		chanResolvers, err := fileutil.ReadFile(options.Resolvers)
		if err != nil {
			return err
		}
		for resolver := range chanResolvers {
			options.baseResolvers = append(options.baseResolvers, resolver)
		}
	} else if options.Resolvers != "" {
		for _, resolver := range strings.Split(options.Resolvers, ",") {
			options.baseResolvers = append(options.baseResolvers, strings.TrimSpace(resolver))
		}
	}

	// passive mode enables automatically stream
	if options.Passive {
		options.Stream = true
	}

	// stream
	if options.Stream {
		if options.Resume {
			return errors.New("resume not supported in stream active mode")
		}
		if options.EnableProgressBar {
			return errors.New("stats not supported in stream active mode")
		}
		if options.Nmap {
			return errors.New("nmap not supported in stream active mode")
		}
	}

	// stream passive
	if options.Verify && options.Stream && !options.Passive {
		return errors.New("verify not supported in stream active mode")
	}

	// Parse and validate source ip and source port
	// checks if source ip is ip only
	isOnlyIP := iputil.IsIP(options.SourceIP)
	if options.SourceIP != "" && !isOnlyIP {
		ip, port, err := net.SplitHostPort(options.SourceIP)
		if err != nil {
			return err
		}
		options.SourceIP = ip
		options.SourcePort = port
	}

	if len(options.IPVersion) > 0 && !sliceutil.ContainsItems([]string{scan.IPv4, scan.IPv6}, options.IPVersion) {
		return errors.New("IP Version must be 4 and/or 6")
	}
	// Return error if any host discovery releated option is provided but host discovery is disabled
	if options.SkipHostDiscovery && options.hasProbes() {
		return errors.New("discovery probes were provided but host discovery is disabled")
	}

	// Host Discovery mode needs provileged access
	if options.OnlyHostDiscovery && !privileges.IsPrivileged {
		if osutil.IsWindows() {
			return errors.New("host discovery not (yet) supported on windows")
		}
		return errors.New("sudo access required to perform host discovery")
	}

	if options.PortThreshold < 0 || options.PortThreshold > 65535 {
		return errors.New("port threshold must be between 0 and 65535")
	}

	if options.Proxy != "" && options.ScanType == SynScan {
		gologger.Warning().Msgf("Syn Scan can't be used with socks proxy: falling back to connect scan")
		options.ScanType = ConnectScan
	}

	if options.ScanType == SynScan && scan.PkgRouter == nil {
		gologger.Warning().Msgf("Routing could not be determined (are you using a VPN?).falling back to connect scan")
		options.ScanType = ConnectScan
	}

	return nil
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

// ConfigureHostDiscovery enables default probes if none is specified
// but host discovery option was requested
func (options *Options) configureHostDiscovery(ports []*port.Port) {
	// if less than two ports are specified as input, reduce time and scan directly
	if len(ports) <= 2 {
		gologger.Info().Msgf("Host discovery disabled: less than two ports were specified")
		options.SkipHostDiscovery = true
	}
	if options.shouldDiscoverHosts() && !options.hasProbes() {
		// if no options were defined enable
		// - ICMP Echo Request
		// - ICMP timestamp
		// - TCP SYN on port 80
		// - TCP SYN on port 443
		// - TCP ACK on port 80
		// - TCP ACK on port 443
		options.IcmpEchoRequestProbe = true
		options.IcmpTimestampRequestProbe = true
		options.TcpSynPingProbes = append(options.TcpSynPingProbes, "80")
		options.TcpSynPingProbes = append(options.TcpSynPingProbes, "443")
		options.TcpAckPingProbes = append(options.TcpAckPingProbes, "80")
		options.TcpAckPingProbes = append(options.TcpAckPingProbes, "443")
	}
}
