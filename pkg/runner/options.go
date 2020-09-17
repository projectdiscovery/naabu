package runner

import (
	"flag"
	"os"

	"github.com/projectdiscovery/gologger"
)

// Options contains the configuration options for tuning
// the port enumeration process.
type Options struct {
	// Retries is the number of retries for the port
	Retries int
	// Rate is the rate of port scan requests
	Rate int
	// Verbose flag indicates whether to show verbose output or not
	Verbose bool
	// No-Color disables the colored output
	NoColor bool
	// Thread controls the number of parallel host to enumerate
	Threads int
	// Timeout is the seconds to wait for ports to respond
	Timeout int
	// Host is the host to find ports for
	Host string
	// HostsFile is the file containing list of hosts to find port for
	HostsFile string
	// Output is the file to write found ports to.
	Output string
	// JSON specifies whether to use json for output format or text file
	JSON bool
	// Silent suppresses any extra text and only writes found host:port to screen
	Silent bool
	// Ports is the ports to use for enumeration
	Ports string
	// PortsFile is the file containing ports to use for enumeration
	PortsFile string
	// ExcludePorts is the list of ports to exclude from enumeration
	ExcludePorts string
	// Stdin specifies whether stdin input was given to the process
	Stdin bool
	// Verify is used to check if the ports found were valid using CONNECT method
	Verify bool
	// Version specifies if we should just show version and exit
	Version bool
	// NoProbe skips probes to discover alive hosts
	NoProbe bool
	// Ping uses ping probes to discover fastest active host and discover dead hosts
	Ping bool
	// Port Probes (SYN-PORT, ACK-PORT)
	PortProbes string
	// Ips or cidr to be excluded from the scan
	ExcludeIps string
	// File containing Ips or cidr to exclude from the scan
	ExcludeIpsFile string
	// Prints out debug information
	Debug bool
	// Top ports list
	TopPorts string
	// Attempts to run as root
	Privileged bool
	// Drop root privileges
	Unprivileged bool
	// Excludes ip of knows CDN ranges
	ExcludeCDN bool
	// IcmpEchoProbe before scanning
	IcmpEchoProbe bool
	// IcmpTimestampProbe before scanning
	IcmpTimestampProbe bool
	// SourceIp to use in TCP packets
	SourceIp string
	// Interface to use for TCP packets
	Interface string
	// WarmUpTime between scan phases
	WarmUpTime int
	// InterfacesList show interfaces list
	InterfacesList bool
	// Config file contains a scan configuration
	ConfigFile string
	config     *ConfigFile
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

	flag.StringVar(&options.Host, "host", "", "Host to find ports for")
	flag.StringVar(&options.TopPorts, "top-ports", "", "Top Ports")
	flag.StringVar(&options.HostsFile, "iL", "", "File containing list of hosts to enumerate ports")
	flag.StringVar(&options.Ports, "p", "", "Ports to enumerate for on hosts (top-1000, full, custom, default: top-100)")
	flag.StringVar(&options.PortProbes, "port-probe", "S80,A443", "Port probes for hosts (default SYN - 80, ACK - 443)")
	flag.BoolVar(&options.IcmpEchoProbe, "icmp-echo-probe", true, "Use ICMP_ECHO_REQUEST probe")
	flag.BoolVar(&options.IcmpTimestampProbe, "icmp-timestamp-probe", true, "Use ICMP_ECHO_REQUEST probe")
	flag.BoolVar(&options.NoProbe, "no-probe", false, "Skip all probes for verification of host")
	flag.BoolVar(&options.Ping, "ping", true, "Use ping probes for verification of host")
	flag.StringVar(&options.PortsFile, "ports-file", "", "File containing ports to enumerate for on hosts")
	flag.StringVar(&options.Output, "o", "", "File to write output to (optional)")
	flag.BoolVar(&options.JSON, "json", false, "Write output in JSON lines Format")
	flag.BoolVar(&options.Silent, "silent", false, "Show only host:ports in output")
	flag.IntVar(&options.Retries, "retries", DefaultRetriesSynScan, "Number of retries for the port scan probe")
	flag.IntVar(&options.Rate, "rate", DefaultRateSynScan, "Rate of port scan probe requests")
	flag.BoolVar(&options.Verbose, "v", false, "Show Verbose output")
	flag.BoolVar(&options.NoColor, "nC", false, "Don't Use colors in output")
	flag.IntVar(&options.Threads, "t", DefaultResolverThreads, "Number of concurrent goroutines for resolving")
	flag.IntVar(&options.Timeout, "timeout", DefaultPortTimeoutSynScan, "Millisecond to wait before timing out")
	flag.StringVar(&options.ExcludePorts, "exclude-ports", "", "Ports to exclude from enumeration")
	flag.BoolVar(&options.Verify, "verify", false, "Validate the ports again")
	flag.BoolVar(&options.Version, "version", false, "Show version of naabu")
	flag.StringVar(&options.ExcludeIps, "exclude-hosts", "", "Specifies a comma-separated list of targets to be excluded from the scan (ip, cidr)")
	flag.StringVar(&options.ExcludeIpsFile, "exclude-file", "", "This offers the same functionality as the -exclude option, except that the excluded targets are provided in a newline-delimited file")
	flag.BoolVar(&options.Debug, "debug", false, "Enable debugging information") // Debug mode allows debugging request/responses for the engine
	flag.StringVar(&options.SourceIp, "source-ip", "", "Source Ip")
	flag.StringVar(&options.Interface, "interface", "", "Network Interface")
	flag.BoolVar(&options.Privileged, "privileged", false, "Attempts to run as root - Use sudo if possible")
	flag.BoolVar(&options.Unprivileged, "unprivileged", false, "Drop root privileges")
	flag.BoolVar(&options.ExcludeCDN, "exclude-cdn", false, "Avoid scanning CDN ips")
	flag.IntVar(&options.WarmUpTime, "warm-up-time", 2, "Time in Seconds between scan phases")
	flag.BoolVar(&options.InterfacesList, "interface-list", false, "list available interfaces and public ip")
	flag.StringVar(&options.ConfigFile, "config", "", "Config file")
	flag.Parse()

	// Check if stdin pipe was given
	options.Stdin = hasStdin()

	// Read the inputs and configure the logging
	options.configureOutput()

	// Show the user the banner
	showBanner()

	if options.Version {
		gologger.Infof("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// Show network configuration and exit if the user requested it
	if options.InterfacesList {
		showNetworkInterfaces()
		os.Exit(0)
	}

	// If a config file is provided, merge the options
	if options.ConfigFile != "" {
		options.MergeFromConfig()
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.validateOptions()
	if err != nil {
		gologger.Fatalf("Program exiting: %s\n", err)
	}

	showNetworkCapabilities()

	// Handle privileges - most probably elevation will fail as the process would need to invoke fork()
	err = handlePrivileges(options)
	if err != nil {
		gologger.Warningf("Could not set privileges:%s\n", err)
	}

	return options
}

func hasStdin() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	return fi.Mode()&os.ModeNamedPipe != 0
}

func (options *Options) MergeFromConfig() {
	configFile, err := UnmarshalRead(options.ConfigFile)
	if err != nil {
		gologger.Fatalf("Could not read configuration file %s: %s\n", options.ConfigFile, err)
	}
	options.config = &configFile

	if configFile.Retries > 0 {
		options.Retries = configFile.Retries
	}
	if configFile.Rate > 0 {
		options.Rate = configFile.Rate
	}
	if configFile.Threads > 0 {
		options.Threads = configFile.Threads
	}
	if configFile.Timeout > 0 {
		options.Timeout = configFile.Timeout
	}
	options.Verify = configFile.Verify
	options.NoProbe = configFile.NoProbe
	options.Ping = configFile.Ping
	if configFile.TopPorts != "" {
		options.TopPorts = configFile.TopPorts
	}
	options.Privileged = configFile.Privileged
	options.Unprivileged = configFile.Unprivileged
	options.ExcludeCDN = configFile.ExcludeCDN
	options.IcmpEchoProbe = configFile.IcmpEchoProbe
	options.IcmpTimestampProbe = configFile.IcmpTimestampProbe
	if configFile.SourceIp != "" {
		options.SourceIp = configFile.SourceIp
	}
	if configFile.Interface != "" {
		options.Interface = configFile.Interface
	}
	if configFile.WarmUpTime > 0 {
		options.WarmUpTime = configFile.WarmUpTime
	}
}
