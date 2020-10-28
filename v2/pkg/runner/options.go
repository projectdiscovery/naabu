package runner

import (
	"flag"
	"os"

	"github.com/projectdiscovery/gologger"
)

// Options contains the configuration options for tuning
// the port enumeration process.
type Options struct {
	Verbose        bool // Verbose flag indicates whether to show verbose output or not
	NoColor        bool // No-Color disables the colored output
	JSON           bool // JSON specifies whether to use json for output format or text file
	Silent         bool // Silent suppresses any extra text and only writes found host:port to screen
	Stdin          bool // Stdin specifies whether stdin input was given to the process
	Verify         bool // Verify is used to check if the ports found were valid using CONNECT method
	Version        bool // Version specifies if we should just show version and exit
	Ping           bool // Ping uses ping probes to discover fastest active host and discover dead hosts
	Debug          bool // Prints out debug information
	Privileged     bool // Attempts to run as root
	Unprivileged   bool // Drop root privileges
	ExcludeCDN     bool // Excludes ip of knows CDN ranges for full port scan
	Nmap           bool // Invoke nmap detailed scan on results
	InterfacesList bool // InterfacesList show interfaces list

	Retries        int    // Retries is the number of retries for the port
	Rate           int    // Rate is the rate of port scan requests
	Timeout        int    // Timeout is the seconds to wait for ports to respond
	WarmUpTime     int    // WarmUpTime between scan phases
	Host           string // Host is the host to find ports for
	HostsFile      string // HostsFile is the file containing list of hosts to find port for
	Output         string // Output is the file to write found ports to.
	Ports          string // Ports is the ports to use for enumeration
	PortsFile      string // PortsFile is the file containing ports to use for enumeration
	ExcludePorts   string // ExcludePorts is the list of ports to exclude from enumeration
	ExcludeIps     string // Ips or cidr to be excluded from the scan
	ExcludeIpsFile string // File containing Ips or cidr to exclude from the scan
	TopPorts       string // Tops ports to scan
	SourceIP       string // SourceIP to use in TCP packets
	Interface      string // Interface to use for TCP packets
	ConfigFile     string // Config file contains a scan configuration
	NmapCLI        string // Nmap command (has priority over config file)
	Threads        int    // Internal worker threads
	config         *ConfigFile
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

	flag.StringVar(&options.Host, "host", "", "Host to find ports for")
	flag.StringVar(&options.TopPorts, "top-ports", "", "Top Ports to scan (default top 100")
	flag.StringVar(&options.HostsFile, "iL", "", "File containing list of hosts to enumerate ports")
	flag.StringVar(&options.Ports, "p", "", "Ports to scan (80, 80,443, 100-200, (-p - for full port scan)")
	flag.BoolVar(&options.Ping, "ping", false, "Use ping probes for verification of host")
	flag.StringVar(&options.PortsFile, "ports-file", "", "File containing ports to enumerate for on hosts")
	flag.StringVar(&options.Output, "o", "", "File to write output to (optional)")
	flag.BoolVar(&options.JSON, "json", false, "Write output in JSON lines Format")
	flag.BoolVar(&options.Silent, "silent", false, "Show found ports only in output")
	flag.IntVar(&options.Retries, "retries", DefaultRetriesSynScan, "Number of retries for the port scan probe")
	flag.IntVar(&options.Rate, "rate", DefaultRateSynScan, "Rate of port scan probe requests")
	flag.BoolVar(&options.Verbose, "v", false, "Show Verbose output")
	flag.BoolVar(&options.NoColor, "nC", false, "Don't Use colors in output")
	flag.IntVar(&options.Timeout, "timeout", DefaultPortTimeoutSynScan, "Millisecond to wait before timing out")
	flag.StringVar(&options.ExcludePorts, "exclude-ports", "", "Ports to exclude from enumeration")
	flag.BoolVar(&options.Verify, "verify", false, "Validate the ports again with TCP verification")
	flag.BoolVar(&options.Version, "version", false, "Show version of naabu")
	flag.StringVar(&options.ExcludeIps, "exclude-hosts", "", "Specifies a comma-separated list of targets to be excluded from the scan (ip, cidr)")
	flag.StringVar(&options.ExcludeIpsFile, "exclude-file", "", "Specifies a newline-delimited file with targets to be excluded from the scan (ip, cidr)")
	flag.BoolVar(&options.Debug, "debug", false, "Enable debugging information")
	flag.StringVar(&options.SourceIP, "source-ip", "", "Source Ip")
	flag.StringVar(&options.Interface, "interface", "", "Network Interface to use for port scan")
	flag.BoolVar(&options.Privileged, "privileged", false, "Attempts to run as root - Use sudo if possible")
	flag.BoolVar(&options.Unprivileged, "unprivileged", false, "Drop root privileges")
	flag.BoolVar(&options.ExcludeCDN, "exclude-cdn", false, "Sikp full port scans for CDNs (only checks for 80,443)")
	flag.IntVar(&options.WarmUpTime, "warm-up-time", 2, "Time in seconds between scan phases")
	flag.BoolVar(&options.InterfacesList, "interface-list", false, "List available interfaces and public ip")
	flag.StringVar(&options.ConfigFile, "config", "", "Config file")
	flag.BoolVar(&options.Nmap, "nmap", false, "Invoke nmap scan on targets (nmap must be installed)")
	flag.StringVar(&options.NmapCLI, "nmap-cli", "", "Nmap command line (invoked as COMMAND + TARGETS)")
	flag.IntVar(&options.Threads, "c", 25, "General internal worker threads")

	flag.Parse()

	// Check if stdin pipe was given
	options.Stdin = hasStdin()

	// Read the inputs and configure the logging
	options.configureOutput()

	// Show the user the banner
	showBanner()

	// write default conf file template if it doesn't exist
	options.writeDefaultConfig()

	if options.Version {
		gologger.Infof("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// Show network configuration and exit if the user requested it
	if options.InterfacesList {
		err := showNetworkInterfaces()
		if err != nil {
			gologger.Errorf("Could not get network interfaces: %s\n", err)
		}
		os.Exit(0)
	}

	// If a config file is provided, merge the options
	if options.ConfigFile != "" {
		options.MergeFromConfig(options.ConfigFile, false)
	} else {
		defaultConfigPath, err := getDefaultConfigFile()
		if err != nil {
			gologger.Errorf("Program exiting: %s\n", err)
		}
		options.MergeFromConfig(defaultConfigPath, true)
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
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}

func (options *Options) MergeFromConfig(configFileName string, ignoreError bool) {
	configFile, err := UnmarshalRead(configFileName)
	if err != nil {
		if ignoreError {
			gologger.Warningf("Could not read configuration file %s: %s\n", configFileName, err)
			return
		}
		gologger.Fatalf("Could not read configuration file %s: %s\n", configFileName, err)
	}
	options.config = &configFile

	if configFile.Retries > 0 {
		options.Retries = configFile.Retries
	}
	if configFile.Rate > 0 {
		options.Rate = configFile.Rate
	}
	if configFile.Timeout > 0 {
		options.Timeout = configFile.Timeout
	}
	options.Verify = configFile.Verify
	options.Ping = configFile.Ping
	if configFile.TopPorts != "" {
		options.TopPorts = configFile.TopPorts
	}
	options.Privileged = configFile.Privileged
	options.Unprivileged = configFile.Unprivileged
	options.ExcludeCDN = configFile.ExcludeCDN
	if configFile.SourceIP != "" {
		options.SourceIP = configFile.SourceIP
	}
	if configFile.Interface != "" {
		options.Interface = configFile.Interface
	}
	if configFile.WarmUpTime > 0 {
		options.WarmUpTime = configFile.WarmUpTime
	}
}
