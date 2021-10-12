package runner

import (
	"os"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

// Options contains the configuration options for tuning
// the port enumeration process.
// nolint:maligned // just an option structure
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
	ExcludeCDN     bool // Excludes ip of knows CDN ranges for full port scan
	Nmap           bool // Invoke nmap detailed scan on results
	InterfacesList bool // InterfacesList show interfaces list

	Retries           int    // Retries is the number of retries for the port
	Rate              int    // Rate is the rate of port scan requests
	Timeout           int    // Timeout is the seconds to wait for ports to respond
	WarmUpTime        int    // WarmUpTime between scan phases
	Host              string // Host is the host to find ports for
	HostsFile         string // HostsFile is the file containing list of hosts to find port for
	Output            string // Output is the file to write found ports to.
	Ports             string // Ports is the ports to use for enumeration
	PortsFile         string // PortsFile is the file containing ports to use for enumeration
	ExcludePorts      string // ExcludePorts is the list of ports to exclude from enumeration
	ExcludeIps        string // Ips or cidr to be excluded from the scan
	ExcludeIpsFile    string // File containing Ips or cidr to exclude from the scan
	TopPorts          string // Tops ports to scan
	SourceIP          string // SourceIP to use in TCP packets
	Interface         string // Interface to use for TCP packets
	ConfigFile        string // Config file contains a scan configuration
	NmapCLI           string // Nmap command (has priority over config file)
	Threads           int    // Internal worker threads
	EnableProgressBar bool   // Enable progress bar
	ScanAllIPS        bool   // Scan all the ips
	ScanType          string // Scan Type
	Resolvers         string // Resolvers (comma separated or file)
	baseResolvers     []string
	OnResult          OnResultCallback // OnResult callback
}

// OnResultCallback (hostname, ip, ports)
type OnResultCallback func(string, string, []int)

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Naabu is a port scanning tool written in Go that allows you to enumerate open ports for hosts in a fast and reliable manner.`)

	createGroup(flagSet, "input", "Input",
		flagSet.StringVar(&options.Host, "host", "", "Host to scan ports for"),
		flagSet.StringVarP(&options.HostsFile, "l", "list", "", "File containing list of hosts to scan ports"),
		flagSet.StringVarP(&options.ExcludeIps, "eh", "exclude-hosts", "", "Specifies a comma-separated list of targets to be excluded from the scan (ip, cidr)"),
		flagSet.StringVarP(&options.ExcludeIpsFile, "ef", "exclude-file", "", "Specifies a newline-delimited file with targets to be excluded from the scan (ip, cidr)"),
	)

	createGroup(flagSet, "port", "Port",
		flagSet.StringVarP(&options.Ports, "p", "port", "", "Ports to scan (80, 80,443, 100-200"),
		flagSet.StringVarP(&options.TopPorts, "tp", "top-ports", "", "Top Ports to scan (default top 100)"),
		flagSet.StringVarP(&options.ExcludePorts, "ep", "exclude-ports", "", "Ports to exclude from scan"),
		flagSet.StringVarP(&options.PortsFile, "pf", "ports-file", "", "File containing ports to scan for"),
		flagSet.BoolVarP(&options.ExcludeCDN, "ec", "exclude-cdn", false, "Skip full port scans for CDNs (only checks for 80,443)"),
	)

	createGroup(flagSet, "rate-limit", "Rate-limit",
		flagSet.IntVar(&options.Threads, "c", 25, "General internal worker threads"),
		flagSet.IntVar(&options.Rate, "rate", DefaultRateSynScan, "Rate of port scan probe request"),
	)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "File to write output to (optional)"),
		flagSet.BoolVar(&options.JSON, "json", false, "Write output in JSON lines Format"),
	)

	createGroup(flagSet, "config", "Configuration",
		flagSet.BoolVar(&options.ScanAllIPS, "scan-all-ips", false, "Scan all the ips"),
		flagSet.StringVarP(&options.ScanType, "s", "scan-type", SynScan, "Port scan type (SYN/CONNECT)"),
		flagSet.StringVar(&options.SourceIP, "source-ip", "", "Source Ip"),
		flagSet.BoolVarP(&options.InterfacesList, "il", "interface-list", false, "List available interfaces and public ip"),
		flagSet.StringVarP(&options.Interface, "i", "interface", "", "Network Interface to use for port scan"),
		flagSet.BoolVar(&options.Nmap, "nmap", false, "Invoke nmap scan on targets (nmap must be installed) - Deprecated"),
		flagSet.StringVar(&options.NmapCLI, "nmap-cli", "", "nmap command to run on found results (example: -nmap-cli 'nmap -sV')"),
		flagSet.StringVar(&options.Resolvers, "r", "", "Custom resolvers to use to resolve DNS names (comma separated or from file)"),
	)

	createGroup(flagSet, "optimization", "Optimization",
		flagSet.IntVar(&options.Retries, "retries", DefaultRetriesSynScan, "Number of retries for the port scan probe"),
		flagSet.IntVar(&options.Timeout, "timeout", DefaultPortTimeoutSynScan, "Millisecond to wait before timing out"),
		flagSet.IntVar(&options.WarmUpTime, "warm-up-time", 2, "Time in seconds between scan phases"),
		flagSet.BoolVar(&options.Ping, "ping", false, "Use ping probes for verification of host"),
		flagSet.BoolVar(&options.Verify, "verify", false, "Validate the ports again with TCP verification"),
	)

	createGroup(flagSet, "debug", "Debug",
		flagSet.BoolVar(&options.Debug, "debug", false, "Enable debugging information"),
		flagSet.BoolVar(&options.Verbose, "v", false, "Show Verbose output"),
		flagSet.BoolVarP(&options.NoColor, "nc", "no-color", false, "Don't Use colors in output"),
		flagSet.BoolVar(&options.Silent, "silent", false, "Show found ports only in output"),
		flagSet.BoolVar(&options.Version, "version", false, "Show version of naabu"),
		flagSet.BoolVar(&options.EnableProgressBar, "stats", false, "Display stats of the running scan"),
	)

	_ = flagSet.Parse()

	// Check if stdin pipe was given
	options.Stdin = hasStdin()

	// Read the inputs and configure the logging
	options.configureOutput()

	// Show the user the banner
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// Show network configuration and exit if the user requested it
	if options.InterfacesList {
		err := showNetworkInterfaces()
		if err != nil {
			gologger.Error().Msgf("Could not get network interfaces: %s\n", err)
		}
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	showNetworkCapabilities(options)

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

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
