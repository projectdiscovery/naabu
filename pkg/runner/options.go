package runner

import (
	"flag"
	"os"

	"github.com/projectdiscovery/naabu/pkg/log"
)

// Options contains the configuration options for tuning
// the port enumeration process.
type Options struct {
	Retries         int    // Retries is the number of retries for the port
	Rate            int    // Rate is the rate of port scan requests
	Verbose         bool   // Verbose flag indicates whether to show verbose output or not
	NoColor         bool   // No-Color disables the colored output
	Threads         int    // Thread controls the number of parallel host to enumerate
	Timeout         int    // Timeout is the seconds to wait for ports to respond
	Host            string // Host is the host to find ports for
	HostsFile       string // HostsFile is the file containing list of hosts to find port for
	Output          string // Output is the file to write found ports to.
	OutputDirectory string // OutputDirectory is the directory to write results to in case list of hosts is given
	JSON            bool   // JSON specifies whether to use json for output format or text file
	Silent          bool   // Silent suppresses any extra text and only writes found host:port to screen
	Ports           string // Ports is the ports to use for enumeration
	PortsFile       string // PortsFile is the file containing ports to use for enumeration
	ExcludePorts    string // ExcludePorts is the list of ports to exclude from enumeration
	Stdin           bool   // Stdin specifies whether stdin input was given to the process
	Verify          bool   // Verify is used to check if the ports found were valid using CONNECT method
	Version         bool   // Version specifies if we should just show version and exit
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

	flag.IntVar(&options.Retries, "retries", 1, "Number of retries for the port scan probe")
	flag.IntVar(&options.Rate, "rate", 1000, "Rate of port scan probe requests")
	flag.BoolVar(&options.Verbose, "v", false, "Show Verbose output")
	flag.BoolVar(&options.NoColor, "nC", false, "Don't Use colors in output")
	flag.IntVar(&options.Threads, "t", 10, "Number of concurrent goroutines for resolving")
	flag.IntVar(&options.Timeout, "timeout", 700, "Millisecond to wait before timing out")
	flag.StringVar(&options.Host, "host", "", "Host to find ports for")
	flag.StringVar(&options.HostsFile, "hL", "", "File containing list of hosts to enumerate ports")
	flag.StringVar(&options.Output, "o", "", "File to write output to (optional)")
	flag.StringVar(&options.OutputDirectory, "oD", "", "Directory to write enumeration results to (optional)")
	flag.BoolVar(&options.JSON, "oJ", false, "Write output in JSON lines Format")
	flag.BoolVar(&options.Silent, "silent", false, "Show only host:ports in output")
	flag.StringVar(&options.Ports, "ports", "", "Ports to enumerate for on hosts (top-100, top-1000, full, custom)")
	flag.StringVar(&options.PortsFile, "ports-file", "", "File containing ports to enumerate for on hosts")
	flag.StringVar(&options.ExcludePorts, "exclude-ports", "", "Ports to exclude from enumeration")
	flag.BoolVar(&options.Verify, "verify", false, "Validate the ports again")
	flag.BoolVar(&options.Version, "version", false, "Show version of naabu")
	flag.Parse()

	// Check if stdin pipe was given
	options.Stdin = hasStdin()

	// Read the inputs and configure the logging
	options.configureOutput()

	// Show the user the banner
	showBanner()

	if options.Version {
		log.Infof("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.validateOptions()
	if err != nil {
		log.Fatalf("Program exiting: %s\n", err)
	}

	return options
}

func hasStdin() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		return false
	}
	return true
}
