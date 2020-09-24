package runner

import (
	"errors"
	"flag"
	"fmt"
	"net"

	"github.com/projectdiscovery/gologger"
)

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {
	// Check if Host, list of domains, or stdin info was provided.
	// If none was provided, then return.
	if options.Host == "" && options.HostsFile == "" && !options.Stdin && len(flag.Args()) == 0 && (options.config != nil && len(options.config.Host) == 0) {
		return errors.New("no input list provided")
	}

	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}

	if options.Timeout == 0 {
		return errors.New("timeout cannot be zero")
	} else if !isRoot() && options.Timeout == DefaultPortTimeoutSynScan {
		options.Timeout = DefaultPortTimeoutConnectScan
	}

	if options.Rate == 0 {
		return errors.New("rate cannot be zero")
	} else if !isRoot() && options.Rate == DefaultRateSynScan {
		options.Rate = DefaultRateConnectScan
	}

	if !isRoot() && options.Retries == DefaultRetriesSynScan {
		options.Retries = DefaultRetriesConnectScan
	}

	if options.Interface != "" {
		if _, err := net.InterfaceByName(options.Interface); err != nil {
			return fmt.Errorf("interface %s not found", options.Interface)
		}
	}

	return nil
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.MaxLevel = gologger.Verbose
	}
	if options.NoColor {
		gologger.UseColors = false
	}
	if options.Silent {
		gologger.MaxLevel = gologger.Silent
	}
}
