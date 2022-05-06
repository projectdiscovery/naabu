package runner

import (
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"

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

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {
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
	if options.Verify && !options.Passive {
		return errors.New("verify not supported in stream active mode")
	}

	return nil
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}
