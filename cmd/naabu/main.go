package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	// Setup context with cancelation
	ctx, cancel := context.WithCancel(context.Background())

	// Setup signal handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-c
		gologger.Info().Msgf("Received signal: %s, exiting gracefully...\n", sig)

		// Cancel context to stop ongoing tasks
		cancel()

		// Try to save resume config if needed
		if options.ResumeCfg != nil && options.ResumeCfg.ShouldSaveResume() {
			gologger.Info().Msgf("Creating resume file: %s\n", runner.DefaultResumeFilePath())
			if err := options.ResumeCfg.SaveResumeConfig(); err != nil {
				gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
			}
		}

		// Show scan result if runner is available
		if naabuRunner != nil {
			naabuRunner.ShowScanResultOnExit()

			if err := naabuRunner.Close(); err != nil {
				gologger.Error().Msgf("Couldn't close runner: %s\n", err)
			}
		}

		// Final flush if gologger has a Close method (placeholder if exists)
		// Example: gologger.Close()

		os.Exit(1)
	}()

	// Start enumeration
	if err := naabuRunner.RunEnumeration(ctx); err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}

	// On successful execution, cleanup resume config if needed
	if options.ResumeCfg != nil {
		options.ResumeCfg.CleanupResumeConfig()
	}
}
