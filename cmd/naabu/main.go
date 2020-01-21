package main

import (
	"os"

	"github.com/projectdiscovery/naabu/pkg/log"
	"github.com/projectdiscovery/naabu/pkg/runner"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	if os.Geteuid() > 0 {
		log.Fatalf("Exiting, You must be a privileged user to run this scan\n")
	}

	runner, err := runner.NewRunner(options)
	if err != nil {
		log.Fatalf("Could not create runner: %s\n", err)
	}

	err = runner.RunEnumeration()
	if err != nil {
		log.Fatalf("Could not run enumeration: %s\n", err)
	}
}
