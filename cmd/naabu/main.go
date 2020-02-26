package main

import (
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/pkg/runner"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	if os.Geteuid() > 0 {
		gologger.Fatalf("Exiting, You must be a privileged user to run this scan\n")
	}

	runner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatalf("Could not create runner: %s\n", err)
	}

	err = runner.RunEnumeration()
	if err != nil {
		gologger.Fatalf("Could not run enumeration: %s\n", err)
	}
}
