package main

import (
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatalf("Could not create runner: %s\n", err)
	}

	err = naabuRunner.RunEnumeration()
	if err != nil {
		gologger.Fatalf("Could not run enumeration: %s\n", err)
	}
}

// implement this
// https://github.com/robertdavidgraham/masscan/blob/1cb966862559effd5c585ac3a0ccd986a21f7c37/doc/algorithm.js
