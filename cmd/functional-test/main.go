package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/naabu/v2/internal/testutils"
)

var (
	debug   = os.Getenv("DEBUG") == "true"
	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()
	errored = false

	mainNaabuBinary = flag.String("main", "", "Main Branch Naabu Binary")
	devNaabuBinary  = flag.String("dev", "", "Dev Branch Naabu Binary")
	testcases       = flag.String("testcases", "", "Test cases file for Naabu functional tests")
)

func main() {
	flag.Parse()

	if err := runFunctionalTests(); err != nil {
		log.Fatalf("Could not run functional tests: %s\n", err)
	}
	if errored {
		os.Exit(1)
	}
}

func runFunctionalTests() error {
	file, err := os.Open(*testcases)
	if err != nil {
		return errors.Wrap(err, "could not open test cases")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		if err := runIndividualTestCase(text); err != nil {
			errored = true
			fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, text, err)
		} else {
			fmt.Printf("%s Test \"%s\" passed!\n", success, text)
		}
	}
	return nil
}

func runIndividualTestCase(testcase string) error {
	parts := strings.Fields(testcase)

	var finalArgs []string
	var target string
	if len(parts) > 1 {
		finalArgs = parts[2:]
		target = parts[0]
	}
	mainOutput, err := testutils.RunNaabuBinaryAndGetResults(target, *mainNaabuBinary, debug, finalArgs)
	if err != nil {
		return errors.Wrap(err, "could not run naabu main test")
	}
	devOutput, err := testutils.RunNaabuBinaryAndGetResults(target, *devNaabuBinary, debug, finalArgs)
	if err != nil {
		return errors.Wrap(err, "could not run naabu dev test")
	}
	if len(mainOutput) == len(devOutput) {
		return nil
	}
	return fmt.Errorf("%s main is not equal to %s dev", mainOutput, devOutput)
}
