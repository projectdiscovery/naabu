package main

import (
	"github.com/projectdiscovery/naabu/v2/internal/testutils"
)

var cliTestcases = map[string]testutils.TestCase{
	"cli with passive flag": &cliWithPassiveFlag{},
}

type cliWithPassiveFlag struct {
}

func (h *cliWithPassiveFlag) Execute() error {
	results, err := testutils.RunNaabuAndGetResults("projectdiscovery.io", false, "-ec", "-passive")
	if err != nil {
		return err
	}

	if len(results) <= 0 {
		return errIncorrectResultsCount(results)
	}

	return nil
}
