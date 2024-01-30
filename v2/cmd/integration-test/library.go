package main

import (
	"context"
	"errors"
	"os"

	"github.com/projectdiscovery/naabu/v2/internal/testutils"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

var libraryTestcases = map[string]testutils.TestCase{
	"sdk - one passive execution": &naabuPassiveSingleLibrary{},
	"sdk - one execution":         &naabuSingleLibrary{},
	"sdk - multiple executions":   &naabuMultipleExecLibrary{},
}

type naabuPassiveSingleLibrary struct {
}

func (h *naabuPassiveSingleLibrary) Execute() error {
	testFile := "test.txt"
	err := os.WriteFile(testFile, []byte("scanme.sh"), 0644)
	if err != nil {
		return err
	}
	defer os.RemoveAll(testFile)

	options := runner.Options{
		HostsFile: testFile,
		Ports:     "80",
		Passive:   true,
		OnResult:  func(hr *result.HostResult) {},
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		return err
	}
	defer naabuRunner.Close()

	return naabuRunner.RunEnumeration(context.TODO())
}

type naabuSingleLibrary struct {
}

func (h *naabuSingleLibrary) Execute() error {
	testFile := "test.txt"
	err := os.WriteFile(testFile, []byte("scanme.sh"), 0644)
	if err != nil {
		return err
	}
	defer os.RemoveAll(testFile)

	var got bool

	options := runner.Options{
		HostsFile: testFile,
		Ports:     "80",
		OnResult: func(hr *result.HostResult) {
			got = true
		},
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		return err
	}
	defer naabuRunner.Close()

	if err = naabuRunner.RunEnumeration(context.TODO()); err != nil {
		return err
	}
	if !got {
		return errors.New("no results found")
	}

	return nil
}

type naabuMultipleExecLibrary struct {
}

func (h *naabuMultipleExecLibrary) Execute() error {
	testFile := "test.txt"
	err := os.WriteFile(testFile, []byte("scanme.sh"), 0644)
	if err != nil {
		return err
	}
	defer os.RemoveAll(testFile)

	var got bool

	options := runner.Options{
		HostsFile: testFile,
		Ports:     "80",
		OnResult: func(hr *result.HostResult) {
			got = true
		},
	}

	for i := 0; i < 25; i++ {
		naabuRunner, err := runner.NewRunner(&options)
		if err != nil {
			return err
		}

		if err = naabuRunner.RunEnumeration(context.TODO()); err != nil {
			return err
		}
		if !got {
			return errors.New("no results found")
		}
		naabuRunner.Close()
	}
	return nil
}
