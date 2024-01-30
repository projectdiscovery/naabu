package main

import (
	"context"
	"errors"
	"os"
	"os/user"

	"github.com/projectdiscovery/naabu/v2/internal/testutils"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

var libraryTestcases = map[string]testutils.TestCase{
	"sdk - one passive execution":         &naabuPassiveSingleLibrary{},
	"sdk - one execution - connect":       &naabuSingleLibrary{scanType: "c"},
	"sdk - multiple executions - connect": &naabuMultipleExecLibrary{scanType: "c"},
	"sdk - one execution - syn":           &naabuSingleLibrary{scanType: "s"},
	"sdk - multiple executions - syn":     &naabuMultipleExecLibrary{scanType: "s"},
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
		HostsFile:         testFile,
		Ports:             "80",
		Passive:           true,
		SkipHostDiscovery: true,
		OnResult:          func(hr *result.HostResult) {},
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		return err
	}
	defer naabuRunner.Close()

	return naabuRunner.RunEnumeration(context.TODO())
}

type naabuSingleLibrary struct {
	scanType string
}

func (h *naabuSingleLibrary) Execute() error {
	if h.scanType == "s" && !privileges.IsPrivileged {
		usr, _ := user.Current()
		return errors.New("invalid user" + usr.Name)
	}

	testFile := "test.txt"
	err := os.WriteFile(testFile, []byte("scanme.sh"), 0644)
	if err != nil {
		return err
	}
	defer os.RemoveAll(testFile)

	var got bool

	options := runner.Options{
		HostsFile:         testFile,
		Ports:             "80",
		SkipHostDiscovery: true,
		ScanType:          h.scanType,
		OnResult: func(hr *result.HostResult) {
			got = true
		},
		WarmUpTime: 2,
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
	scanType string
}

func (h *naabuMultipleExecLibrary) Execute() error {
	if h.scanType == "s" && !privileges.IsPrivileged {
		usr, _ := user.Current()
		return errors.New("invalid user" + usr.Name)
	}

	testFile := "test.txt"
	err := os.WriteFile(testFile, []byte("scanme.sh"), 0644)
	if err != nil {
		return err
	}
	defer os.RemoveAll(testFile)

	var got bool

	options := runner.Options{
		HostsFile:         testFile,
		Ports:             "80",
		ScanType:          h.scanType,
		SkipHostDiscovery: true,
		OnResult: func(hr *result.HostResult) {
			got = true
		},
		WarmUpTime: 2,
	}

	for i := 0; i < 3; i++ {
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
