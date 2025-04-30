package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/user"
	"time"

	"github.com/armon/go-socks5"
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
	"sdk - connect with proxy":            &naabuWithSocks5{},
}

type naabuPassiveSingleLibrary struct {
}

func (h *naabuPassiveSingleLibrary) Execute() error {
	testFile := "test.txt"
	err := os.WriteFile(testFile, []byte("scanme.sh"), 0644)
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(testFile); err != nil {
			log.Printf("could not remove test file: %s\n", err)
		}
	}()

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
	defer func() {
		if err := naabuRunner.Close(); err != nil {
			log.Printf("could not close naabu runner: %s\n", err)
		}
	}()

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
	defer func() {
		if err := os.RemoveAll(testFile); err != nil {
			log.Printf("could not remove test file: %s\n", err)
		}
	}()

	var got bool

	options := runner.Options{
		HostsFile: testFile,
		Ports:     "80",
		ScanType:  h.scanType,
		OnResult: func(hr *result.HostResult) {
			got = true
		},
		WarmUpTime: 2,
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		return err
	}
	defer func() {
		if err := naabuRunner.Close(); err != nil {
			log.Printf("could not close naabu runner: %s\n", err)
		}
	}()

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
	defer func() {
		if err := os.RemoveAll(testFile); err != nil {
			log.Printf("could not remove test file: %s\n", err)
		}
	}()

	var got bool

	options := runner.Options{
		HostsFile: testFile,
		Ports:     "80",
		ScanType:  h.scanType,
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
		if err := naabuRunner.Close(); err != nil {
			log.Printf("could not close naabu runner: %s\n", err)
		}
	}
	return nil
}

type naabuWithSocks5 struct{}

func (h *naabuWithSocks5) Execute() error {
	// Start local SOCKS5 proxy server with test:test credentials
	conf := &socks5.Config{
		Credentials: socks5.StaticCredentials{
			"test": "test",
		},
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}
	go func() {
		if err = server.ListenAndServe("tcp", "127.0.0.1:38401"); err != nil {
			panic(err)
		}
	}()

	testFile := "test.txt"
	err = os.WriteFile(testFile, []byte("scanme.sh"), 0644)
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(testFile); err != nil {
			log.Printf("could not remove test file: %s\n", err)
		}
	}()

	var got bool

	options := runner.Options{
		HostsFile: testFile,
		Ports:     "80",
		ScanType:  "c",
		Proxy:     "127.0.0.1:38401",
		ProxyAuth: "test:test",
		OnResult: func(hr *result.HostResult) {
			got = true
		},
		WarmUpTime: 2,
		Timeout:    10 * time.Second,
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		return err
	}
	defer func() {
		if err := naabuRunner.Close(); err != nil {
			log.Printf("could not close naabu runner: %s\n", err)
		}
	}()

	if err = naabuRunner.RunEnumeration(context.TODO()); err != nil {
		return err
	}
	if !got {
		return errors.New("no results found")
	}

	return nil
}
