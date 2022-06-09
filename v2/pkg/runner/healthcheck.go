package runner

import (
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/folderutil"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
)

func DoHealthCheck(options *Options) string {
	// RW permissions on config file
	cfgFilePath := filepath.Join(folderutil.HomeDirOrDefault("$home"), ".config/naabu/config.yaml")
	var test strings.Builder
	test.WriteString(fmt.Sprintf("Version: %s\n", Version))
	test.WriteString(fmt.Sprintf("Operative System: %s\n", runtime.GOOS))
	test.WriteString(fmt.Sprintf("Architecture: %s\n", runtime.GOARCH))

	var testResult string
	if privileges.IsPrivileged {
		testResult = "Ok"
	} else {
		testResult = "Ko"
	}
	test.WriteString(fmt.Sprintf("Privileged/NET_RAW: %s\n", testResult))

	ok, err := fileutil.IsReadable(cfgFilePath)
	if ok {
		testResult = "Ok"
	} else {
		testResult = "Ko"
	}
	if err != nil {
		testResult += fmt.Sprintf(" (%s)", err)
	}
	test.WriteString(fmt.Sprintf("Config file \"%s\" Read => %s\n", cfgFilePath, testResult))
	ok, err = fileutil.IsWriteable(cfgFilePath)
	if ok {
		testResult = "Ok"
	} else {
		testResult = "Ko"
	}
	if err != nil {
		testResult += fmt.Sprintf(" (%s)", err)
	}
	test.WriteString(fmt.Sprintf("Config file \"%s\" Write => %s\n", cfgFilePath, testResult))
	c4, err := net.Dial("tcp4", "scanme.sh:80")
	if err == nil && c4 != nil {
		c4.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("IPv4 connectivity to scanme.sh:80 => %s\n", testResult))
	c6, err := net.Dial("tcp6", "scanme.sh:80")
	if err == nil && c6 != nil {
		c6.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("IPv6 connectivity to scanme.sh:80 => %s\n", testResult))

	return test.String()
}
