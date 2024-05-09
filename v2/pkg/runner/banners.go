package runner

import (
	"net"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	osutil "github.com/projectdiscovery/utils/os"
	updateutils "github.com/projectdiscovery/utils/update"
)

const banner = `
                  __
  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/
`

// Version is the current version of naabu
const version = `2.3.1`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// showNetworkCapabilities shows the network capabilities/scan types possible with the running user
func showNetworkCapabilities(options *Options) {
	var accessLevel, scanType string

	switch {
	case privileges.IsPrivileged && options.ScanType == SynScan:
		accessLevel = "root"
		if osutil.IsLinux() {
			accessLevel = "CAP_NET_RAW"
		}
		scanType = "SYN"
	case options.Passive:
		accessLevel = "non root"
		scanType = "PASSIVE"
	default:
		accessLevel = "non root"
		scanType = "CONNECT"
	}

	switch {
	case options.OnlyHostDiscovery:
		scanType = "Host Discovery"
		gologger.Info().Msgf("Running %s\n", scanType)
	case options.Passive:
		scanType = "PASSIVE"
		gologger.Info().Msgf("Running %s scan\n", scanType)
	default:
		gologger.Info().Msgf("Running %s scan with %s privileges\n", scanType, accessLevel)
	}
}

func showHostDiscoveryInfo() {
	gologger.Info().Msgf("Running host discovery scan\n")
}

func showNetworkInterfaces() error {
	// Interfaces List
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, itf := range interfaces {
		addresses, addErr := itf.Addrs()
		if addErr != nil {
			gologger.Warning().Msgf("Could not retrieve addresses for %s: %s\n", itf.Name, addErr)
			continue
		}
		var addrstr []string
		for _, address := range addresses {
			addrstr = append(addrstr, address.String())
		}
		gologger.Info().Msgf("Interface %s:\nMAC: %s\nAddresses: %s\nMTU: %d\nFlags: %s\n", itf.Name, itf.HardwareAddr, strings.Join(addrstr, " "), itf.MTU, itf.Flags.String())
	}
	// External ip
	externalIP, err := scan.WhatsMyIP()
	if err != nil {
		gologger.Warning().Msgf("Could not obtain public ip: %s\n", err)
	}
	gologger.Info().Msgf("External Ip: %s\n", externalIP)

	return nil
}

// GetUpdateCallback returns a callback function that updates naabu
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("naabu", version)()
	}
}