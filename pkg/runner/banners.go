package runner

import (
	"net"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/pkg/runas"
	"github.com/projectdiscovery/naabu/pkg/scan"
)

const banner = `
                  __       
  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/ v2.0.0				 
`

// Version is the current version of naabu
const Version = `2.0.0`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Printf("%s\n", banner)
	gologger.Printf("\t\tprojectdiscovery.io\n\n")

	gologger.Labelf("Use with caution. You are responsible for your actions\n")
	gologger.Labelf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}

// showNetworkCapabilities shows the network capabilities/scan types possible with the running user
func showNetworkCapabilities() {
	accessLevel := "not root"
	scanType := "Connect (Full Handshake)"
	if isRoot() {
		accessLevel = "root"
		scanType = "TCP/ICMP Probes + Syn Scan"
	}
	gologger.Infof("Access Level: %s\n", accessLevel)
	gologger.Infof("Scan Type: %s\n", scanType)
}

func showNetworkInterfaces() error {
	// Interfaces List
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, itf := range interfaces {
		addresses, err := itf.Addrs()
		if err != nil {
			gologger.Warningf("Could not retrieve addresses for %s: %s\n", itf.Name, err)
			continue
		}
		var addrstr []string
		for _, address := range addresses {
			addrstr = append(addrstr, address.String())
		}
		gologger.Infof("Interface %s:\nMAC: %s\nAddresses: %s\nMTU: %d\nFlags: %s\n", itf.Name, itf.HardwareAddr, strings.Join(addrstr, " "), itf.MTU, itf.Flags.String())
	}
	// External ip
	externalIP, err := scan.WhatsMyIP()
	if err != nil {
		gologger.Warningf("Could not obtain public ip: %s\n", err)
	}
	gologger.Infof("External Ip: %s\n", externalIP)

	return nil
}

func handlePrivileges(options *Options) error {
	if options.Privileged {
		return runas.Root()
	}

	if options.Unprivileged {
		return runas.Nobody()
	}

	return nil
}
