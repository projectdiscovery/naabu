package runner

import "github.com/projectdiscovery/gologger"

const banner = `
                  __       
  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/ v2				 
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

func handlePrivileges(options *Options) error {
	if options.Privileged {
		return Sudo()
	}

	if options.Unprivileged {
		return DropSudo()
	}

	return nil
}
