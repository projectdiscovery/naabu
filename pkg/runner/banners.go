package runner

import (
	"github.com/projectdiscovery/naabu/pkg/log"
)

const banner = `
                  __       
  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/ v1				 
`

// Version is the current version of naabu
const Version = `1.0.1`

// showBanner is used to show the banner to the user
func showBanner() {
	log.Printf("%s\n", banner)
	log.Printf("\t\tprojectdiscovery.io\n\n")

	log.Labelf("Use with caution. You are responsible for your actions\n")
	log.Labelf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}
