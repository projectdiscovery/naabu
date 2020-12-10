// +build linux darwin

package runner

import (
	"fmt"
	"net"
)

func (r *Runner) SetSourceIPAndInterface() error {
	if r.options.SourceIP != "" && r.options.Interface != "" {
		r.scanner.SourceIP = net.ParseIP(r.options.SourceIP)
		if r.options.Interface != "" {
			var err error
			r.scanner.NetworkInterface, err = net.InterfaceByName(r.options.Interface)
			if err != nil {
				return err
			}
		}
	}

	return fmt.Errorf("source Ip and Interface not specified")
}
