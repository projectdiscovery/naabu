//go:build linux

package routing

import (
	"net"

	"github.com/google/gopacket/routing"
)

// New creates a https://github.com/google/gopacket instance for Linux
func New() (Router, error) {
	router, err := routing.New()
	if err != nil {
		return nil, err
	}
	return RouterLinux{router: router}, nil
}

type RouterLinux struct {
	router routing.Router
}

func (r RouterLinux) Route(dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	return r.router.Route(dst)
}

func (r RouterLinux) RouteWithSrc(input net.HardwareAddr, src, dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	return r.router.RouteWithSrc(input, src, dst)
}
