//go:build darwin

package scan

import (
	"net"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
)

func newRouter() (Router, error) {
	srcIP4, err := GetSourceIP("8.8.8.8")
	if err != nil {
		return nil, err
	}

	// ignores errors on ipv6 routing
	srcIP6, err := GetSourceIP("2001:4860:4860::8888")
	if err != nil {
		gologger.Warning().Msgf("couldn't determine ipv6 routing interface: %s\n", err)
	}

	return &RouterDarwin{SourceIP4: srcIP4, SourceIP6: srcIP6}, nil
}

type RouterDarwin struct {
	SourceIP4 net.IP
	SourceIP6 net.IP
}

func (r *RouterDarwin) Route(dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	switch {
	case dst.To4() != nil:
		return nil, nil, r.SourceIP4, nil
	case dst.To16() != nil:
		return nil, nil, r.SourceIP6, nil
	}
	return nil, nil, nil, errors.New("could not find route")
}

func (r *RouterDarwin) RouteWithSrc(input net.HardwareAddr, src, dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	return nil, nil, nil, errors.New("not implemented")
}
