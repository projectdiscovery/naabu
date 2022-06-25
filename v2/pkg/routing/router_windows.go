//go:build windows

package routing

import (
	"bufio"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/executil"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/sliceutil"
	"github.com/projectdiscovery/stringsutil"
)

// New creates a routing engine for windows
func New() (Router, error) {
	return nil, errors.New("not implemented")
}

type RouterWindows struct {
	Routes []*Route
}

func (r *RouterWindows) Route(dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	return nil, nil, nil, errors.New("not implemented")
}

func (r *RouterDarwin) RouteWithSrc(input net.HardwareAddr, src, dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error) {
	return nil, nil, nil, errors.New("not implemented")
}
