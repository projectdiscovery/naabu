//go:build linux

package scan

import (
	"net"

	"github.com/google/gopacket/routing"
	"github.com/pkg/errors"
)

func newRouter() (Router, error) {
	return routing.New()
}
