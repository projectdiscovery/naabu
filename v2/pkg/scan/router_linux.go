//go:build linux

package scan

import (
	"github.com/google/gopacket/routing"
)

func newRouter() (Router, error) {
	return routing.New()
}
