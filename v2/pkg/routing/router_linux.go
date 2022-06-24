//go:build linux

package routing

import (
	"github.com/google/gopacket/routing"
)

// New creates a https://github.com/google/gopacket instance
func New() (Router, error) {
	return routing.New()
}
