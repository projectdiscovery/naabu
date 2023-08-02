package port

import (
	"fmt"

	"github.com/Mzack9999/naabu/v2/pkg/protocol"
)

type Port struct {
	Port     int
	Protocol protocol.Protocol
	TLS      bool
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%d-%v", p.Port, p.Protocol, p.TLS)
}
