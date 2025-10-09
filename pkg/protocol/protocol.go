package protocol

import (
	"fmt"
)

type Protocol int

const (
	TCP Protocol = iota
	UDP
	ARP
)

func (p Protocol) String() string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	case ARP:
		return "arp"
	default:
		panic("uknown type")
	}
}

func ParseProtocol(s string) Protocol {
	switch s {
	case "tcp":
		return TCP
	case "udp":
		return UDP
	case "arp":
		return ARP
	default:
		panic("uknown type")
	}
}

func (p Protocol) MarshalJSON() ([]byte, error) {
	return []byte(`"` + p.String() + `"`), nil
}

func (p *Protocol) UnmarshalJSON(data []byte) error {
	// Remove quotes from string
	s := string(data)
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return fmt.Errorf("invalid protocol format: %s", s)
	}
	s = s[1 : len(s)-1]

	// Convert string to Protocol
	switch s {
	case "tcp":
		*p = TCP
	case "udp":
		*p = UDP
	case "arp":
		*p = ARP
	default:
		return fmt.Errorf("unknown protocol: %s", s)
	}
	return nil
}
