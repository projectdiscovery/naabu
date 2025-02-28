package protocol

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
