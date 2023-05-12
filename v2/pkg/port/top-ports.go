package port

import (
	_ "embed"
	"encoding/json"

	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

var (
	AllTopPorts []*Port
	TopTcpPorts []*Port
	TopUdpPorts []*Port
)

//go:embed top-ports.json
var topPortsData []byte

func init() {
	err := json.Unmarshal(topPortsData, &AllTopPorts)
	if err != nil {
		panic(err)
	}
	for _, p := range AllTopPorts {
		switch p.Protocol {
		case protocol.TCP:
			TopTcpPorts = append(TopTcpPorts, p)
		case protocol.UDP:
			TopUdpPorts = append(TopUdpPorts, p)
		}
	}
}
