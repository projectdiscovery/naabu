package port

import (
	"fmt"

	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

type Port struct {
	Port     int               `json:"port"`
	Protocol protocol.Protocol `json:"protocol"`
	// Deprecated: TLS field will be removed in a future version
	TLS     bool    `json:"tls"`
	Service Service `json:"service"`
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%d-%v", p.Port, p.Protocol, p.TLS)
}

type Service struct {
	DeviceType  string `json:"device_type"`
	ExtraInfo   string `json:"extra_info"`
	HighVersion string `json:"high_version"`
	Hostname    string `json:"hostname"`
	LowVersion  string `json:"low_version"`
	Method      string `json:"method"`
	Name        string `json:"name"`
	OSType      string `json:"os_type"`
	Product     string `json:"product"`
	Proto       string `json:"proto"`
	RPCNum      string `json:"rpc_num"`
	ServiceFP   string `json:"service_fp"`
	Tunnel      string `json:"tunnel"`
	Version     string `json:"version"`
	Confidence  int    `json:"confidence"`
}

func (s *Service) String() string {
	return s.Name
}
