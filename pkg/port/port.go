package port

import (
	"fmt"

	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

type Port struct {
	Port     int               `json:"port"`
	Protocol protocol.Protocol `json:"protocol"`
	
	// Deprecated: TLS field will be removed in a future version
	TLS      bool              `json:"tls"`
	Service  *Service          `json:"service,omitempty"`
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%s-%v", p.Port, p.Protocol.String(), p.TLS)
}

type Service struct {
	DeviceType  string `json:"device_type,omitempty"`
	ExtraInfo   string `json:"extra_info,omitempty"`
	HighVersion string `json:"high_version,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	LowVersion  string `json:"low_version,omitempty"`
	Method      string `json:"method,omitempty"`
	Name        string `json:"name,omitempty"`
	OSType      string `json:"os_type,omitempty"`
	Product     string `json:"product,omitempty"`
	Proto       string `json:"proto,omitempty"`
	RPCNum      string `json:"rpc_num,omitempty"`
	ServiceFP   string `json:"service_fp,omitempty"`
	Tunnel      string `json:"tunnel,omitempty"`
	Version     string `json:"version,omitempty"`
	Confidence  int    `json:"confidence,omitempty"`
}

func (s *Service) String() string {
	return s.Name
}
