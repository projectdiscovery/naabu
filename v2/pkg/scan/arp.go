package scan

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/projectdiscovery/gologger"
)

func init() {
	arpRequestAsyncCallback = ArpRequestAsync
}

// ArpRequestAsync asynchronous to the target ip address
func ArpRequestAsync(s *Scanner, ip string) {
	// network layers
	eth := layers.Ethernet{
		SrcMAC:       s.NetworkInterface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.NetworkInterface.HardwareAddr),
		SourceProtAddress: s.SourceIP4.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    net.ParseIP(ip).To4(),
	}

	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err != nil {
		gologger.Warning().Msgf("%s\n", err)
		return
	}
	// send the packet out on every interface
	handlers := s.handlers.(Handlers)
	for _, handler := range handlers.EthernetActive {
		err := handler.WritePacketData(buf.Bytes())
		if err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	}
}
