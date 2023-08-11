//go:build linux || darwin

package scan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/projectdiscovery/freeport"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/routing"
	"golang.org/x/net/icmp"
)

func init() {
	newScannerCallback = NewScannerUnix
	setupHandlerCallback = SetupHandlerUnix
	tcpReadWorkerPCAPCallback = TransportReadWorkerPCAPUnix
	cleanupHandlersCallback = CleanupHandlersUnix
}

// Handlers contains the list of pcap handlers
type Handlers struct {
	TransportActive   []*pcap.Handle
	LoopbackHandlers  []*pcap.Handle
	TransportInactive []*pcap.InactiveHandle
	EthernetActive    []*pcap.Handle
	EthernetInactive  []*pcap.InactiveHandle
}

func getFreePort() (int, error) {
	rawPort, err := freeport.GetFreeTCPPort("")
	if err != nil {
		return 0, err
	}
	return rawPort.Port, nil
}

// NewScannerUnix creates a new instance specific for unix OS
func NewScannerUnix(scanner *Scanner) error {
	if scanner.SourcePort <= 0 {
		rawport, err := getFreePort()
		if err != nil {
			return err
		}
		scanner.SourcePort = rawport
	}

	tcpConn4, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.tcpPacketListener4 = tcpConn4

	udpConn4, err := net.ListenIP("ip4:udp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.udpPacketListener4 = udpConn4

	tcpConn6, err := net.ListenIP("ip6:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf(":::%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.tcpPacketListener6 = tcpConn6

	udpConn6, err := net.ListenIP("ip6:udp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf(":::%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.udpPacketListener6 = udpConn6

	var handlers Handlers
	scanner.handlers = handlers

	scanner.tcpChan = make(chan *PkgResult, chanSize)
	scanner.udpChan = make(chan *PkgResult, chanSize)
	scanner.transportPacketSend = make(chan *PkgSend, packetSendSize)

	icmpConn4, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	scanner.icmpPacketListener4 = icmpConn4

	icmpConn6, err := icmp.ListenPacket("ip6:icmp", "::")
	if err != nil {
		return err
	}
	scanner.icmpPacketListener6 = icmpConn6

	scanner.hostDiscoveryChan = make(chan *PkgResult, chanSize)
	scanner.icmpPacketSend = make(chan *PkgSend, packetSendSize)
	scanner.ethernetPacketSend = make(chan *PkgSend, packetSendSize)

	scanner.Router, err = routing.New()

	return err
}

// SetupHandlerUnix on unix OS
func SetupHandlerUnix(s *Scanner, interfaceName, bpfFilter string, protocols ...protocol.Protocol) error {
	for _, proto := range protocols {
		inactive, err := pcap.NewInactiveHandle(interfaceName)
		if err != nil {
			return err
		}

		err = inactive.SetSnapLen(snaplen)
		if err != nil {
			return err
		}

		readTimeout := time.Duration(readtimeout) * time.Millisecond
		if err = inactive.SetTimeout(readTimeout); err != nil {
			s.CleanupHandlers()
			return err
		}
		err = inactive.SetImmediateMode(true)
		if err != nil {
			return err
		}

		handlers, ok := s.handlers.(Handlers)
		if !ok {
			return errors.New("couldn't create handlers")
		}

		switch proto {
		case protocol.TCP, protocol.UDP:
			handlers.TransportInactive = append(handlers.TransportInactive, inactive)
		case protocol.ARP:
			handlers.EthernetInactive = append(handlers.EthernetInactive, inactive)
		default:
			panic("protocol not supported")
		}

		handle, err := inactive.Activate()
		if err != nil {
			s.CleanupHandlers()
			return err
		}

		// Strict BPF filter
		// + Destination port equals to sender socket source port
		err = handle.SetBPFFilter(bpfFilter)
		if err != nil {
			return err
		}
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return err
		}
		switch proto {
		case protocol.TCP, protocol.UDP:
			if iface.Flags&net.FlagLoopback == net.FlagLoopback {
				handlers.LoopbackHandlers = append(handlers.LoopbackHandlers, handle)
			} else {
				handlers.TransportActive = append(handlers.TransportActive, handle)
			}
		case protocol.ARP:
			handlers.EthernetActive = append(handlers.EthernetActive, handle)
		default:
			panic("protocol not supported")
		}
		s.handlers = handlers
	}

	return nil
}

// TransportReadWorkerPCAPUnix for TCP and UDP
func TransportReadWorkerPCAPUnix(s *Scanner) {
	defer s.CleanupHandlers()

	var wgread sync.WaitGroup

	handlers, ok := s.handlers.(Handlers)
	if !ok {
		return
	}

	transportReaderCallback := func(tcp layers.TCP, udp layers.UDP, ip, srcIP4, srcIP6 string) {
		// We consider only incoming packets
		tcpPortMatches := tcp.DstPort == layers.TCPPort(s.SourcePort)
		udpPortMatches := udp.DstPort == layers.UDPPort(s.SourcePort)
		sourcePortMatches := tcpPortMatches || udpPortMatches
		switch {
		case !sourcePortMatches:
			gologger.Debug().Msgf("Discarding Transport packet from non target ips: ip4=%s ip6=%s tcp_dport=%d udp_dport=%d\n", srcIP4, srcIP6, tcp.DstPort, udp.DstPort)

		case s.Phase.Is(HostDiscovery):
			proto := protocol.TCP
			if udpPortMatches {
				proto = protocol.UDP
			}
			s.hostDiscoveryChan <- &PkgResult{ip: ip, port: &port.Port{Port: int(tcp.SrcPort), Protocol: proto}}
		case tcpPortMatches && tcp.SYN && tcp.ACK:
			s.tcpChan <- &PkgResult{ip: ip, port: &port.Port{Port: int(tcp.SrcPort), Protocol: protocol.TCP}}
		case udpPortMatches && udp.Length > 0: // needs a better matching of udp payloads
			s.udpChan <- &PkgResult{ip: ip, port: &port.Port{Port: int(udp.SrcPort), Protocol: protocol.UDP}}
		}
	}

	// In case of OSX, when we decode the data from 'loO' interface
	// always get [Ethernet] layer only.
	// with the help of data received from packetSource.Packets() we can
	// extract the high level layers like [IPv4, IPv6, TCP, UDP]
	loopBackScanCaseCallback := func(handler *pcap.Handle, wg *sync.WaitGroup) {
		defer wg.Done()
		packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
		for packet := range packetSource.Packets() {
			tcp := &layers.TCP{}
			udp := &layers.UDP{}
			for _, layerType := range packet.Layers() {
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer == nil {
					ipLayer = packet.Layer(layers.LayerTypeIPv6)
					if ipLayer == nil {
						continue
					}
				}
				var srcIP4, srcIP6 string
				if ipv4, ok := ipLayer.(*layers.IPv4); ok {
					srcIP4 = ipv4.SrcIP.String()
				} else if ipv6, ok := ipLayer.(*layers.IPv6); ok {
					srcIP6 = ipv6.SrcIP.String()
				}

				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, ok = tcpLayer.(*layers.TCP)
					if !ok {
						continue
					}
				}
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, ok = udpLayer.(*layers.UDP)
					if !ok {
						continue
					}
				}

				if layerType.LayerType() == layers.LayerTypeTCP || layerType.LayerType() == layers.LayerTypeUDP {
					srcPort := fmt.Sprint(int(tcp.SrcPort))
					srcIP4WithPort := net.JoinHostPort(srcIP4, srcPort)
					isIP4InRange := s.IPRanger.ContainsAny(srcIP4, srcIP4WithPort)
					srcIP6WithPort := net.JoinHostPort(srcIP6, srcPort)
					isIP6InRange := s.IPRanger.ContainsAny(srcIP6, srcIP6WithPort)
					var ip string
					if isIP4InRange {
						ip = srcIP4
					} else if isIP6InRange {
						ip = srcIP6
					} else {
						gologger.Debug().Msgf("Discarding Transport packet from non target ips: ip4=%s ip6=%s\n", srcIP4, srcIP6)
					}
					transportReaderCallback(*tcp, *udp, ip, srcIP4, srcIP6)
				}
			}
		}
	}

	// Loopback Readers
	for _, handler := range handlers.LoopbackHandlers {
		wgread.Add(1)
		go loopBackScanCaseCallback(handler, &wgread)
	}

	// Transport Readers (TCP|UDP)
	for _, handler := range handlers.TransportActive {
		wgread.Add(1)
		go func(handler *pcap.Handle) {
			defer wgread.Done()

			var (
				eth layers.Ethernet
				ip4 layers.IPv4
				ip6 layers.IPv6
				tcp layers.TCP
				udp layers.UDP
			)

			// Interfaces with MAC (Physical + Virtualized)
			parser4Mac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp)
			parser6Mac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &tcp, &udp)
			// Interfaces without MAC (TUN/TAP)
			parser4NoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp, &udp)
			parser6NoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &tcp, &udp)

			var parsers []*gopacket.DecodingLayerParser
			parsers = append(parsers,
				parser4Mac, parser6Mac,
				parser4NoMac, parser6NoMac,
			)

			decoded := []gopacket.LayerType{}

			for {
				data, _, err := handler.ReadPacketData()
				if err == io.EOF {
					break
				} else if err != nil {
					continue
				}

				for _, parser := range parsers {
					err := parser.DecodeLayers(data, &decoded)
					if err != nil {
						continue
					}
					for _, layerType := range decoded {
						if layerType == layers.LayerTypeTCP || layerType == layers.LayerTypeUDP {
							srcPort := fmt.Sprint(int(tcp.SrcPort))
							srcIP4 := ip4.SrcIP.String()
							srcIP4WithPort := net.JoinHostPort(srcIP4, srcPort)
							isIP4InRange := s.IPRanger.ContainsAny(srcIP4, srcIP4WithPort)
							srcIP6 := ip6.SrcIP.String()
							srcIP6WithPort := net.JoinHostPort(srcIP6, srcPort)
							isIP6InRange := s.IPRanger.ContainsAny(srcIP6, srcIP6WithPort)
							var ip string
							if isIP4InRange {
								ip = srcIP4
							} else if isIP6InRange {
								ip = srcIP6
							} else {
								gologger.Debug().Msgf("Discarding Transport packet from non target ips: ip4=%s ip6=%s\n", srcIP4, srcIP6)
								continue
							}
							transportReaderCallback(tcp, udp, ip, srcIP4, srcIP6)
						}
					}
				}
			}
		}(handler)
	}

	// Ethernet Readers
	for _, handler := range handlers.EthernetActive {
		wgread.Add(1)
		go func(handler *pcap.Handle) {
			defer wgread.Done()

			var (
				eth layers.Ethernet
				arp layers.ARP
			)

			parser4 := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp)
			parser4.IgnoreUnsupported = true
			var parsers []*gopacket.DecodingLayerParser
			parsers = append(parsers, parser4)

			decoded := []gopacket.LayerType{}

			for {
				data, _, err := handler.ReadPacketData()
				if err == io.EOF {
					break
				} else if err != nil {
					continue
				}

				for _, parser := range parsers {
					err := parser.DecodeLayers(data, &decoded)
					if err != nil {
						continue
					}
					for _, layerType := range decoded {
						if layerType == layers.LayerTypeARP {
							// check if the packet was sent out
							isReply := arp.Operation == layers.ARPReply
							var sourceMacIsInterfaceMac bool
							if s.NetworkInterface != nil {
								sourceMacIsInterfaceMac = bytes.Equal([]byte(s.NetworkInterface.HardwareAddr), arp.SourceHwAddress)
							}
							isOutgoingPacket := !isReply || sourceMacIsInterfaceMac
							if isOutgoingPacket {
								continue
							}
							srcIP4 := net.IP(arp.SourceProtAddress)
							srcMac := net.HardwareAddr(arp.SourceHwAddress)

							isIP4InRange := s.IPRanger.Contains(srcIP4.String())

							var ip string
							if isIP4InRange {
								ip = srcIP4.String()
							} else {
								gologger.Debug().Msgf("Discarding ARP packet from non target ip: ip4=%s mac=%s\n", srcIP4, srcMac)
								continue
							}

							s.hostDiscoveryChan <- &PkgResult{ip: ip}
						}
					}
				}
			}
		}(handler)
	}

	wgread.Wait()
}

// CleanupHandlers for all interfaces
func CleanupHandlersUnix(s *Scanner) {
	if handlers, ok := s.handlers.(Handlers); ok {
		for _, handler := range append(handlers.TransportActive, handlers.EthernetActive...) {
			handler.Close()
		}
		for _, inactiveHandler := range append(handlers.TransportInactive, handlers.EthernetInactive...) {
			inactiveHandler.CleanUp()
		}
	}
}
