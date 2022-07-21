//go:build linux || darwin

package scan

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phayes/freeport"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/routing"
	"golang.org/x/net/icmp"
)

func init() {
	newScannerCallback = NewScannerUnix
	setupHandlerCallback = SetupHandlerUnix
	tcpReadWorkerPCAPCallback = TCPReadWorkerPCAPUnix
	cleanupHandlersCallback = CleanupHandlersUnix
}

type Handlers struct {
	TcpActive        []*pcap.Handle
	TcpInactive      []*pcap.InactiveHandle
	EthernetActive   []*pcap.Handle
	EthernetInactive []*pcap.InactiveHandle
}

func getFreePort() (int, error) {
	return freeport.GetFreePort()
}

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
	scanner.tcpPacketlistener4 = tcpConn4

	tcpConn6, err := net.ListenIP("ip6:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf(":::%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.tcpPacketlistener6 = tcpConn6

	var handlers Handlers
	scanner.handlers = handlers
	scanner.tcpChan = make(chan *PkgResult, chanSize)
	scanner.tcpPacketSend = make(chan *PkgSend, packetSendSize)

	icmpConn4, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	scanner.icmpPacketListener4 = icmpConn4

	icmpConn6, err := icmp.ListenPacket("udp6", "::")
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

func SetupHandlerUnix(s *Scanner, interfaceName, bpfFilter string, protocol Protocol) error {
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

	handlers := s.handlers.(Handlers)

	switch protocol {
	case TCP:
		handlers.TcpInactive = append(handlers.TcpInactive, inactive)
	case ARP:
		handlers.EthernetInactive = append(handlers.EthernetInactive, inactive)
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

	switch protocol {
	case TCP:
		handlers.TcpActive = append(handlers.TcpActive, handle)
	case ARP:
		handlers.EthernetActive = append(handlers.EthernetActive, handle)
	}
	s.handlers = handlers

	return nil
}

func TCPReadWorkerPCAPUnix(s *Scanner) {
	defer s.CleanupHandlers()

	var wgread sync.WaitGroup

	handlers := s.handlers.(Handlers)

	// Tcp Readers
	for _, handler := range handlers.TcpActive {
		wgread.Add(1)
		go func(handler *pcap.Handle) {
			defer wgread.Done()

			var (
				eth layers.Ethernet
				ip4 layers.IPv4
				ip6 layers.IPv6
				tcp layers.TCP
			)

			// Interfaces with MAC (Physical + Virtualized)
			parser4Mac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
			parser6Mac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &tcp)
			// Interfaces without MAC (TUN/TAP)
			parser4NoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp)
			parser6NoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &tcp)

			var parsers []*gopacket.DecodingLayerParser
			parsers = append(parsers, parser4Mac, parser6Mac, parser4NoMac, parser6NoMac)

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
						if layerType == layers.LayerTypeTCP {
							srcIP4 := ip4.SrcIP.String()
							isIP4InRange := s.IPRanger.Contains(srcIP4)
							srcIP6 := ip6.SrcIP.String()
							isIP6InRange := s.IPRanger.Contains(srcIP6)
							var ip string
							if isIP4InRange {
								ip = srcIP4
							} else if isIP6InRange {
								ip = srcIP6
							} else {
								gologger.Debug().Msgf("Discarding TCP packet from non target ips: ip4=%s ip6=%s\n", srcIP4, srcIP6)
								continue
							}

							// We consider only incoming packets
							if tcp.DstPort != layers.TCPPort(s.SourcePort) {
								continue
							} else if s.Phase.Is(HostDiscovery) {
								s.tcpChan <- &PkgResult{ip: ip, port: int(tcp.SrcPort)}
							} else if tcp.SYN && tcp.ACK {
								s.tcpChan <- &PkgResult{ip: ip, port: int(tcp.SrcPort)}
							}
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
	handlers := s.handlers.(Handlers)
	for _, handler := range append(handlers.TcpActive, handlers.EthernetActive...) {
		handler.Close()
	}
	for _, inactiveHandler := range append(handlers.TcpInactive, handlers.EthernetInactive...) {
		inactiveHandler.CleanUp()
	}
}
