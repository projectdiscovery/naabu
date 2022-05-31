//go:build linux || darwin

package scan

import (
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/phayes/freeport"
	"github.com/projectdiscovery/gologger"
)

func init() {
	newScannerCallback = NewScannerUnix
	setupHandlerCallback = SetupHandlerUnix
	tcpReadWorkerPCAPCallback = TCPReadWorkerPCAPUnix
	cleanupHandlersCallback = CleanupHandlersUnix
}

type Handlers struct {
	Active   []*pcap.Handle
	Inactive []*pcap.InactiveHandle
}

func NewScannerUnix(scanner *Scanner) error {
	rawPort, err := freeport.GetFreePort()
	if err != nil {
		return err
	}
	scanner.listenPort = rawPort

	tcpConn4, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", rawPort))})
	if err != nil {
		return err
	}
	scanner.tcpPacketlistener4 = tcpConn4

	tcpConn6, err := net.ListenIP("ip6:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf(":::%d", rawPort))})
	if err != nil {
		return err
	}
	scanner.tcpPacketlistener6 = tcpConn6

	var handlers Handlers
	scanner.handlers = handlers

	scanner.tcpChan = make(chan *PkgResult, chanSize)
	scanner.tcpPacketSend = make(chan *PkgSend, packetSendSize)
	switch runtime.GOOS {
	case "linux":
		scanner.Router, err = routing.New()
		if err != nil {
			return err
		}
	case "darwin":
		scanner.Router, err = newDarwinRouter()
		if err != nil {
			return err
		}
	}
	return nil
}

func SetupHandlerUnix(s *Scanner, interfaceName string) error {
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
	handlers.Inactive = append(handlers.Inactive, inactive)

	handle, err := inactive.Activate()
	if err != nil {
		s.CleanupHandlers()
		return err
	}

	handlers.Active = append(handlers.Active, handle)

	// Strict BPF filter
	// + Packets coming from target ip
	// + Destination port equals to sender socket source port
	err = handle.SetBPFFilter(fmt.Sprintf("tcp and dst port %d", s.listenPort))
	if err != nil {
		s.CleanupHandlers()
		return err
	}
	s.handlers = handlers

	return nil
}

func TCPReadWorkerPCAPUnix(s *Scanner) {
	defer s.CleanupHandlers()

	var wgread sync.WaitGroup

	handlers := s.handlers.(Handlers)

	for _, handler := range handlers.Active {
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
							if tcp.DstPort != layers.TCPPort(s.listenPort) {
								continue
							} else if tcp.SYN && tcp.ACK {
								s.tcpChan <- &PkgResult{ip: ip, port: int(tcp.SrcPort)}
							}
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
	handler := s.handlers.(Handlers)
	for _, handler := range handler.Active {
		handler.Close()
	}
	for _, inactiveHandler := range handler.Inactive {
		inactiveHandler.CleanUp()
	}
}
