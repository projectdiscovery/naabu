package scan

import (
	"errors"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/mostlygeek/arp"
	"github.com/phayes/freeport"
)

// Scanner is a scanner that scans for ports using SYN packets.
type Scanner struct {
	timeout          time.Duration
	serializeOptions gopacket.SerializeOptions
	retries          int
	rate             int

	networkInterface *net.Interface
	host             net.IP
	gateway          net.IP
	srcIP            net.IP
	hwaddr           net.HardwareAddr

	Latency time.Duration
}

// Result is a port or an error returned from the scanner
type Result struct {
	Port  int
	Type  ResultType
	Error error
}

// ResultType is the type of result returned
type ResultType int

// Types of results retured
const (
	ResultPort ResultType = iota
	ResultError
)

// NewScanner creates a new full port scanner that scans all ports using SYN packets.
func NewScanner(host net.IP, timeout time.Duration, retries, rate int) (*Scanner, error) {
	rand.Seed(time.Now().UnixNano())

	scanner := &Scanner{
		serializeOptions: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		timeout: timeout,
		retries: retries,
		host:    host,
		rate:    rate,

		Latency: -1,
	}

	router, err := routing.New()
	if err != nil {
		return nil, err
	}
	scanner.networkInterface, scanner.gateway, scanner.srcIP, err = router.Route(host)
	if err != nil {
		return nil, err
	}

	// First off, get the MAC address we should be sending packets to.
	scanner.hwaddr, err = scanner.getHwAddr(host, scanner.gateway, scanner.srcIP, scanner.networkInterface)
	if err != nil {
		return nil, err
	}

	return scanner, nil
}

func (s *Scanner) getHwAddr(ip, gateway net.IP, srcIP net.IP, networkInterface *net.Interface) (net.HardwareAddr, error) {
	// grab mac from ARP table if we have it cached
	macStr := arp.Search(ip.String())
	if macStr != "00:00:00:00:00:00" {
		if mac, err := net.ParseMAC(macStr); err == nil {
			return mac, nil
		}
	}

	arpDst := ip
	if gateway != nil {
		arpDst = gateway
	}

	handle, err := pcap.OpenLive(networkInterface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	start := time.Now()

	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       networkInterface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(networkInterface.HardwareAddr),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}

	buf := gopacket.NewSerializeBuffer()

	// Send a single ARP request packet
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, &eth, &arp); err != nil {
		handle.Close()
		return nil, err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		handle.Close()
		return nil, err
	}

	// Wait 10 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Duration(10)*time.Second {
			handle.Close()
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			handle.Close()
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(arpDst) {
				handle.Close()
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

// send sends the given layers as a single packet on the network.
func (s *Scanner) send(handle *pcap.Handle, l ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

// Scan scans a single host and returns the results
func (s *Scanner) Scan(wordlist map[int]struct{}) (map[int]struct{}, error) {
	inactive, err := pcap.NewInactiveHandle(s.networkInterface.Name)
	if err != nil {
		return nil, err
	}
	inactive.SetSnapLen(65536)

	readTimeout := time.Duration(1500) * time.Millisecond
	if err = inactive.SetTimeout(readTimeout); err != nil {
		inactive.CleanUp()
		return nil, err
	}
	inactive.SetImmediateMode(true)

	handle, err := inactive.Activate()
	if err != nil {
		inactive.CleanUp()
		return nil, err
	}

	rawPort, err := freeport.GetFreePort()
	if err != nil {
		handle.Close()
		inactive.CleanUp()
		return nil, err
	}

	filter := "tcp and port " + strconv.Itoa(rawPort)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		handle.Close()
		inactive.CleanUp()
		return nil, err
	}

	openChan := make(chan int)
	results := make(map[int]struct{})
	resultsWg := &sync.WaitGroup{}
	resultsWg.Add(1)

	startTime := time.Now()

	go func() {
		for open := range openChan {
			// Set latency if the latency is less than 0 or
			// more than the default latency.
			latency := time.Since(startTime)
			if s.Latency < 0 || s.Latency < latency {
				s.Latency = latency
			}
			results[open] = struct{}{}
		}
		resultsWg.Done()
	}()

	// Construct all the network layers we need.
	eth := layers.Ethernet{
		SrcMAC:       s.networkInterface.HardwareAddr,
		DstMAC:       s.hwaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.srcIP,
		DstIP:    s.host,
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x12, 0x34},
	}
	randSeq := 1000000000 + rand.Intn(8999999999)

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rawPort),
		DstPort: 0,
		SYN:     true,
		Window:  1024,
		Seq:     uint32(randSeq),
		Options: []layers.TCPOption{tcpOption},
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	tasksWg := &sync.WaitGroup{}
	tasksWg.Add(1)
	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.host, s.srcIP)

	go func() {
		eth := &layers.Ethernet{}
		ip4 := &layers.IPv4{}
		tcp := &layers.TCP{}

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, eth, ip4, tcp)
		decoded := []gopacket.LayerType{}
		for {
			data, _, err := handle.ReadPacketData()
			if err == io.EOF {
				break
			} else if err != nil {
				continue
			}

			if err := parser.DecodeLayers(data, &decoded); err != nil {
				continue
			}
			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeIPv4:
					if ip4.NetworkFlow() != ipFlow {
						continue
					}
				case layers.LayerTypeTCP:
					// We consider only incoming packets
					if tcp.DstPort != layers.TCPPort(rawPort) {
						continue
					} else if tcp.SYN && tcp.ACK {
						openChan <- int(tcp.SrcPort)
					}
				}
			}
		}
		tasksWg.Done()
	}()

	limiter := time.Tick(time.Second / time.Duration(s.rate))

	ports := make(chan int)
	go func() {
		for port := range ports {
			// Increment sequence number from initial seed.
			// Some firewalls drop requests if Sequence values
			// are not incremental.
			randSeq += 1 + rand.Intn(5)
			tcp.Seq = uint32(randSeq)
			tcp.DstPort = layers.TCPPort(port)
			for i := 0; i < s.retries; i++ {
				<-limiter
				err := s.send(handle, &eth, &ip4, &tcp)
				if err == nil {
					break
				}
			}
		}
	}()

	for port := range wordlist {
		ports <- port
	}
	close(ports)

	// Just like masscan, wait for 10 seconds for further packets
	if s.timeout > 0 {
		timer := time.AfterFunc(10*time.Second, func() { handle.Close() })
		defer timer.Stop()
	} else {
		handle.Close()
	}

	tasksWg.Wait()
	close(openChan)
	resultsWg.Wait()

	inactive.CleanUp()

	return results, nil
}
