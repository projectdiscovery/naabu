package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/phayes/freeport"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/pkg/KV"
)

// Scanner is a scanner that scans for ports using SYN packets.
type Scanner struct {
	ports          map[int]struct{}
	wg             sync.WaitGroup
	Targets        map[string]map[string]struct{}
	ProbeResults   *KV.KV
	SynProbesPorts map[int]struct{}
	AckProbesPorts map[int]struct{}

	timeout           time.Duration
	serializeOptions  gopacket.SerializeOptions
	retries           int
	rate              int
	debug             bool
	tcpPacketSend     chan uint64
	tcpPacketlistener net.PacketConn
	listenPort        int
	tcpPacketRecv     chan uint64
	ScanResults       *KV.KVD

	networkInterface *net.Interface
	sourceIP         net.IP
	tcpsequencer     *TCPSequencer
}

type ipPortPair struct {
	ip   net.IP
	port uint16
}

// Options of the scan
type Options struct {
	Timeout time.Duration
	Retries int
	Rate    int
	Debug   bool
}

// NewScanner creates a new full port scanner that scans all ports using SYN packets.
func NewScanner(options *Options) (*Scanner, error) {
	scanner := &Scanner{
		serializeOptions: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		timeout:      options.Timeout,
		retries:      options.Retries,
		rate:         options.Rate,
		tcpsequencer: NewTCPSequencer(),
	}

	rawPort, err := freeport.GetFreePort()
	if err != nil {
		return nil, err
	}
	scanner.listenPort = rawPort

	tcpConn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", rawPort))})
	if err != nil {
		return nil, err
	}
	scanner.tcpPacketlistener = tcpConn

	scanner.tcpPacketRecv = make(chan uint64, 1000)
	scanner.tcpPacketSend = make(chan uint64)

	scanner.ProbeResults = KV.NewKV()
	scanner.ScanResults = KV.NewKVResults()
	return scanner, nil
}

// Close the scanner and terminate all workers
func (s *Scanner) Close() {
	s.tcpPacketlistener.Close()
}

// StartWorkers of the scanner
func (s *Scanner) StartWorkers() {
	go s.TCPReadWorker()
	go s.TCPWriteWorker()
	go s.TCPResultWorker()
}

// TCPWriteWorker that sends out TCP packets
func (s *Scanner) TCPWriteWorker() {
	for pkg := range s.tcpPacketSend {
		s.SynPortAsync(pkg.ip, pkg.port)
	}
}

// TCPReadWorker reads and parse incoming TCP packets
func (s *Scanner) TCPReadWorker() {
	defer s.tcpPacketlistener.Close()
	data := make([]byte, 4096)
	for {
		if s.State == Done {
			break
		}
		n, addr, err := s.tcpPacketlistener.ReadFrom(data)
		if err != nil {
			break
		}

		_, ok := s.Targets[addr.String()]
		if !ok {
			gologger.Debugf("Discarding TCP packet from non target ip %s\n", addr.String())
			continue
		}

		packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}
			// We consider only incoming packets
			if tcp.DstPort != layers.TCPPort(s.listenPort) {
				gologger.Debugf("Discarding TCP packet from %s:%d not matching port %d port\n", addr.String(), tcp.DstPort, s.listenPort)
			} else if tcp.SYN && tcp.ACK {
				gologger.Debugf("Accepting SYN+ACK packet from %s:%d\n", addr.String(), tcp.DstPort)
				addr.String()
				s.tcpPacketRecv <- &PkgResult{ip: addr.String(), port: int(tcp.SrcPort)}
			}
		}
	}
}

// Enqueue enqueues an IP and port for being scanned
func (s *Scanner) Enqueue(ip net.IP, port int) {
	s.tcpPacketSend <- packUint32IntoUint64()
}

// TCPResultWorker handles probes and scan results
func (s *Scanner) TCPResultWorker() {
	for ip := range s.tcpPacketRecv {
		gologger.Debugf("Received TCP scan response from %s:%d\n", ip.ip, ip.port)
		s.ScanResults.AddPort(ip.ip, ip.port)
	}
}

// GetSrcParameters gets the network parameters from the destination ip
func GetSrcParameters(destIP string) (srcIP net.IP, networkInterface *net.Interface, err error) {
	srcIP, err = GetSourceIP(net.ParseIP(destIP))
	if err != nil {
		return
	}

	networkInterface, err = GetInterfaceFromIP(srcIP)
	if err != nil {
		return
	}

	return
}

// send sends the given layers as a single packet on the network.
func (s *Scanner) send(destIP string, conn net.PacketConn, l ...gopacket.SerializableLayer) (int, error) {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
		return 0, err
	}

	var (
		retries, n int
		err        error
	)

send:
	if retries >= 10 {
		return n, err
	}
	n, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(destIP)})
	if err != nil {
		retries++
		// introduce a small delay to allow the network interface to flush the queue
		time.Sleep(time.Duration(10) * time.Millisecond)
		goto send
	}
	return n, err
}

// ScanSyn a target ip
func (s *Scanner) ScanSyn(ip string) {
	for port := range s.ports {
		s.SynPortAsync(ip, port)
	}
}

// GetSourceIP gets the local ip based on our destination ip
func GetSourceIP(dstip net.IP) (net.IP, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		return nil, err
	}

	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		defer con.Close()
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, nil
		}
	}
	return nil, err
}

// GetInterfaceFromIP gets the name of the network interface from local ip address
func GetInterfaceFromIP(ip net.IP) (*net.Interface, error) {
	address := ip.String()

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range interfaces {
		byNameInterface, err := net.InterfaceByName(i.Name)
		if err != nil {
			return nil, err
		}
		addresses, err := byNameInterface.Addrs()
		for _, v := range addresses {
			// Check if the IP for the current interface is our
			// source IP. If yes, return the interface
			if strings.HasPrefix(v.String(), address+"/") {
				return byNameInterface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found for ip %s", address)
}

// SynPortAsync sends a single SYN packet to a port
func (s *Scanner) SynPortAsync(ip string, port int) {
	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		SrcIP:    s.sourceIP,
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x12, 0x34},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.listenPort),
		DstPort: layers.TCPPort(port),
		SYN:     true,
		Window:  1024,
		Seq:     s.tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}
	tcp.SetNetworkLayerForChecksum(&ip4)
	s.send(ip, s.tcpPacketlistener, &tcp)
}

// TuneSource automatically with ip and interface
func (s *Scanner) TuneSource(ip string) error {
	var err error
	s.sourceIP, s.networkInterface, err = GetSrcParameters(ip)
	if err != nil {
		return err
	}

	return nil
}
