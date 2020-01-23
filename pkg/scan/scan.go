package scan

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phayes/freeport"
)

// Scanner is a scanner that scans for ports using SYN packets.
type Scanner struct {
	timeout          time.Duration
	serializeOptions gopacket.SerializeOptions
	retries          int
	rate             int

	host         net.IP
	srcIP        net.IP
	srcInterface string

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

	// Get the source IP and the network interface packets will be sent from
	var err error
	scanner.srcIP, err = getSourceIP(host)
	if err != nil {
		return nil, err
	}

	networkInterface, err := getInterfaceFromIP(scanner.srcIP)
	if err != nil {
		return nil, err
	}
	scanner.srcInterface = networkInterface.Name

	return scanner, nil
}

// send sends the given layers as a single packet on the network.
func (s *Scanner) send(conn net.PacketConn, dstip net.IP, l ...gopacket.SerializableLayer) (int, error) {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
		return 0, err
	}
	return conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip})
}

// Scan scans a single host and returns the results
func (s *Scanner) Scan(wordlist map[int]struct{}) (map[int]struct{}, error) {
	inactive, err := pcap.NewInactiveHandle(s.srcInterface)
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

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
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
			results[open] = struct{}{}
		}
		resultsWg.Done()
	}()

	// Construct all the network layers we need.
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
		ip4 := &layers.IPv4{}
		tcp := &layers.TCP{}

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, ip4, tcp)
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
					} else {
						// Set latency if the latency is less than 0
						if s.Latency < 0 {
							s.Latency = time.Since(startTime)
						}

						if tcp.SYN && tcp.ACK {
							openChan <- int(tcp.SrcPort)
						}
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
				n, err := s.send(conn, ip4.DstIP, &tcp)
				if n > 0 && err == nil {
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
		timer := time.AfterFunc(10*time.Second, func() { conn.Close(); handle.Close() })
		defer timer.Stop()
	} else {
		conn.Close()
		handle.Close()
		inactive.CleanUp()
	}

	tasksWg.Wait()
	close(openChan)
	resultsWg.Wait()

	inactive.CleanUp()

	return results, nil
}

// getSourceIP gets the local ip based on our destination ip
func getSourceIP(dstip net.IP) (net.IP, error) {
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

// getInterfaceFromIP gets the name of the network interface from local ip address
func getInterfaceFromIP(ip net.IP) (*net.Interface, error) {
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
