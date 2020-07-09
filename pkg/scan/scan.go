package scan

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/phayes/freeport"
	"github.com/projectdiscovery/gologger"
	"github.com/remeh/sizedwaitgroup"
)

// Scanner is a scanner that scans for ports using SYN packets.
type Scanner struct {
	timeout          time.Duration
	serializeOptions gopacket.SerializeOptions
	retries          int
	rate             int
	debug            bool

	networkInterface *net.Interface
	host             net.IP
	srcIP            net.IP
}

// NewScanner creates a new full port scanner that scans all ports using SYN packets.
func NewScanner(host net.IP, timeout time.Duration, retries, rate int, debug bool) (*Scanner, error) {
	rand.Seed(time.Now().UnixNano())

	scanner := &Scanner{
		serializeOptions: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		timeout: timeout,
		retries: retries,
		rate:    rate,
		debug:   debug,

		host: host,
	}

	// Get the source IP and the network interface packets will be sent from
	var err error
	if debug {
		gologger.Debugf("Looking for source ip\n")
	}
	scanner.srcIP, err = getSourceIP(host)
	if err != nil {
		return nil, err
	}
	if debug {
		gologger.Debugf("Source ip %s found\n", scanner.srcIP)
	}

	if debug {
		gologger.Debugf("Looking for interface from ip %s\n", scanner.srcIP)
	}
	scanner.networkInterface, err = getInterfaceFromIP(scanner.srcIP)
	if err != nil {
		return nil, err
	}
	if debug {
		gologger.Debugf("Interface %s (%s) for source ip %s found\n", scanner.networkInterface.Name, scanner.networkInterface.HardwareAddr, scanner.srcIP)
	}

	return scanner, nil
}

// send sends the given layers as a single packet on the network.
func (s *Scanner) send(conn net.PacketConn, l ...gopacket.SerializableLayer) (int, error) {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
		return 0, err
	}
	return conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: s.host})
}

// ScanSyn scans a single host and returns the results
func (s *Scanner) ScanSyn(wordlist map[int]struct{}) (map[int]struct{}, error) {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	rawPort, err := freeport.GetFreePort()
	if err != nil {
		return nil, err
	}

	openChan := make(chan int)
	results := make(map[int]struct{})
	resultsWg := &sync.WaitGroup{}
	resultsWg.Add(1)

	go func() {
		for open := range openChan {
			gologger.Debugf("Found active port %d on %s\n", open, s.host.String())

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
	randSeq := 1000000000 + rand.Intn(math.MaxInt32)

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

	go func() {
		defer tasksWg.Done()
		data := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(data)
			if err != nil {
				break
			}

			// not matching ip
			if addr.String() != s.host.String() {
				if s.debug {
					gologger.Debugf("Discarding TCP packet from %s not matching %s ip\n", addr.String(), s.host.String())
				}
				continue
			}

			packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, ok := tcpLayer.(*layers.TCP)
				if !ok {
					continue
				}
				// We consider only incoming packets
				if tcp.DstPort != layers.TCPPort(rawPort) {
					if s.debug {
						gologger.Debugf("Discarding TCP packet to %s:%d not matching %s:%d port\n", addr.String(), tcp.DstPort, s.host.String(), rawPort)
					}
					continue
				} else if tcp.SYN && tcp.ACK {
					if s.debug {
						gologger.Debugf("Accepting SYN+ACK packet from %s:%d\n", addr.String(), tcp.DstPort)
					}
					openChan <- int(tcp.SrcPort)
				}
			}
		}
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
				if s.debug {
					gologger.Debugf("Sending Syn Packet from %s:%d to %s:%d (Retry %d)\n", s.srcIP, rawPort, s.host, port, i)
				}
				n, err := s.send(conn, &tcp)
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
		if s.debug {
			gologger.Debugf("Waiting %d seconds before closing\n", 10)
		}
		timer := time.AfterFunc(10*time.Second, func() {
			conn.Close()
		})
		defer timer.Stop()
	} else {
		conn.Close()
	}

	tasksWg.Wait()
	close(openChan)
	resultsWg.Wait()

	return results, nil
}

// ScanConnect a single host and returns the results
func (s *Scanner) ScanConnect(wordlist map[int]struct{}) (map[int]struct{}, error) {
	openChan := make(chan int)
	results := make(map[int]struct{})
	resultsWg := &sync.WaitGroup{}
	resultsWg.Add(1)

	go func() {
		for open := range openChan {
			gologger.Debugf("Found active port %d on %s\n", open, s.host.String())

			results[open] = struct{}{}
		}
		resultsWg.Done()
	}()

	tasksWg := &sync.WaitGroup{}
	tasksWg.Add(1)

	ports := make(chan int)
	go func() {
		defer tasksWg.Done()

		swgscan := sizedwaitgroup.New(s.rate)
		for port := range ports {
			swgscan.Add()
			go func(port int) {
				defer swgscan.Done()

				if s.debug {
					gologger.Debugf("Connecting to %s:%d\n", s.host, port)
				}
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", s.host, port), s.timeout)
				if err != nil {
					if s.debug {
						gologger.Debugf("Connection to %s:%d failed: %s\n", s.host, port, err)
					}
					return
				}
				defer conn.Close()

				if s.debug {
					gologger.Debugf("Connection to %s:%d successful\n", s.host, port)
				}
				openChan <- port
			}(port)
		}
		swgscan.Wait()
	}()

	for port := range wordlist {
		ports <- port
	}
	close(ports)

	tasksWg.Wait()
	close(openChan)
	resultsWg.Wait()

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
