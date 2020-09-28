package scan

import (
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Some constants
const (
	DeadlineSec  = 10
	ProtocolICMP = 1
)

// PingResult contains the results for the Ping request
type PingResult struct {
	Hosts []Ping
}

// Ping contains the results for ping on a single host
type Ping struct {
	Type    PingResultType
	Latency time.Duration
	Error   error
	Host    string
}

// PingResultType contains the type of result for ping request on an address
type PingResultType int

// Type of ping responses
const (
	HostInactive PingResultType = iota
	HostActive
)

// PingHosts pings the addresses given and returns the latencies of each host
// If the address returns an error, that address is marked as unusable.
func PingHosts(addresses []string) (*PingResult, error) {
	// Start listening for icmp replies
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	defer c.Close()

	results := &PingResult{Hosts: []Ping{}}
	var sequence int

	for _, addr := range addresses {
		// Resolve any DNS (if used) and get the real IP of the target
		dst, err := net.ResolveIPAddr("ip4", addr)
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}

		sequence++
		// Make a new ICMP message
		m := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  sequence,
				Data: []byte(""),
			},
		}

		data, err := m.Marshal(nil)
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}

		// Send the packet
		start := time.Now()
		_, err = c.WriteTo(data, dst)
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}

		reply := make([]byte, 1500)
		err = c.SetReadDeadline(time.Now().Add(DeadlineSec * time.Second))
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}

		n, _, err := c.ReadFrom(reply)
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}
		duration := time.Since(start)

		rm, err := icmp.ParseMessage(ProtocolICMP, reply[:n])
		if err != nil {
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: err, Host: addr})
			continue
		}
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			results.Hosts = append(results.Hosts, Ping{Type: HostActive, Latency: duration, Host: addr})
		default:
			results.Hosts = append(results.Hosts, Ping{Type: HostInactive, Error: errors.New("no reply found for ping probe"), Host: addr})
			continue
		}
	}

	return results, nil
}

// GetFastestHost gets the fastest host from the ping responses
func (p *PingResult) GetFastestHost() (Ping, error) {
	var ping Ping

	// If the latency of the current host is less than the
	// host selected and host is active, use the host that has least latency.
	for _, host := range p.Hosts {
		if (host.Latency < ping.Latency || ping.Latency == 0) && host.Type == HostActive {
			ping.Type = HostActive
			ping.Latency = host.Latency
			ping.Host = host.Host
		}
	}

	if ping.Type != HostActive {
		return ping, errors.New("no active host found for target")
	}
	return ping, nil
}
