package probe

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

var Probes map[string]Probe

type Probe interface {
	Do(host string, p *port.Port, timeout time.Duration) ([]byte, error)
}

func MustAddProbe(name string, probe Probe) {
	if _, ok := Probes[name]; ok {
		panic("probe " + name + " already defined")
	}
	Probes[name] = probe
}

func init() {
	Probes = make(map[string]Probe)
	// Protocols (TCP|UDP)
	// FTP
	// SSH
	MustAddProbe("null", nullProbe{})
	// Protocols (TCP)
	// HTTP(S)
	MustAddProbe("http(s)", httpProbe{})
	// Protocols (UDP)
	// DHCP
	MustAddProbe("dhcp", dhcpProbe{})
	// Protocols (UDP)
	// DNS
	MustAddProbe("dns", dnsProbe{})
	// Protocols (TCP|UDP)
	// Echo
	MustAddProbe("echo", echoProbe{})
}

type httpProbe struct{}

func (h httpProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	if p.Protocol != protocol.TCP {
		return nil, errors.New("dhcp probes only works on TCP")
	}

	httpClient := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	var URL strings.Builder
	URL.WriteString("http")
	if p.TLS {
		URL.WriteString("s")
	}
	URL.WriteString("://")
	URL.WriteString(fmt.Sprintf("%s:%d", host, p.Port))
	resp, err := httpClient.Get(URL.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return httputil.DumpResponse(resp, true)
}

// genericReadProbe for self-advertising services
type nullProbe struct{}

func (h nullProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	var URL strings.Builder
	URL.WriteString(fmt.Sprintf("%s:%d", host, p.Port))
	conn, err := net.Dial(p.Protocol.String(), URL.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))
	return io.ReadAll(conn)
}

type dhcpProbe struct {
	SourceIP string
}

func (h dhcpProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	if p.Protocol != protocol.UDP {
		return nil, errors.New("dhcp probes only works on UDP")
	}
	dhcpMsg, err := dhcpv4.New(
		dhcpv4.WithClientIP(net.ParseIP(h.SourceIP)),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeInform),
	)
	if err != nil {
		return nil, err
	}
	dhcpMsg.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP(host)))

	conn, err := net.DialUDP("udp", &net.UDPAddr{Port: 68}, &net.UDPAddr{IP: net.ParseIP(host), Port: p.Port})
	if err != nil {
		// in case of error we fallback to arbitrary port
		conn, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(host), Port: p.Port})
		if err != nil {
			return nil, err
		}
	}
	defer conn.Close()

	conn.Write(dhcpMsg.ToBytes())
	conn.SetReadDeadline(time.Now().Add(timeout))

	// todo: broadcast response should be intercepted via pcap
	data := make([]byte, 1024)
	_, err = conn.Read(data)
	if err != nil {
		return nil, err
	}
	_, err = dhcpv4.FromBytes(data)
	if err != nil {
		return nil, errors.New("invalid dhcp response")
	}
	return data, nil
}

type dnsProbe struct{}

func (d dnsProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	if p.Protocol != protocol.UDP {
		return nil, errors.New("dhcp probes only works on UDP")
	}
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS) // Query for the root domain NS records

	dnsClient := new(dns.Client)
	dnsClient.ReadTimeout = timeout
	resp, _, err := dnsClient.Exchange(req, net.JoinHostPort(host, fmt.Sprint(p.Port)))
	if err != nil {
		return nil, err
	}

	return resp.Pack()
}

type echoProbe struct{}

func (d echoProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	var URL strings.Builder
	URL.WriteString(fmt.Sprintf("%s:%d", host, p.Port))
	conn, err := net.Dial(p.Protocol.String(), URL.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	randomData := make([]byte, 16)

	_, err = rand.Read(randomData)
	if err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	return io.ReadAll(conn)
}
