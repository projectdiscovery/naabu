package probe

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/beevik/ntp"
	"github.com/gosnmp/gosnmp"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

var Probes map[string]Probe

// Probe attempts to trigger a service response for a specific service
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
	// POP3
	// SMTP
	// TELNET
	// MYSQL
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
	// ECHO
	MustAddProbe("echo", echoProbe{})
	// Protocols (TCP|UDP)
	// IMAP
	MustAddProbe("imap", imapProbe{})
	// Protocols (UDP)
	// TFTP
	MustAddProbe("tftp", tftpProbe{})
	// Protocols (UDP)
	// SNMP
	MustAddProbe("snmp", snmpProbe{})
	// Protocols (UDP)
	// SNMP
	MustAddProbe("ntp", ntpProbe{})
	// todo: undetectable (one-way protocols)
	// SYSLOG
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

	// TODO: broadcast response to 255.255.255.255:68 lot of times is not delivered to user space socket => intercepted via pcap
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
		return nil, errors.New("dns probes only works on UDP")
	}
	req := new(dns.Msg)

	// Query for the root domain NS records
	req.SetQuestion(".", dns.TypeNS)

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

	if _, err := conn.Write(randomData); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	return io.ReadAll(conn)
}

type imapProbe struct{}

func (d imapProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	var URL strings.Builder
	URL.WriteString(fmt.Sprintf("%s:%d", host, p.Port))
	conn, err := net.Dial(p.Protocol.String(), URL.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// imap should already trigger a response
	retriedWithPayload := false
read:
	conn.SetReadDeadline(time.Now().Add(timeout))
	data, err := io.ReadAll(conn)
	if err != nil {
		if !retriedWithPayload {
			retriedWithPayload = true
			conn.SetWriteDeadline(time.Now().Add(timeout))
			if _, err := conn.Write([]byte("CAPABILITY\r\n")); err != nil {
				return nil, err
			}
			goto read
		}
	}

	return data, err
}

// tftp servers are very hard to detect without a valid filename as most servers are unresponsive
type tftpProbe struct{}

func (h tftpProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	if p.Protocol != protocol.UDP {
		return nil, errors.New("tftp probes only works on UDP")
	}
	var URL strings.Builder
	URL.WriteString(fmt.Sprintf("%s:%d", host, p.Port))
	conn, err := net.Dial(p.Protocol.String(), URL.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// todo: tftp servers are very hard to detect since mostly they reply only with valid file names (nmap default: r7tftp.txt)
	if _, err := conn.Write([]byte("\x00\x01r7tftp.txt\x00octet\x00")); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	return io.ReadAll(conn)
}

type snmpProbe struct{}

func (h snmpProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	if p.Protocol != protocol.UDP {
		return nil, errors.New("snmp probes only works on UDP")
	}

	oid := "1.3.6.1.2.1.1.1.0" // OID for sysDescr

	// Create SNMP GoSNMP instance
	snmp := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(p.Port),
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
	}

	// Send SNMP GetRequest
	err := snmp.Connect()
	if err != nil {
		return nil, err
	}
	defer snmp.Conn.Close()

	response, err := snmp.Get([]string{oid})
	if err != nil {
		return nil, err
	}

	return response.MarshalMsg()
}

// tftp servers are very hard to detect without a valid filename as most servers are unresponsive
type ntpProbe struct{}

func (h ntpProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	if p.Protocol != protocol.UDP {
		return nil, errors.New("tftp probes only works on UDP")
	}

	ntpOptions := ntp.QueryOptions{
		Timeout: timeout,
		Port:    p.Port,
	}
	response, err := ntp.QueryWithOptions(host, ntpOptions)
	if err != nil {
		return nil, err
	}
	// todo: patch original library to dump raw bytes => for now marshaling to common json
	return json.Marshal(response)
}
