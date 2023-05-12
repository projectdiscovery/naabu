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
	"github.com/projectdiscovery/utils/generic"
)

var Probes map[string]Probe

// Probe attempts to trigger a service response for a specific service
type Probe interface {
	Id() string
	ValidFor(p *port.Port) bool
	DoWithConn(conn net.Conn, timeout time.Duration) ([]byte, error)
	Do(host string, p *port.Port, timeout time.Duration) ([]byte, error)
}

func MustAddProbe(probe Probe) {
	name := probe.Id()
	if _, ok := Probes[name]; ok {
		panic("probe " + name + " already defined")
	}
	Probes[name] = probe
}

func LookupOneOrNull(p *port.Port) Probe {
	for _, probe := range Probes {
		if probe.ValidFor(p) {
			return probe
		}
	}
	return Probes["null"]
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
	MustAddProbe(nullProbe{})
	// Protocols (TCP)
	// HTTP(S)
	MustAddProbe(httpProbe{})
	// Protocols (UDP)
	// DHCP
	MustAddProbe(dhcpProbe{})
	// Protocols (UDP)
	// DNS
	MustAddProbe(dnsProbe{})
	// Protocols (TCP|UDP)
	// ECHO
	MustAddProbe(echoProbe{})
	// Protocols (TCP|UDP)
	// IMAP
	MustAddProbe(imapProbe{})
	// Protocols (UDP)
	// TFTP
	MustAddProbe(tftpProbe{})
	// Protocols (UDP)
	// SNMP
	MustAddProbe(snmpProbe{})
	// Protocols (UDP)
	// SNMP
	MustAddProbe(ntpProbe{})
	// todo: undetectable (one-way protocols)
	// SYSLOG
}

type httpProbe struct{}

func (h httpProbe) Id() string {
	return "http"
}

func (h httpProbe) ValidFor(p *port.Port) bool {
	return p.Protocol == protocol.TCP &&
		generic.EqualsAny(p.Port, 80, 443, 8080)
}

func (h httpProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
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

func (h httpProbe) DoWithConn(conn net.Conn, timeout time.Duration) ([]byte, error) {
	return nil, errors.New("not supported")
}

// genericReadProbe for self-advertising services
type nullProbe struct{}

func (h nullProbe) Id() string {
	return "null"
}

func (h nullProbe) ValidFor(p *port.Port) bool {
	return true
}

func (h nullProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	var URL strings.Builder
	URL.WriteString(fmt.Sprintf("%s:%d", host, p.Port))
	conn, err := net.Dial(p.Protocol.String(), URL.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return h.DoWithConn(conn, timeout)
}

func (h nullProbe) DoWithConn(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	return io.ReadAll(conn)
}

type dhcpProbe struct {
	SourceIP string
}

func (h dhcpProbe) Id() string {
	return "dhcp"
}

func (h dhcpProbe) ValidFor(p *port.Port) bool {
	return p.Protocol == protocol.UDP &&
		generic.EqualsAny(p.Port, 67)
}

func (h dhcpProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialUDP("udp", &net.UDPAddr{Port: 68}, &net.UDPAddr{IP: net.ParseIP(host), Port: p.Port})
	if err != nil {
		// in case of error we fallback to arbitrary port
		conn, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(host), Port: p.Port})
		if err != nil {
			return nil, err
		}
	}
	defer func() {
		_ = conn.Close()
	}()

	return h.DoWithConn(conn, timeout)
}

func (h dhcpProbe) DoWithConn(conn net.Conn, timeout time.Duration) ([]byte, error) {
	dhcpMsg, err := dhcpv4.New(
		dhcpv4.WithClientIP(net.ParseIP(h.SourceIP)),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeInform),
	)
	if err != nil {
		return nil, err
	}
	dhcpMsg.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP(conn.RemoteAddr().Network())))

	if _, err := conn.Write(dhcpMsg.ToBytes()); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

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

func (h dnsProbe) Id() string {
	return "dns"
}

func (h dnsProbe) ValidFor(p *port.Port) bool {
	return p.Protocol == protocol.UDP &&
		generic.EqualsAny(p.Port, 53)
}

func (h dnsProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	conn, err := net.Dial(p.Protocol.String(), net.JoinHostPort(host, fmt.Sprint(p.Port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return h.DoWithConn(conn, timeout)
}

func (h dnsProbe) DoWithConn(conn net.Conn, timeout time.Duration) ([]byte, error) {
	req := new(dns.Msg)

	// Query for the root domain NS records
	req.SetQuestion(".", dns.TypeNS)
	dnsClient := new(dns.Client)
	dnsClient.ReadTimeout = timeout
	resp, _, err := dnsClient.ExchangeWithConn(req, &dns.Conn{Conn: conn})
	if err != nil {
		return nil, err
	}

	return resp.Pack()
}

type echoProbe struct{}

func (h echoProbe) Id() string {
	return "echo"
}

func (h echoProbe) ValidFor(p *port.Port) bool {
	return generic.EqualsAny(p.Port, 7)
}

func (d echoProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	var URL strings.Builder
	URL.WriteString(fmt.Sprintf("%s:%d", host, p.Port))
	conn, err := net.Dial(p.Protocol.String(), URL.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return d.DoWithConn(conn, timeout)
}

func (d echoProbe) DoWithConn(conn net.Conn, timeout time.Duration) ([]byte, error) {
	randomData := make([]byte, 16)

	_, err := rand.Read(randomData)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(randomData); err != nil {
		return nil, err
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	return io.ReadAll(conn)
}

type imapProbe struct{}

func (h imapProbe) Id() string {
	return "imap"
}

func (h imapProbe) ValidFor(p *port.Port) bool {
	return generic.EqualsAny(p.Port, 143, 993)
}

func (d imapProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	var URL strings.Builder
	URL.WriteString(fmt.Sprintf("%s:%d", host, p.Port))
	conn, err := net.Dial(p.Protocol.String(), URL.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return d.DoWithConn(conn, timeout)
}

func (d imapProbe) DoWithConn(conn net.Conn, timeout time.Duration) ([]byte, error) {
	// imap should already trigger a response
	retriedWithPayload := false
read:
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		if !retriedWithPayload {
			retriedWithPayload = true
			if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
				return nil, err
			}
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

func (h tftpProbe) Id() string {
	return "tftp"
}

func (h tftpProbe) ValidFor(p *port.Port) bool {
	return p.Protocol == protocol.UDP &&
		generic.EqualsAny(p.Port, 69)
}

func (h tftpProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
	var URL strings.Builder
	URL.WriteString(fmt.Sprintf("%s:%d", host, p.Port))
	conn, err := net.Dial(p.Protocol.String(), URL.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return h.DoWithConn(conn, timeout)
}

func (h tftpProbe) DoWithConn(conn net.Conn, timeout time.Duration) ([]byte, error) {
	// todo: tftp servers are very hard to detect since mostly they reply only with valid file names (nmap default: r7tftp.txt)
	if _, err := conn.Write([]byte("\x00\x01r7tftp.txt\x00octet\x00")); err != nil {
		return nil, err
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	return io.ReadAll(conn)
}

type snmpProbe struct{}

func (h snmpProbe) Id() string {
	return "snmp"
}

func (h snmpProbe) ValidFor(p *port.Port) bool {
	return p.Protocol == protocol.UDP &&
		generic.EqualsAny(p.Port, 161, 162)
}

func (h snmpProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
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

func (h snmpProbe) DoWithConn(conn net.Conn, timeout time.Duration) ([]byte, error) {
	return nil, errors.New("not supported")
}

type ntpProbe struct{}

func (h ntpProbe) Id() string {
	return "ntp"
}

func (h ntpProbe) ValidFor(p *port.Port) bool {
	return p.Protocol == protocol.UDP &&
		generic.EqualsAny(p.Port, 161, 162)
}

func (h ntpProbe) Do(host string, p *port.Port, timeout time.Duration) ([]byte, error) {
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

func (h ntpProbe) DoWithConn(conn net.Conn, timeout time.Duration) ([]byte, error) {
	return nil, errors.New("not supported")
}
