package runner

import (
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	iputil "github.com/projectdiscovery/utils/ip"
)

// nmapHostData is the flattened per-host view used to render the nmap-compatible
// XML and greppable outputs.
type nmapHostData struct {
	ip       string
	hostname string
	mac      string
	macVnd   string
	ports    []*port.Port
}

// --- XML schema (subset of nmap's DTD, enough for common consumers) ---

type xmlRun struct {
	XMLName          xml.Name    `xml:"nmaprun"`
	Scanner          string      `xml:"scanner,attr"`
	Args             string      `xml:"args,attr,omitempty"`
	Start            int64       `xml:"start,attr"`
	StartStr         string      `xml:"startstr,attr"`
	Version          string      `xml:"version,attr"`
	XMLOutputVersion string      `xml:"xmloutputversion,attr"`
	ScanInfo         xmlScanInfo `xml:"scaninfo"`
	Hosts            []xmlHost   `xml:"host"`
	RunStats         xmlRunStats `xml:"runstats"`
}

type xmlScanInfo struct {
	Type     string `xml:"type,attr"`
	Protocol string `xml:"protocol,attr"`
}

type xmlHost struct {
	Status    xmlStatus     `xml:"status"`
	Addresses []xmlAddress  `xml:"address"`
	Hostnames *xmlHostnames `xml:"hostnames,omitempty"`
	Ports     *xmlPorts     `xml:"ports,omitempty"`
}

type xmlStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr,omitempty"`
}

type xmlAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr,omitempty"`
}

type xmlHostnames struct {
	Hostnames []xmlHostname `xml:"hostname"`
}

type xmlHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type xmlPorts struct {
	Ports []xmlPort `xml:"port"`
}

type xmlPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    xmlPortState `xml:"state"`
	Service  *xmlService  `xml:"service,omitempty"`
}

type xmlPortState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr,omitempty"`
}

type xmlService struct {
	Name      string   `xml:"name,attr,omitempty"`
	Product   string   `xml:"product,attr,omitempty"`
	Version   string   `xml:"version,attr,omitempty"`
	ExtraInfo string   `xml:"extrainfo,attr,omitempty"`
	Method    string   `xml:"method,attr,omitempty"`
	Conf      int      `xml:"conf,attr,omitempty"`
	CPEs      []string `xml:"cpe,omitempty"`
}

type xmlRunStats struct {
	Finished xmlFinished  `xml:"finished"`
	Hosts    xmlHostsStat `xml:"hosts"`
}

type xmlFinished struct {
	Time    int64  `xml:"time,attr"`
	TimeStr string `xml:"timestr,attr"`
	Elapsed string `xml:"elapsed,attr"`
	Exit    string `xml:"exit,attr"`
}

type xmlHostsStat struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

const nmapTimeLayout = "Mon Jan 2 15:04:05 2006"

func addrType(ip string) string {
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		return "ipv6"
	}
	return "ipv4"
}

// scanInfoType maps naabu scan types to nmap scaninfo "type" values.
func scanInfoType(scanType string) string {
	if scanType == SynScan {
		return "syn"
	}
	return "connect"
}

func newXMLService(svc *port.Service) *xmlService {
	if svc == nil || svc.Name == "" {
		return nil
	}
	return &xmlService{
		Name:      svc.Name,
		Product:   svc.Product,
		Version:   svc.Version,
		ExtraInfo: svc.ExtraInfo,
		Method:    svc.Method,
		Conf:      svc.Confidence,
		CPEs:      svc.CPEs,
	}
}

// writeNmapXML renders hosts as an nmap-compatible XML document.
func writeNmapXML(w io.Writer, hosts []nmapHostData, scanType string, start, end time.Time) error {
	run := xmlRun{
		Scanner:          "naabu",
		Start:            start.Unix(),
		StartStr:         start.Format(nmapTimeLayout),
		Version:          Version,
		XMLOutputVersion: "1.05",
		ScanInfo:         xmlScanInfo{Type: scanInfoType(scanType), Protocol: "tcp"},
	}

	for _, h := range hosts {
		xh := xmlHost{
			Status:    xmlStatus{State: "up", Reason: "syn-ack"},
			Addresses: []xmlAddress{{Addr: h.ip, AddrType: addrType(h.ip)}},
		}
		if h.mac != "" {
			xh.Addresses = append(xh.Addresses, xmlAddress{Addr: h.mac, AddrType: "mac", Vendor: h.macVnd})
		}
		if h.hostname != "" && h.hostname != h.ip {
			xh.Hostnames = &xmlHostnames{Hostnames: []xmlHostname{{Name: h.hostname, Type: "user"}}}
		}
		if len(h.ports) > 0 {
			xp := &xmlPorts{}
			for _, p := range h.ports {
				xp.Ports = append(xp.Ports, xmlPort{
					Protocol: p.Protocol.String(),
					PortID:   p.Port,
					State:    xmlPortState{State: "open", Reason: "syn-ack"},
					Service:  newXMLService(p.Service),
				})
			}
			xh.Ports = xp
		}
		run.Hosts = append(run.Hosts, xh)
	}

	run.RunStats = xmlRunStats{
		Finished: xmlFinished{
			Time:    end.Unix(),
			TimeStr: end.Format(nmapTimeLayout),
			Elapsed: fmt.Sprintf("%.2f", end.Sub(start).Seconds()),
			Exit:    "success",
		},
		Hosts: xmlHostsStat{Up: len(hosts), Down: 0, Total: len(hosts)},
	}

	if _, err := io.WriteString(w, xml.Header+"<!DOCTYPE nmaprun>\n"); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(run); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// grepSanitize strips the field separators greppable output relies on.
func grepSanitize(s string) string {
	return strings.NewReplacer("/", "|", ",", ";", "\n", " ", "\t", " ").Replace(s)
}

// writeGreppable renders hosts in nmap's greppable (-oG) format.
func writeGreppable(w io.Writer, hosts []nmapHostData, start, end time.Time) error {
	if _, err := fmt.Fprintf(w, "# Naabu %s scan initiated %s\n", Version, start.Format(nmapTimeLayout)); err != nil {
		return err
	}
	for _, h := range hosts {
		name := h.hostname
		if name == "" {
			name = h.ip
		}
		if len(h.ports) == 0 {
			if _, err := fmt.Fprintf(w, "Host: %s (%s)\tStatus: Up\n", h.ip, name); err != nil {
				return err
			}
			continue
		}
		var parts []string
		for _, p := range h.ports {
			svcName := ""
			version := ""
			if p.Service != nil {
				svcName = grepSanitize(p.Service.Name)
				version = grepSanitize(strings.TrimSpace(p.Service.Product + " " + p.Service.Version))
			}
			// portid/state/protocol/owner/service/rpc/version
			parts = append(parts, fmt.Sprintf("%d/open/%s//%s//%s/", p.Port, p.Protocol.String(), svcName, version))
		}
		if _, err := fmt.Fprintf(w, "Host: %s (%s)\tPorts: %s\n", h.ip, name, strings.Join(parts, ", ")); err != nil {
			return err
		}
	}
	upHosts := len(hosts)
	if _, err := fmt.Fprintf(w, "# Naabu done at %s -- %d IP addresses (%d hosts up) scanned\n",
		end.Format(nmapTimeLayout), upHosts, upHosts); err != nil {
		return err
	}
	return nil
}

// collectNmapHosts flattens the scan result set into the per-host view used by
// the nmap-compatible writers, resolving hostnames the same way handleOutput does.
func (r *Runner) collectNmapHosts(scanResults *result.Result) []nmapHostData {
	var hosts []nmapHostData
	switch {
	case scanResults.HasIPsPorts():
		for hostResult := range scanResults.GetIPsPorts() {
			if !ipMatchesIpVersions(hostResult.IP, r.options.IPVersion...) {
				continue
			}
			hosts = append(hosts, nmapHostData{
				ip:       hostResult.IP,
				hostname: r.primaryHostname(hostResult.IP),
				mac:      hostResult.MacAddress,
				macVnd:   vendorFromMAC(hostResult.MacAddress),
				ports:    hostResult.Ports,
			})
		}
	case scanResults.HasIPS():
		for hostIP := range scanResults.GetIPs() {
			if !ipMatchesIpVersions(hostIP, r.options.IPVersion...) {
				continue
			}
			hosts = append(hosts, nmapHostData{
				ip:       hostIP,
				hostname: r.primaryHostname(hostIP),
			})
		}
	}
	return hosts
}

// primaryHostname returns the first non-IP hostname recorded for an IP, or "".
func (r *Runner) primaryHostname(ip string) string {
	dt, err := r.hostsForIP(ip)
	if err != nil {
		return ""
	}
	for _, h := range dt {
		if h != "" && h != "ip" && !iputil.IsIP(h) {
			return h
		}
	}
	return ""
}

// writeNmapFormats emits the nmap-compatible XML and greppable outputs when the
// corresponding -oX / -oG flags are set.
func (r *Runner) writeNmapFormats(scanResults *result.Result) {
	if r.options.XMLOutput == "" && r.options.GrepOutput == "" {
		return
	}
	if r.scanStartTime.IsZero() {
		r.scanStartTime = time.Now()
	}
	hosts := r.collectNmapHosts(scanResults)

	if r.options.XMLOutput != "" {
		r.emitNmapFile(r.options.XMLOutput, func(w io.Writer) error {
			return writeNmapXML(w, hosts, r.options.ScanType, r.scanStartTime, time.Now())
		})
	}
	if r.options.GrepOutput != "" {
		r.emitNmapFile(r.options.GrepOutput, func(w io.Writer) error {
			return writeGreppable(w, hosts, r.scanStartTime, time.Now())
		})
	}
}

func (r *Runner) emitNmapFile(path string, write func(io.Writer) error) {
	if path == "-" {
		if err := write(os.Stdout); err != nil {
			gologger.Error().Msgf("could not write nmap output: %s\n", err)
		}
		return
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			gologger.Error().Msgf("could not create output dir %s: %s\n", dir, err)
			return
		}
	}
	f, err := os.Create(path)
	if err != nil {
		gologger.Error().Msgf("could not create output file %s: %s\n", path, err)
		return
	}
	defer func() { _ = f.Close() }()
	if err := write(f); err != nil {
		gologger.Error().Msgf("could not write output file %s: %s\n", path, err)
	}
}
