package runner

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
)

// Port states and reasons, named as nmap names them.
const (
	stateOpen     = "open"
	stateClosed   = "closed"
	stateFiltered = "filtered"
	reasonReset   = "reset"
	reasonNoReply = "no-response"
	// nmap lists a state port by port up to this many ports per host and
	// collapses it into a count above it.
	collapseThreshold = 25
)

// hostPortStates is what -port-state adds to a host: its closed ports and how
// many probed tcp ports never answered. filtered is -1 when it is unknown.
type hostPortStates struct {
	closed   []*port.Port
	filtered int
}

// enableFilteredCount turns on the filtered count when every host was probed
// on the same port list. Smart scan picks ports per host, ip:port targets
// probe only their own port and a shard probes a slice of the (host, port)
// space, so any of them would make the count wrong.
func (r *Runner) enableFilteredCount(targetsWithPort []string) {
	r.countFiltered = r.options.PortState && !r.options.SmartScan && len(targetsWithPort) == 0 && r.options.ShardTotal <= 1
}

// portStates returns the -port-state view of every host with an open or
// closed tcp port, keyed by ip. It is nil unless -port-state is set.
func (r *Runner) portStates(scanResults *result.Result) map[string]hostPortStates {
	if !r.options.PortState {
		return nil
	}
	r.portStatesMu.Lock()
	defer r.portStatesMu.Unlock()
	if r.portStatesFor != scanResults {
		r.portStatesCache = r.computePortStates(scanResults)
		r.portStatesFor = scanResults
	}
	return r.portStatesCache
}

func (r *Runner) computePortStates(scanResults *result.Result) map[string]hostPortStates {
	states := make(map[string]hostPortStates)
	for ip, ports := range scanResults.GetClosedPorts() {
		states[ip] = hostPortStates{closed: sortedPorts(ports), filtered: -1}
	}
	if !r.countFiltered {
		return states
	}
	openCounts := scanResults.GetTCPPortCounts()
	for ip := range openCounts {
		if _, ok := states[ip]; !ok {
			states[ip] = hostPortStates{filtered: -1}
		}
	}
	allTCP, webTCP := r.probedTCPPorts()
	for ip, s := range states {
		// -port-threshold stops probing a host early, so its silent ports
		// were not all probed.
		if scanResults.HasSkipped(ip) {
			continue
		}
		probed := allTCP
		// Port 0 passes only for hosts the CDN rule leaves unrestricted.
		if !r.canIScanIfCDN(ip, &port.Port{}) {
			probed = webTCP
		}
		if answered := len(s.closed) + openCounts[ip]; probed >= answered {
			s.filtered = probed - answered
			states[ip] = s
		}
	}
	return states
}

// probedTCPPorts counts the tcp ports in the scan list, and those of them a
// CDN host is still probed on (see canIScanIfCDN).
func (r *Runner) probedTCPPorts() (all, web int) {
	for _, p := range r.scanner.Ports {
		if p.Protocol != protocol.TCP {
			continue
		}
		all++
		if p.Port == 80 || p.Port == 443 {
			web++
		}
	}
	return all, web
}

// outputPortStates logs closed and filtered counts per host and, in JSON and
// CSV modes, writes one closed record per port. Plain stdout stays open-only,
// so piping naabu into other tools is unchanged.
func (r *Runner) outputPortStates(states map[string]hostPortStates, file *os.File, stdoutHeader, fileHeader *bool) {
	ips := make([]string, 0, len(states))
	for ip := range states {
		if ipMatchesIpVersions(ip, r.options.IPVersion...) {
			ips = append(ips, ip)
		}
	}
	sort.Slice(ips, func(i, j int) bool { return compareIPStrings(ips[i], ips[j]) < 0 })

	for _, ip := range ips {
		s := states[ip]
		hosts, _ := r.hostsForIP(ip)
		if len(hosts) == 0 {
			hosts = []string{ip}
		}
		for _, host := range hosts {
			if host == "ip" {
				host = ip
			}
			if s.filtered >= 0 {
				gologger.Info().Msgf("Found %d closed and %d filtered ports on host %s (%s)\n", len(s.closed), s.filtered, host, ip)
			} else {
				gologger.Info().Msgf("Found %d closed ports on host %s (%s)\n", len(s.closed), host, ip)
			}
			if (!r.options.JSON && !r.options.CSV) || len(s.closed) == 0 {
				continue
			}
			if !r.options.DisableStdout {
				gologger.Silent().Msgf("%s", r.closedRecords(host, ip, s.closed, stdoutHeader))
			}
			if file != nil {
				if _, err := file.WriteString(r.closedRecords(host, ip, s.closed, fileHeader)); err != nil {
					gologger.Error().Msgf("Could not write closed ports of %s to file: %s\n", ip, err)
				}
			}
		}
	}
}

func (r *Runner) closedRecords(host, ip string, closed []*port.Port, csvHeader *bool) string {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	for _, p := range closed {
		data := &Result{IP: ip, Port: p.Port, Protocol: p.Protocol.String(), State: stateClosed, TimeStamp: time.Now().UTC()}
		if host != ip {
			data.Host = host
		}
		if r.options.JSON {
			b, err := data.JSON(r.options.ExcludeOutputFields)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(&buffer, "%s\n", b)
			continue
		}
		if *csvHeader {
			writeCSVHeaders(data, writer, r.options.ExcludeOutputFields)
			*csvHeader = false
		}
		writeCSVRow(data, writer, r.options.ExcludeOutputFields)
	}
	writer.Flush()
	return buffer.String()
}
