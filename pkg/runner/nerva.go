package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/scan"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
)

func (r *Runner) handleServiceFingerprinting() error {
	if !r.options.ServiceDiscovery && !r.options.ServiceVersion {
		return nil
	}

	var tcpTargets, udpTargets []plugins.Target
	for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
		for _, p := range hostResult.Ports {
			if p.Port <= 0 || p.Port > 65535 {
				continue
			}

			target := plugins.Target{
				Host:    hostResult.IP,
				Address: joinAddrPort(hostResult.IP, p.Port),
			}
			if !target.Address.IsValid() {
				continue
			}

			switch p.Protocol {
			case protocol.UDP:
				udpTargets = append(udpTargets, target)
			default:
				tcpTargets = append(tcpTargets, target)
			}
		}
	}

	if len(tcpTargets) == 0 && len(udpTargets) == 0 {
		// gologger.Info().Msg("No hosts with open ports found for service fingerprinting")
		return nil
	}

	baseCfg := scan.Config{
		DefaultTimeout: r.options.Timeout,
		Verbose:        r.options.Verbose || r.options.Debug,
	}

	run := func(targets []plugins.Target, udp bool) {
		if len(targets) == 0 {
			return
		}

		cfg := baseCfg
		cfg.UDP = udp

		results, err := scan.ScanTargets(targets, cfg)
		if err != nil {
			transport := "tcp"
			if udp {
				transport = "udp"
			}
			gologger.Warning().Msgf("Could not fingerprint %s services: %s", transport, err)
			return
		}

		r.integrateNervaResults(results)
	}

	run(tcpTargets, false)
	run(udpTargets, true)

	return nil
}

func joinAddrPort(ip string, portNum int) netip.AddrPort {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.AddrPort{}
	}

	if portNum <= 0 || portNum > 65535 {
		return netip.AddrPort{}
	}

	return netip.AddrPortFrom(addr, uint16(portNum))
}

func (r *Runner) integrateNervaResults(services []plugins.Service) {
	for _, service := range services {
		enhancedPort, ip, ok := r.convertNervaServiceToPort(service)
		if !ok {
			continue
		}

		r.updatePortWithServiceInfo(ip, enhancedPort)
	}
}

func (r *Runner) convertNervaServiceToPort(service plugins.Service) (*port.Port, string, bool) {
	if service.Port <= 0 {
		return nil, "", false
	}

	proto := protocol.TCP
	if strings.EqualFold(service.Transport, "udp") {
		proto = protocol.UDP
	}

	enhancedPort := &port.Port{
		Port:     service.Port,
		Protocol: proto,
		TLS:      service.TLS,
		Service: &port.Service{
			Name: service.Protocol,
		},
	}

	if r.options.ServiceVersion {
		enhancedPort.Service.Version = service.Version
		enhancedPort.Service.Product = service.Protocol
		enhancedPort.Service.ExtraInfo = normalizeServiceRawMetadata(service.Raw)
	}

	ip := service.IP
	if ip == "" {
		ip = service.Host
	}
	if ip == "" {
		return nil, "", false
	}

	return enhancedPort, ip, true
}

func normalizeServiceRawMetadata(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return ""
	}

	if !json.Valid(raw) {
		return trimmed
	}

	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return trimmed
	}

	return compact.String()
}

func (r *Runner) enrichHostResultPorts(hostResult *result.HostResult) []*port.Port {
	if hostResult == nil || len(hostResult.Ports) == 0 {
		return hostResult.Ports
	}
	if !r.options.ServiceDiscovery && !r.options.ServiceVersion {
		return hostResult.Ports
	}

	baseCfg := scan.Config{
		DefaultTimeout: r.options.Timeout,
		Verbose:        r.options.Verbose || r.options.Debug,
	}

	var tcpTargets, udpTargets []plugins.Target
	for _, p := range hostResult.Ports {
		if p.Port <= 0 || p.Port > 65535 {
			continue
		}

		target := plugins.Target{
			Host:    hostResult.IP,
			Address: joinAddrPort(hostResult.IP, p.Port),
		}
		if !target.Address.IsValid() {
			continue
		}

		switch p.Protocol {
		case protocol.UDP:
			udpTargets = append(udpTargets, target)
		default:
			tcpTargets = append(tcpTargets, target)
		}
	}

	resultsByPort := make(map[string]*port.Port)
	key := func(proto protocol.Protocol, portNum int) string {
		return fmt.Sprintf("%s:%d", proto.String(), portNum)
	}
	run := func(targets []plugins.Target, udp bool) {
		if len(targets) == 0 {
			return
		}

		cfg := baseCfg
		cfg.UDP = udp

		services, err := scan.ScanTargets(targets, cfg)
		if err != nil {
			transport := "tcp"
			if udp {
				transport = "udp"
			}
			gologger.Debug().Msgf("Could not fingerprint %s services for %s: %s", transport, hostResult.IP, err)
			return
		}

		for _, service := range services {
			enhancedPort, ip, ok := r.convertNervaServiceToPort(service)
			if !ok {
				continue
			}
			if ip != hostResult.IP {
				continue
			}

			resultsByPort[key(enhancedPort.Protocol, enhancedPort.Port)] = enhancedPort
			r.updatePortWithServiceInfo(ip, enhancedPort)
		}
	}

	run(tcpTargets, false)
	run(udpTargets, true)

	for _, p := range hostResult.Ports {
		if enhanced, ok := resultsByPort[key(p.Protocol, p.Port)]; ok {
			p.TLS = enhanced.TLS
			p.Service = enhanced.Service
		}
	}

	return hostResult.Ports
}

func (r *Runner) handleFingerprinting() error {
	if err := r.handleServiceFingerprinting(); err != nil {
		return err
	}

	if err := r.handleNmap(); err != nil {
		return err
	}

	return nil
}
