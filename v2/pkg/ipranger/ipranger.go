package ipranger

import (
	"bytes"
	"net"
	"strings"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/mapcidr"
	"github.com/yl2chen/cidranger"
)

const (
	singleIPSuffix = "/32"
)

type IPRanger struct {
	TotalIps        uint64
	Ranger          cidranger.Ranger
	TotalExcludeIps uint64
	RangerExclude   cidranger.Ranger
	TotalFqdn       uint64
	Targets         *hybrid.HybridMap
}

func New() (*IPRanger, error) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}
	rangerIn := cidranger.NewPCTrieRanger()
	rangerExclude := cidranger.NewPCTrieRanger()

	return &IPRanger{Ranger: rangerIn, RangerExclude: rangerExclude, Targets: hm}, nil
}

func (ir *IPRanger) Add(ipcidr string) error {
	if ir.Contains(ipcidr) {
		return nil
	}

	// if it's an ip convert it to cidr representation
	if IsIP(ipcidr) {
		ipcidr += singleIPSuffix
	}
	// Check if it's a cidr
	_, network, err := net.ParseCIDR(ipcidr)
	if err != nil {
		return err
	}

	ir.TotalIps += mapcidr.AddressCountIpnet(network)

	return ir.Ranger.Insert(cidranger.NewBasicRangerEntry(*network))
}

func (ir *IPRanger) AddIPNet(network *net.IPNet) error {
	ir.TotalIps += mapcidr.AddressCountIpnet(network)

	return ir.Ranger.Insert(cidranger.NewBasicRangerEntry(*network))
}

func (ir *IPRanger) Delete(ipcidr string) error {
	// if it's an ip convert it to cidr representation
	if IsIP(ipcidr) {
		ipcidr += singleIPSuffix
	}
	// Check if it's a cidr
	_, network, err := net.ParseCIDR(ipcidr)
	if err != nil {
		return err
	}

	ir.TotalIps -= mapcidr.AddressCountIpnet(network)

	_, err = ir.Ranger.Remove(*network)
	return err
}

func (ir *IPRanger) Exclude(ipcidr string) error {
	if !ir.IsExcluded(ipcidr) {
		return nil
	}
	// if it's an ip convert it to cidr representation
	if IsIP(ipcidr) {
		ipcidr += singleIPSuffix
	}
	// Check if it's a cidr
	_, network, err := net.ParseCIDR(ipcidr)
	if err != nil {
		return err
	}

	ir.TotalExcludeIps += mapcidr.AddressCountIpnet(network)

	return ir.RangerExclude.Insert(cidranger.NewBasicRangerEntry(*network))
}

func (ir *IPRanger) Len() int {
	return ir.Ranger.Len()
}

func (ir *IPRanger) LenExclude() int {
	return ir.RangerExclude.Len()
}

func (ir *IPRanger) CountIPS() int {
	return int(ir.TotalIps)
}

func (ir *IPRanger) CountExcludedIps() int {
	return int(ir.TotalExcludeIps)
}

func (ir *IPRanger) IsExcluded(ipcidr string) bool {
	contains, err := ir.RangerExclude.Contains(net.ParseIP(ipcidr))
	return contains && err != nil
}

func (ir *IPRanger) ContainsSkipExclude(ipcidr string) bool {
	contains, err := ir.Ranger.Contains(net.ParseIP(ipcidr))
	return contains && err == nil
}

func (ir *IPRanger) Contains(ipcidr string) bool {
	return !ir.IsExcluded(ipcidr) && ir.ContainsSkipExclude(ipcidr)
}

func (ir *IPRanger) AddFqdn(ip, fqdn string) error {
	// dedupe all the hosts and also keep track of ip => host for the output - just append new hostname
	if data, ok := ir.Targets.Get(ip); ok {
		// check if fqdn not contained
		if !bytes.Contains(data, []byte(fqdn)) {
			fqdns := strings.Split(string(data), ",")
			fqdns = append(fqdns, fqdn)
			return ir.Targets.Set(ip, []byte(strings.Join(fqdns, ",")))
		}
		// fqdn already contained
		return nil
	}

	ir.TotalFqdn++

	return ir.Targets.Set(ip, []byte(fqdn))
}

func (ir *IPRanger) HasIP(ip string) bool {
	_, ok := ir.Targets.Get(ip)
	return ok
}

func (ir *IPRanger) GetFQDNByIP(ip string) ([]string, error) {
	dt, ok := ir.Targets.Get(ip)
	if ok {
		return strings.Split(string(dt), ","), nil
	}

	// if not found return the ip
	return []string{ip}, nil
}

func (ir *IPRanger) Close() error {
	return ir.Targets.Close()
}
