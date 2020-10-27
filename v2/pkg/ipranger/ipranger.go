package ipranger

import (
	"net"
	"strings"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/mapcidr"
	"github.com/yl2chen/cidranger"
)

type IPRanger struct {
	TotalIps        uint64
	Ranger          cidranger.Ranger
	TotalExcludeIps uint64
	RangerExclude   cidranger.Ranger
	TotalFqdn       uint64
	Fqdn2ip         *hybrid.HybridMap
	ports           []int
}

func New() (*IPRanger, error) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}
	rangerIn := cidranger.NewPCTrieRanger()
	rangerExclude := cidranger.NewPCTrieRanger()

	return &IPRanger{Ranger: rangerIn, RangerExclude: rangerExclude, Fqdn2ip: hm}, nil
}

func (ir *IPRanger) Add(ipcidr string) error {
	if ir.Contains(ipcidr) {
		return nil
	}

	// if it's an ip convert it to cidr representation
	if IsIP(ipcidr) {
		ipcidr += "/32"
	}
	// Check if it's a cidr
	_, network, err := net.ParseCIDR(ipcidr)
	if err != nil {
		return err
	}

	ir.TotalIps += mapcidr.AddressCountIpnet(network)

	return ir.Ranger.Insert(cidranger.NewBasicRangerEntry(*network))
}

func (ir *IPRanger) Delete(ipcidr string) error {
	// if it's an ip convert it to cidr representation
	if IsIP(ipcidr) {
		ipcidr += "/32"
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
		ipcidr += "/32"
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

func (ir *IPRanger) AddFqdn(ip string, fqdn string) error {
	// dedupe all the hosts and also keep track of ip => host for the output - just append new hostname
	if data, ok := ir.Fqdn2ip.Get(ip); ok {
		fqdns := strings.Split(string(data), ",")
		fqdns = append(fqdns, fqdn)
		return ir.Fqdn2ip.Set(ip, []byte(strings.Join(fqdns, ",")))
	}

	ir.TotalFqdn++

	return ir.Fqdn2ip.Set(ip, []byte(fqdn))
}

func (ir *IPRanger) HasIp(ip string) bool {
	_, ok := ir.Fqdn2ip.Get(ip)
	return ok
}

func (ir *IPRanger) GetFQDNByIp(ip string) ([]string, error) {
	dt, ok := ir.Fqdn2ip.Get(ip)
	if ok {
		return strings.Split(string(dt), ","), nil
	}

	return []string{}, nil
}

func (ir *IPRanger) Close() error {
	return ir.Fqdn2ip.Close()
}
