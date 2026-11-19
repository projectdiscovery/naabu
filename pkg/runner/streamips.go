package runner

import (
	"context"
	"net"

	"github.com/projectdiscovery/mapcidr"
)

// eachCIDRAddress walks cidr from the first address to the last, in the same
// order as mapcidr.IPAddressesAsStream. It returns true when it stops early
// because ctx is done or yield returns false. The walk itself checks ctx, so
// an enormous range such as fd00::/64 does not keep a generator running.
func eachCIDRAddress(ctx context.Context, cidr string, yield func(ip string) bool) (bool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, err
	}
	network = ipv4MappedAsV4(network)
	first, last, err := mapcidr.AddressRange(network)
	if err != nil {
		return false, err
	}
	ip := append(net.IP(nil), first...)
	for {
		if ctx.Err() != nil {
			return true, nil
		}
		if !yield(ip.String()) {
			return true, nil
		}
		if ip.Equal(last) {
			return false, nil
		}
		next := mapcidr.GetNextIP(ip)
		if next.Equal(ip) {
			return false, nil
		}
		ip = next
	}
}

// ipv4MappedAsV4 rewrites an IPv4-mapped network as a 4-byte CIDR.
// AddressRange sizes the host portion from IPToInteger, which reports 32 bits
// for a mapped address, while the mask can still be 128 bits wide. A prefix
// above 32 then wraps that subtraction and Lsh panics.
func ipv4MappedAsV4(network *net.IPNet) *net.IPNet {
	ip4 := network.IP.To4()
	if ip4 == nil {
		return network
	}
	ones, bits := network.Mask.Size()
	if bits != 128 {
		return network
	}
	ones -= 96
	if ones < 0 {
		ones = 0
	}
	return &net.IPNet{IP: ip4, Mask: net.CIDRMask(ones, 32)}
}
