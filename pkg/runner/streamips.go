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
