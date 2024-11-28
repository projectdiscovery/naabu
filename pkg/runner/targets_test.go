package runner

import (
	"testing"

	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/stretchr/testify/require"
)

func Test_AddTarget(t *testing.T) {
	ipranger, _ := ipranger.New()
	defer ipranger.Close()

	r := &Runner{
		options: &Options{},
		scanner: &scan.Scanner{IPRanger: ipranger},
	}

	// IPV6 Compressed should generate a warning
	err := r.AddTarget("::ffff:c0a8:101")
	require.Nil(t, err, "compressed ipv6 incorrectly parsed")

	// IPV6 Expanded (Shortened)
	err = r.AddTarget("0:0:0:0:0:ffff:c0a8:0101")
	require.Nil(t, err, "expanded shortened ipv6 incorrectly parsed")

	// IPV6 Expanded
	err = r.AddTarget("0000:0000:0000:0000:0000:ffff:c0a8:0101")
	require.Nil(t, err, "fully expanded ipv6 incorrectly parsed")

	// IPV4
	err = r.AddTarget("127.0.0.1")
	require.Nil(t, err, "ipv4 incorrectly parsed")

	// IPV4 cidr
	err = r.AddTarget("127.0.0.1/24")
	require.Nil(t, err, "ipv4 cidr incorrectly parsed")

	// todo: excluding due to api instability (https://github.com/projectdiscovery/asnmap/issues/198)
	// err = r.AddTarget("AS14421")
	// require.Nil(t, err, "ASN incorrectly parsed")
}
