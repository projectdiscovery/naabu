package runner

import (
	"net"
	"os"
	"strings"
	"testing"

	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/stretchr/testify/require"
)

func TestParseExcludedIps(t *testing.T) {
	tmpFileName, err := fileutil.GetTempFileName()
	require.Nil(t, err)
	expectedIpsFromCLI := []string{"8.8.8.0/24", "7.7.7.7"}
	expectedIpsFromFile := []string{"10.10.10.0/24", "192.168.1.0/24"}
	require.Nil(t, os.WriteFile(tmpFileName, []byte(strings.Join(expectedIpsFromFile, "\n")), 0755))
	expected := append(expectedIpsFromCLI, expectedIpsFromFile...)

	r, err := NewRunner(&Options{})
	require.Nil(t, err)

	actual, err := r.parseExcludedIps(&Options{
		ExcludeIps:     strings.Join(expectedIpsFromCLI, ","),
		ExcludeIpsFile: tmpFileName,
	})
	require.Nil(t, err)
	require.Equal(t, expected, actual)

	defer os.RemoveAll(tmpFileName)
}

func TestIsIpOrCidr(t *testing.T) {
	valid := []string{"1.1.1.1", "2.2.2.2", "1.1.1.0/24"}
	invalid := []string{"1.1.1.1.1", "a.a.a.a", "77"}
	for _, validItem := range valid {
		require.True(t, isIpOrCidr(validItem))
	}
	for _, invalidItem := range invalid {
		require.False(t, isIpOrCidr(invalidItem))
	}
}

// Helper function for the following 3 tests
func testIps(testIps []string) func() ([]*net.IPNet, []string) {
	ips := []*net.IPNet{}

	for _, ip := range testIps {
		_, net, _ := net.ParseCIDR(ip)
		ips = append(ips, net)
	}

	return func() ([]*net.IPNet, []string) {
		return ips, []string{}
	}
}

func TestIpV4Only(t *testing.T) {
	ips := []string{"1.1.1.1/32", "2.2.2.2/32", "1.1.1.0/24", "fe80::623e:5fff:fe76:7d82/64", "100.121.237.116/32", "fd7a:115c:a1e0::fb01:ed74/48"}

	r, err := NewRunner(&Options{
		IPVersion: []string{"4"},
	})
	require.Nil(t, err)

	targets, targetsV4, targetsV6, _, err := r.GetTargetIps(testIps(ips))
	require.Nil(t, err)
	require.Equal(t, targets, targetsV4)
	require.Empty(t, targetsV6)
}

func TestIpV6Only(t *testing.T) {
	ips := []string{"1.1.1.1/32", "2.2.2.2/32", "1.1.1.0/24", "fe80::623e:5fff:fe76:7d82/64", "100.121.237.116/32", "fd7a:115c:a1e0::fb01:ed74/48"}

	r, err := NewRunner(&Options{
		IPVersion: []string{"6"},
	})
	require.Nil(t, err)

	targets, targetsV4, targetsV6, _, err := r.GetTargetIps(testIps(ips))
	require.Nil(t, err)
	require.Equal(t, targets, targetsV6)
	require.Empty(t, targetsV4)
}

func TestIpV4AndV6(t *testing.T) {
	ips := []string{"1.1.1.1/32", "2.2.2.2/32", "1.1.1.0/24", "fe80::623e:5fff:fe76:7d82/64", "100.121.237.116/32", "fd7a:115c:a1e0::fb01:ed74/48"}

	r, err := NewRunner(&Options{
		IPVersion: []string{"4", "6"},
	})
	require.Nil(t, err)

	targets, targetsV4, targetsV6, _, err := r.GetTargetIps(testIps(ips))
	expected := append(targetsV4, targetsV6...)

	require.Nil(t, err)
	require.EqualValues(t, expected, targets)
}
