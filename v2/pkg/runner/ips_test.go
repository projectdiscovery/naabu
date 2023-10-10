package runner

import (
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
