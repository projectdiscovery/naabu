package runner

import (
	"os"
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/utils/errkit"
	"github.com/stretchr/testify/assert"
)

func TestOptions(t *testing.T) {
	options := Options{}
	assert.ErrorIs(t, errNoInputList, options.ValidateOptions())

	options.Host = []string{"target1", "target2"}
	options.Timeout = 2
	assert.EqualError(t, options.ValidateOptions(), errkit.Wrap(errZeroValue, "rate").Error())

	options.Resolvers = "aaabbbccc"
	assert.NotNil(t, options.ValidateOptions())

	options.Rate = 2
	options.ConnectPayload = "aabbcc"
	options.ScanType = SynScan
	assert.EqualError(t, options.ValidateOptions(), "connect payload can only be used with connect scan")
}

func TestValidateDashboardUploadWithoutInput(t *testing.T) {
	// -dashboard-upload uploads a results file and scans nothing
	options := Options{AssetFileUpload: "results.jsonl", Rate: 1000, DnsOrder: "l", ScanType: ConnectScan}
	assert.Nil(t, options.ValidateOptions())
}

func TestValidateTimingShardTxRanges(t *testing.T) {
	base := Options{
		Host:     []string{"example.com"},
		Rate:     1000,
		DnsOrder: "l",
		ScanType: ConnectScan,
	}

	t.Run("valid defaults", func(t *testing.T) {
		o := base
		assert.Nil(t, o.ValidateOptions())
	})
	t.Run("timing too high", func(t *testing.T) {
		o := base
		o.TimingTemplate = 6
		assert.ErrorContains(t, o.ValidateOptions(), "timing template")
	})
	t.Run("timing negative", func(t *testing.T) {
		o := base
		o.TimingTemplate = -1
		assert.ErrorContains(t, o.ValidateOptions(), "timing template")
	})
	t.Run("shard index out of range", func(t *testing.T) {
		o := base
		o.Shard, o.ShardTotal = 5, 4
		assert.ErrorContains(t, o.ValidateOptions(), "invalid shard")
	})
	t.Run("shard index zero", func(t *testing.T) {
		o := base
		o.Shard, o.ShardTotal = 0, 4
		assert.ErrorContains(t, o.ValidateOptions(), "invalid shard")
	})
	t.Run("valid shard", func(t *testing.T) {
		o := base
		o.Shard, o.ShardTotal = 2, 4
		assert.Nil(t, o.ValidateOptions())
	})
	t.Run("tx workers too high", func(t *testing.T) {
		o := base
		o.TxWorkers = 300
		assert.ErrorContains(t, o.ValidateOptions(), "tx-workers")
	})
	t.Run("tx workers negative", func(t *testing.T) {
		o := base
		o.TxWorkers = -1
		assert.ErrorContains(t, o.ValidateOptions(), "tx-workers")
	})
}

// TestConnectScanRateDoesNotClobberExplicitRate guards the unprivileged
// connect-scan fallback: it must only replace a rate the user left alone, not
// an explicit -rate that happens to equal the SYN default.
func TestConnectScanRateDoesNotClobberExplicitRate(t *testing.T) {
	origPriv := privileges.IsPrivileged
	defer func() { privileges.IsPrivileged = origPriv }()
	privileges.IsPrivileged = false

	base := Options{
		Host:     []string{"example.com"},
		DnsOrder: "l",
		ScanType: ConnectScan,
	}

	t.Run("unset rate gets the connect scan default", func(t *testing.T) {
		o := base
		o.Rate = DefaultRateSynScan
		assert.Nil(t, o.ValidateOptions())
		assert.Equal(t, DefaultRateConnectScan, o.Rate)
	})

	t.Run("explicit rate equal to the syn default is honored", func(t *testing.T) {
		o := base
		o.Rate = DefaultRateSynScan
		o.RateSet = true
		assert.Nil(t, o.ValidateOptions())
		assert.Equal(t, DefaultRateSynScan, o.Rate)
	})

	t.Run("explicit non default rate is honored", func(t *testing.T) {
		o := base
		o.Rate = 2000
		o.RateSet = true
		assert.Nil(t, o.ValidateOptions())
		assert.Equal(t, 2000, o.Rate)
	})

	// The cases above set RateSet directly; this one goes through the parser so
	// that ParseOptions is what has to notice the explicit flag.
	t.Run("parser marks an explicit rate", func(t *testing.T) {
		origArgs := os.Args
		defer func() { os.Args = origArgs }()

		tests := []struct {
			name string
			args []string
			want int
		}{
			{"explicit -rate equal to the syn default", []string{"naabu", "-host", "127.0.0.1", "-p", "80", "-rate", "1000", "-silent"}, DefaultRateSynScan},
			{"unset -rate", []string{"naabu", "-host", "127.0.0.1", "-p", "80", "-silent"}, DefaultRateConnectScan},
		}
		for _, tt := range tests {
			os.Args = tt.args
			o := ParseOptions()
			assert.Equal(t, tt.want, o.Rate, tt.name)
		}
	})
}

func TestDnsOrderValidation(t *testing.T) {
	base := Options{
		Host:     []string{"example.com"},
		Rate:     1000,
		DnsOrder: "l",
		ScanType: ConnectScan,
	}

	t.Run("valid local only", func(t *testing.T) {
		o := base
		o.DnsOrder = "l"
		assert.Nil(t, o.ValidateOptions())
	})

	t.Run("valid proxy only with proxy set", func(t *testing.T) {
		o := base
		o.DnsOrder = "p"
		o.Proxy = "127.0.0.1:1080"
		assert.Nil(t, o.ValidateOptions())
	})

	t.Run("valid local then proxy with proxy set", func(t *testing.T) {
		o := base
		o.DnsOrder = "lp"
		o.Proxy = "127.0.0.1:1080"
		assert.Nil(t, o.ValidateOptions())
	})

	t.Run("valid proxy then local with proxy set", func(t *testing.T) {
		o := base
		o.DnsOrder = "pl"
		o.Proxy = "127.0.0.1:1080"
		assert.Nil(t, o.ValidateOptions())
	})

	t.Run("invalid dns-order value", func(t *testing.T) {
		o := base
		o.DnsOrder = "x"
		assert.EqualError(t, o.ValidateOptions(), "dns-order must be one of p, l, lp, pl")
	})

	t.Run("proxy-only dns-order without proxy flag", func(t *testing.T) {
		o := base
		o.DnsOrder = "p"
		o.Proxy = ""
		assert.EqualError(t, o.ValidateOptions(), "dns-order 'p' (proxy-only) requires --proxy to be set")
	})

	t.Run("lp dns-order without proxy flag is valid", func(t *testing.T) {
		o := base
		o.DnsOrder = "lp"
		o.Proxy = ""
		assert.Nil(t, o.ValidateOptions())
	})

	t.Run("pl dns-order without proxy flag is valid", func(t *testing.T) {
		o := base
		o.DnsOrder = "pl"
		o.Proxy = ""
		assert.Nil(t, o.ValidateOptions())
	})
}

func TestServiceVersionValidation(t *testing.T) {
	base := Options{
		Host:     []string{"example.com"},
		Rate:     1000,
		DnsOrder: "l",
		ScanType: ConnectScan,
	}

	t.Run("service version enabled with defaults", func(t *testing.T) {
		o := base
		o.ServiceVersion = true
		err := o.ValidateOptions()
		assert.Nil(t, err)
		assert.Equal(t, 25, o.ServiceVersionWorkers)
		assert.Equal(t, 5*time.Second, o.ServiceVersionTimeout)
	})

	t.Run("service version with custom workers", func(t *testing.T) {
		o := base
		o.ServiceVersion = true
		o.ServiceVersionWorkers = 50
		o.ServiceVersionTimeout = 10 * time.Second
		err := o.ValidateOptions()
		assert.Nil(t, err)
		assert.Equal(t, 50, o.ServiceVersionWorkers)
		assert.Equal(t, 10*time.Second, o.ServiceVersionTimeout)
	})

	t.Run("service version with zero workers gets default", func(t *testing.T) {
		o := base
		o.ServiceVersion = true
		o.ServiceVersionWorkers = 0
		err := o.ValidateOptions()
		assert.Nil(t, err)
		assert.Equal(t, 25, o.ServiceVersionWorkers)
	})

	t.Run("service version with zero timeout gets default", func(t *testing.T) {
		o := base
		o.ServiceVersion = true
		o.ServiceVersionTimeout = 0
		err := o.ValidateOptions()
		assert.Nil(t, err)
		assert.Equal(t, 5*time.Second, o.ServiceVersionTimeout)
	})

	t.Run("service discovery without service version is valid", func(t *testing.T) {
		o := base
		o.ServiceDiscovery = true
		err := o.ValidateOptions()
		assert.Nil(t, err)
	})

	t.Run("service version not enabled does not set defaults", func(t *testing.T) {
		o := base
		err := o.ValidateOptions()
		assert.Nil(t, err)
		assert.Equal(t, 0, o.ServiceVersionWorkers)
	})
}
