package runner

import (
	"testing"

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

	t.Run("proxy dns-order without proxy flag", func(t *testing.T) {
		o := base
		o.DnsOrder = "p"
		o.Proxy = ""
		assert.EqualError(t, o.ValidateOptions(), "dns-order containing 'p' (proxy) requires --proxy to be set")
	})

	t.Run("lp dns-order without proxy flag", func(t *testing.T) {
		o := base
		o.DnsOrder = "lp"
		o.Proxy = ""
		assert.EqualError(t, o.ValidateOptions(), "dns-order containing 'p' (proxy) requires --proxy to be set")
	})
}
