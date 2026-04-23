package runner

import (
	"testing"
	"time"

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
