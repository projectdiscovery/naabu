package runner

import (
	"testing"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_host2ips(t *testing.T) {
	tests := []struct {
		args    string
		want    []string
		wantV6  []string
		wantErr bool
	}{
		{"10.10.10.10", []string{"10.10.10.10"}, nil, false},
		{"localhost", []string{"127.0.0.1"}, []string{"::1"}, false}, // some linux distribution don't have ::1 in /etc/hosts
		{"aaaa", nil, nil, true},
		{"10.10.10.0/24", nil, nil, true},
	}

	r, err := NewRunner(&Options{IPVersion: []string{scan.IPv4, scan.IPv6}, Retries: 1})
	require.Nil(t, err)
	dnsclient, err := dnsx.New(dnsx.DefaultOptions)
	require.Nil(t, err)
	r.dnsclient = dnsclient

	for _, tt := range tests {
		t.Run(tt.args, func(t *testing.T) {
			got, gotV6, err := r.host2ips(tt.args)
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, tt.want, got)
			// As some distributions don't handle correctly ipv6 we compare results only if necessary
			if len(gotV6) > 0 && len(tt.wantV6) > 0 {
				assert.Equal(t, tt.wantV6, gotV6)
			}
		})
	}
}

func Test_host2ips_DnsOrder(t *testing.T) {
	t.Run("default dns-order resolves via local client", func(t *testing.T) {
		r, err := NewRunner(&Options{IPVersion: []string{scan.IPv4, scan.IPv6}, Retries: 1})
		require.Nil(t, err)

		assert.Equal(t, "l", r.options.DnsOrder)
		got, _, err := r.host2ips("localhost")
		assert.Nil(t, err)
		assert.Equal(t, []string{"127.0.0.1"}, got)
	})

	t.Run("explicit dns-order l resolves via local client", func(t *testing.T) {
		r, err := NewRunner(&Options{IPVersion: []string{scan.IPv4, scan.IPv6}, Retries: 1, DnsOrder: "l"})
		require.Nil(t, err)

		got, _, err := r.host2ips("localhost")
		assert.Nil(t, err)
		assert.Equal(t, []string{"127.0.0.1"}, got)
	})

	t.Run("dns-order lp falls back when no proxy client", func(t *testing.T) {
		r, err := NewRunner(&Options{IPVersion: []string{scan.IPv4, scan.IPv6}, Retries: 1, DnsOrder: "lp"})
		require.Nil(t, err)
		assert.Nil(t, r.dnsclientProxy)

		got, _, err := r.host2ips("localhost")
		assert.Nil(t, err)
		assert.Equal(t, []string{"127.0.0.1"}, got)
	})
}

func Test_host2ips_SystemResolver(t *testing.T) {
	t.Run("system-resolver off does not fallback", func(t *testing.T) {
		r, err := NewRunner(&Options{IPVersion: []string{scan.IPv4}, Retries: 1})
		require.Nil(t, err)
		assert.False(t, r.options.SystemResolver)

		// "aaaa" is unresolvable by primary DNS; with SystemResolver off, no fallback
		_, _, err = r.host2ips("aaaa")
		assert.NotNil(t, err)
	})

	t.Run("system-resolver on enables fallback for valid host", func(t *testing.T) {
		r, err := NewRunner(&Options{IPVersion: []string{scan.IPv4}, Retries: 1, SystemResolver: true})
		require.Nil(t, err)

		// localhost should be resolvable by the system resolver even if primary DNS fails
		got, _, err := r.host2ips("localhost")
		assert.Nil(t, err)
		assert.Equal(t, []string{"127.0.0.1"}, got)
	})

	t.Run("system-resolver on still errors for unresolvable host", func(t *testing.T) {
		r, err := NewRunner(&Options{IPVersion: []string{scan.IPv4}, Retries: 1, SystemResolver: true})
		require.Nil(t, err)

		_, _, err = r.host2ips("this-host-does-not-exist-xyz.invalid")
		assert.NotNil(t, err)
	})
}
