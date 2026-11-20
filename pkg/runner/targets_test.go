package runner

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/stretchr/testify/require"
)

func Test_AddTarget(t *testing.T) {
	ipranger, _ := ipranger.New()
	defer func() {
		if err := ipranger.Close(); err != nil {
			log.Printf("could not close ipranger: %s\n", err)
		}
	}()

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

// TestAddTargetsStreamsBeforeEOF ensures a piped target reaches the stream
// scanner while the producer is still writing, not only after it closes.
func TestAddTargetsStreamsBeforeEOF(t *testing.T) {
	ipranger, err := ipranger.New()
	require.NoError(t, err)
	defer func() { _ = ipranger.Close() }()

	r := &Runner{
		options:       &Options{Stream: true, Threads: 1},
		scanner:       &scan.Scanner{IPRanger: ipranger},
		streamChannel: make(chan Target),
	}
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- r.addTargets(pr) }()

	_, err = pw.Write([]byte("127.0.0.1\n"))
	require.NoError(t, err)
	select {
	case target := <-r.streamChannel:
		require.Equal(t, "127.0.0.1/32", target.Cidr)
	case <-time.After(2 * time.Second):
		t.Fatal("target must be streamed before the input closes")
	}

	require.NoError(t, pw.Close())
	require.NoError(t, <-done)
}
