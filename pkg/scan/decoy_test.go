package scan

import (
	"testing"

	"github.com/Mzack9999/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestIsDecoySynAck(t *testing.T) {
	mss := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xb4},
	}

	cases := []struct {
		name  string
		tcp   layers.TCP
		decoy bool
	}{
		{
			name: "middlebox win0 no options",
			tcp: layers.TCP{
				SYN:        true,
				ACK:        true,
				Window:     0,
				DataOffset: 5,
			},
			decoy: true,
		},
		{
			name: "middlebox win0 empty options slice",
			tcp: layers.TCP{
				SYN:    true,
				ACK:    true,
				Window: 0,
			},
			decoy: true,
		},
		{
			name: "real stack non-zero window with MSS",
			tcp: layers.TCP{
				SYN:        true,
				ACK:        true,
				Window:     65535,
				DataOffset: 6,
				Options:    []layers.TCPOption{mss},
			},
			decoy: false,
		},
		{
			name: "win0 but has MSS - keep",
			tcp: layers.TCP{
				SYN:        true,
				ACK:        true,
				Window:     0,
				DataOffset: 6,
				Options:    []layers.TCPOption{mss},
			},
			decoy: false,
		},
		{
			name: "non-zero window no options - keep",
			tcp: layers.TCP{
				SYN:        true,
				ACK:        true,
				Window:     8192,
				DataOffset: 5,
			},
			decoy: false,
		},
		{
			name: "DataOffset claims options even if Options empty - keep",
			tcp: layers.TCP{
				SYN:        true,
				ACK:        true,
				Window:     0,
				DataOffset: 8,
			},
			decoy: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.decoy, isDecoySynAck(tc.tcp))
		})
	}
}
