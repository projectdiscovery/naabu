// Package macvendor resolves the hardware vendor of a MAC address from its
// 24-bit Organizationally Unique Identifier (OUI).
//
// The lookup table is embedded at build time from the public IEEE MA-L
// registry (see the gen command). The dataset is refreshed via
// `go generate ./pkg/macvendor/...` and by the update-oui CI workflow, so the
// signatures stay current with no network access required at runtime.
package macvendor

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net"
	"strings"
	"sync"
)

//go:generate go run ./gen

//go:embed oui.dat.gz
var embedded []byte

var (
	once sync.Once
	db   map[string]string
)

// load decompresses and parses the embedded dataset into the lookup map. It
// runs at most once, lazily, on the first lookup.
func load() {
	db = make(map[string]string, 40000)

	gr, err := gzip.NewReader(bytes.NewReader(embedded))
	if err != nil {
		return
	}
	defer func() { _ = gr.Close() }()

	scanner := bufio.NewScanner(gr)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		tab := strings.IndexByte(line, '\t')
		if tab <= 0 {
			continue
		}
		db[line[:tab]] = line[tab+1:]
	}
}

// Lookup returns the vendor associated with a MAC address or bare OUI, or an
// empty string when the address is too short or the prefix is unknown. The
// input may use any (or no) separators and any letter case.
func Lookup(addr string) string {
	prefix := normalizeHex(addr)
	if len(prefix) < 6 {
		return ""
	}
	once.Do(load)
	return db[prefix[:6]]
}

// VendorFromMAC returns the vendor of a parsed hardware address. Both 48- and
// 64-bit addresses are supported since the OUI is the first 24 bits of each.
func VendorFromMAC(mac net.HardwareAddr) string {
	return Lookup(mac.String())
}

// normalizeHex keeps only hex digits and lower-cases them, discarding any
// separators so callers can pass "aa:bb:cc", "AA-BB-CC", "aabbcc", etc.
func normalizeHex(addr string) string {
	var b strings.Builder
	b.Grow(len(addr))
	for _, r := range addr {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		case r >= 'A' && r <= 'F':
			b.WriteRune(r + ('a' - 'A'))
		}
	}
	return b.String()
}
