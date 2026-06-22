// Command gen regenerates the embedded OUI dataset used by the macvendor
// package. It downloads the public IEEE MA-L registry (the authoritative
// source for 24-bit OUI -> organization mappings) and writes a compact,
// gzipped "<oui-hex>\t<vendor>" dataset to oui.dat.gz.
//
// It is invoked via `go generate ./pkg/macvendor/...` and by the
// update-oui CI workflow so the signatures can be refreshed automatically
// (e.g. on release).
package main

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// ieeeOUIURL is the official IEEE MA-L registry in CSV form.
const ieeeOUIURL = "https://standards-oui.ieee.org/oui/oui.csv"

const outputFile = "oui.dat.gz"

func main() {
	if err := run(); err != nil {
		log.Fatalf("macvendor/gen: %s", err)
	}
}

func run() error {
	url := ieeeOUIURL
	if env := os.Getenv("OUI_SOURCE_URL"); env != "" {
		url = env
	}

	log.Printf("downloading OUI registry from %s", url)
	rows, err := fetch(url)
	if err != nil {
		return err
	}

	lines, err := parse(rows)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return fmt.Errorf("no OUI entries parsed from %s", url)
	}
	sort.Strings(lines)

	log.Printf("writing %d OUI entries to %s", len(lines), outputFile)
	return write(outputFile, lines)
}

func fetch(url string) (io.ReadCloser, error) {
	client := &http.Client{Timeout: 2 * time.Minute}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// IEEE occasionally rejects requests without a UA.
	req.Header.Set("User-Agent", "naabu-oui-generator")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("unexpected status %d fetching %s", resp.StatusCode, url)
	}
	return resp.Body, nil
}

// parse reads the IEEE CSV (columns: Registry, Assignment, Organization Name,
// Organization Address) and returns deduplicated "<oui>\t<vendor>" lines.
func parse(r io.ReadCloser) ([]string, error) {
	defer func() { _ = r.Close() }()

	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1

	seen := make(map[string]string)
	first := true
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if first {
			first = false // skip header row
			continue
		}
		if len(record) < 3 {
			continue
		}

		oui := normalizeHex(record[1])
		if len(oui) != 6 {
			continue
		}
		vendor := sanitize(record[2])
		if vendor == "" {
			continue
		}
		seen[oui] = vendor
	}

	lines := make([]string, 0, len(seen))
	for oui, vendor := range seen {
		lines = append(lines, oui+"\t"+vendor)
	}
	return lines, nil
}

func normalizeHex(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		case r >= 'A' && r <= 'F':
			b.WriteRune(r + ('a' - 'A'))
		}
	}
	return b.String()
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func write(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	for _, line := range lines {
		if _, err := gw.Write([]byte(line + "\n")); err != nil {
			_ = gw.Close()
			return err
		}
	}
	return gw.Close()
}
