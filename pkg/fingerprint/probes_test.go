package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const tinyProbeDB = `
Probe TCP NULL q||
match ssh m|^SSH-| p/OpenSSH/

Probe UDP DNS q|\0|
ports 53
match dns m|^\0| p/DNS/
`

func withProbeCachePath(t *testing.T, path string) {
	t.Helper()
	old := probeCachePathOverride
	probeCachePathOverride = path
	t.Cleanup(func() {
		probeCachePathOverride = old
	})
}

func withProbeUpdateURL(t *testing.T, url string) {
	t.Helper()
	old := probeUpdateURLOverride
	probeUpdateURLOverride = url
	t.Cleanup(func() {
		probeUpdateURLOverride = old
	})
}

func TestParseEmbeddedProbes(t *testing.T) {
	db, err := ParseEmbeddedProbes()
	if err != nil {
		t.Fatalf("ParseEmbeddedProbes() error = %v", err)
	}
	if len(db.Probes) == 0 {
		t.Fatal("ParseEmbeddedProbes() returned no probes")
	}
	if db.Probes[0].Name != "NULL" {
		t.Fatalf("first embedded probe = %q, want NULL", db.Probes[0].Name)
	}
}

func TestParseDefaultProbeDBUsesCacheFirst(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), probeFileName)
	withProbeCachePath(t, cachePath)

	if err := os.WriteFile(cachePath, []byte(tinyProbeDB), 0600); err != nil {
		t.Fatal(err)
	}

	db, source, err := ParseDefaultProbeDB()
	if err != nil {
		t.Fatalf("ParseDefaultProbeDB() error = %v", err)
	}
	if source != cachePath {
		t.Fatalf("source = %q, want %q", source, cachePath)
	}
	if len(db.Probes) != 2 {
		t.Fatalf("probes = %d, want 2", len(db.Probes))
	}
}

func TestParseProbeSourceCustomPathWins(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "cache", probeFileName)
	customPath := filepath.Join(t.TempDir(), "custom-probes")
	withProbeCachePath(t, cachePath)

	if err := os.MkdirAll(filepath.Dir(cachePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte(tinyProbeDB), 0600); err != nil {
		t.Fatal(err)
	}
	customDB := strings.Replace(tinyProbeDB, "OpenSSH", "CustomSSH", 1)
	if err := os.WriteFile(customPath, []byte(customDB), 0600); err != nil {
		t.Fatal(err)
	}

	db, source, err := ParseProbeSource(customPath)
	if err != nil {
		t.Fatalf("ParseProbeSource() error = %v", err)
	}
	if source != customPath {
		t.Fatalf("source = %q, want %q", source, customPath)
	}
	if got := db.Probes[0].Matches[0].Product; got != "CustomSSH" {
		t.Fatalf("product = %q, want CustomSSH", got)
	}
}

func TestUpdateDefaultProbesValidatesAndWritesCache(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "naabu", probeFileName)
	withProbeCachePath(t, cachePath)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, tinyProbeDB)
	}))
	defer server.Close()
	withProbeUpdateURL(t, server.URL)

	path, updated, err := UpdateDefaultProbes(context.Background())
	if err != nil {
		t.Fatalf("UpdateDefaultProbes() error = %v", err)
	}
	if !updated {
		t.Fatal("updated = false, want true")
	}
	if path != cachePath {
		t.Fatalf("path = %q, want %q", path, cachePath)
	}
	if _, err := ParseProbeFile(cachePath); err != nil {
		t.Fatalf("cached probes failed parse: %v", err)
	}
}

func TestUpdateDefaultProbesRejectsInvalidContent(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), probeFileName)
	withProbeCachePath(t, cachePath)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not a probe file")
	}))
	defer server.Close()
	withProbeUpdateURL(t, server.URL)

	_, updated, err := UpdateDefaultProbes(context.Background())
	if err == nil {
		t.Fatal("UpdateDefaultProbes() error = nil, want validation error")
	}
	if updated {
		t.Fatal("updated = true, want false")
	}
	if _, statErr := os.Stat(cachePath); !os.IsNotExist(statErr) {
		t.Fatalf("cache file exists after invalid update: %v", statErr)
	}
}
