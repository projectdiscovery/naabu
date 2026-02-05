package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanHistory(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		format   string
		scope    string
		ttl      time.Duration
		wantErr  bool
	}{
		{
			name:     "valid txt format",
			filePath: filepath.Join(t.TempDir(), "test-scan-txt.log"),
			format:   "txt",
			scope:    "host",
			ttl:      0,
			wantErr:  false,
		},
		{
			name:     "valid json format",
			filePath: filepath.Join(t.TempDir(), "test-scan-json.json"),
			format:   "json",
			scope:    "host",
			ttl:      time.Hour,
			wantErr:  false,
		},
		{
			name:     "valid with TTL",
			filePath: filepath.Join(t.TempDir(), "test-scan-ttl.log"),
			format:   "txt",
			scope:    "host",
			ttl:      24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "empty format defaults to txt",
			filePath: filepath.Join(t.TempDir(), "test-scan-default.log"),
			format:   "",
			scope:    "host",
			ttl:      0,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sh, err := NewScanHistory(tt.filePath, tt.format, tt.scope, tt.ttl)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, sh)
				assert.Equal(t, tt.filePath, sh.filePath)
				assert.Equal(t, tt.ttl, sh.ttl)
				assert.NotNil(t, sh.entries)
			}
		})
	}
}

func TestScanHistory_RecordAndIsScanned(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test-history-record.log")

	sh, err := NewScanHistory(tmpFile, "txt", "host", 0)
	require.NoError(t, err)

	t.Run("new target not scanned", func(t *testing.T) {
		assert.False(t, sh.IsScanned("example.com"))
		assert.False(t, sh.IsScanned("google.com"))
	})

	t.Run("record single target", func(t *testing.T) {
		err := sh.Record("example.com", "1.2.3.4")
		assert.NoError(t, err)
		assert.True(t, sh.IsScanned("example.com"))
		assert.False(t, sh.IsScanned("google.com"))
	})

	t.Run("record updates scan count", func(t *testing.T) {
		err := sh.Record("example.com", "1.2.3.4")
		assert.NoError(t, err)

		sh.mutex.RLock()
		entry := sh.entries["example.com"]
		sh.mutex.RUnlock()

		assert.Equal(t, 2, entry.ScanCount)
		assert.Equal(t, "example.com", entry.Target)
		assert.Equal(t, "1.2.3.4", entry.IP)
	})

	t.Run("record multiple targets", func(t *testing.T) {
		targets := []struct {
			host string
			ip   string
		}{
			{"google.com", "8.8.8.8"},
			{"github.com", "140.82.112.3"},
			{"cloudflare.com", "1.1.1.1"},
		}

		for _, target := range targets {
			err := sh.Record(target.host, target.ip)
			assert.NoError(t, err)
		}

		for _, target := range targets {
			assert.True(t, sh.IsScanned(target.host))
		}

		assert.Equal(t, 4, len(sh.entries)) // example.com + 3 new
	})

	t.Run("record updates timestamp", func(t *testing.T) {
		sh.mutex.RLock()
		firstScan := sh.entries["example.com"].FirstScan
		lastScan1 := sh.entries["example.com"].LastScan
		sh.mutex.RUnlock()

		time.Sleep(10 * time.Millisecond)

		err := sh.Record("example.com", "1.2.3.4")
		require.NoError(t, err)

		sh.mutex.RLock()
		lastScan2 := sh.entries["example.com"].LastScan
		sh.mutex.RUnlock()

		assert.Equal(t, firstScan, sh.entries["example.com"].FirstScan)
		assert.True(t, lastScan2.After(lastScan1))
	})
}

func TestScanHistory_TTLExpiration(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test-ttl-expiration.log")

	// Create with 100ms TTL
	sh, err := NewScanHistory(tmpFile, "txt", "host", 100*time.Millisecond)
	require.NoError(t, err)

	// Record a target
	err = sh.Record("example.com", "1.2.3.4")
	require.NoError(t, err)

	t.Run("target valid within TTL", func(t *testing.T) {
		assert.True(t, sh.IsScanned("example.com"))
	})

	t.Run("target expired after TTL", func(t *testing.T) {
		time.Sleep(150 * time.Millisecond) // Wait for TTL to expire
		assert.False(t, sh.IsScanned("example.com"))
	})

	t.Run("no TTL means never expires", func(t *testing.T) {
		sh2, err := NewScanHistory(filepath.Join(t.TempDir(), "test-no-ttl.log"), "txt", "host", 0)
		require.NoError(t, err)

		sh2.Record("permanent.com", "1.2.3.4")
		time.Sleep(200 * time.Millisecond)
		assert.True(t, sh2.IsScanned("permanent.com"))
	})
}

func TestScanHistory_TxtFormat(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test-txt-format.log")

	sh, err := NewScanHistory(tmpFile, "txt", "host", 0)
	require.NoError(t, err)

	// Record some entries
	testData := []struct {
		host string
		ip   string
	}{
		{"example.com", "1.2.3.4"},
		{"google.com", "8.8.8.8"},
		{"github.com", "140.82.112.3"},
	}

	for _, td := range testData {
		err := sh.Record(td.host, td.ip)
		require.NoError(t, err)
	}

	// Save
	err = sh.Save()
	require.NoError(t, err)

	// Verify file exists and has content
	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "# Naabu Scan History")
	assert.Contains(t, string(content), "example.com|1.2.3.4")
	assert.Contains(t, string(content), "google.com|8.8.8.8")
	assert.Contains(t, string(content), "github.com|140.82.112.3")

	// Load in new instance
	sh2, err := NewScanHistory(tmpFile, "txt", "host", 0)
	require.NoError(t, err)

	// Verify entries loaded
	for _, td := range testData {
		assert.True(t, sh2.IsScanned(td.host))
	}
	assert.Equal(t, len(testData), len(sh2.entries))

	// Verify entry details
	sh2.mutex.RLock()
	entry := sh2.entries["example.com"]
	sh2.mutex.RUnlock()
	assert.Equal(t, "example.com", entry.Target)
	assert.Equal(t, "1.2.3.4", entry.IP)
	assert.Greater(t, entry.ScanCount, 0)
}

func TestScanHistory_JsonFormat(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test-json-format.json")

	sh, err := NewScanHistory(tmpFile, "json", "host", 0)
	require.NoError(t, err)

	// Record some entries
	testData := []struct {
		host string
		ip   string
	}{
		{"example.com", "1.2.3.4"},
		{"google.com", "8.8.8.8"},
	}

	for _, td := range testData {
		err := sh.Record(td.host, td.ip)
		require.NoError(t, err)
	}

	// Save
	err = sh.Save()
	require.NoError(t, err)

	// Verify file exists and has valid JSON
	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "example.com")
	assert.Contains(t, string(content), "1.2.3.4")

	// Load in new instance
	sh2, err := NewScanHistory(tmpFile, "json", "host", 0)
	require.NoError(t, err)

	// Verify entries loaded
	for _, td := range testData {
		assert.True(t, sh2.IsScanned(td.host))
	}
	assert.Equal(t, len(testData), len(sh2.entries))
}

func TestScanHistory_DirtyFlag(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test-dirty-flag.log")

	sh, err := NewScanHistory(tmpFile, "txt", "host", 0)
	require.NoError(t, err)

	t.Run("dirty flag set after record", func(t *testing.T) {
		assert.False(t, sh.existUnsaved)
		sh.Record("example.com", "1.2.3.4")
		assert.True(t, sh.existUnsaved)
	})

	t.Run("dirty flag cleared after save", func(t *testing.T) {
		err := sh.Save()
		require.NoError(t, err)
		assert.False(t, sh.existUnsaved)
	})

	t.Run("no file modification when not dirty", func(t *testing.T) {
		// Get file mod time
		info1, err := os.Stat(tmpFile)
		require.NoError(t, err)
		modTime1 := info1.ModTime()

		time.Sleep(10 * time.Millisecond)

		// Save again without changes
		err = sh.Save()
		require.NoError(t, err)

		// File should not have been modified
		info2, err := os.Stat(tmpFile)
		require.NoError(t, err)
		modTime2 := info2.ModTime()

		assert.Equal(t, modTime1, modTime2)
	})

	t.Run("file modified when dirty", func(t *testing.T) {
		info1, err := os.Stat(tmpFile)
		require.NoError(t, err)
		modTime1 := info1.ModTime()

		time.Sleep(10 * time.Millisecond)

		// Make a change
		sh.Record("newsite.com", "5.6.7.8")

		// Save
		err = sh.Save()
		require.NoError(t, err)

		// File should have been modified
		info2, err := os.Stat(tmpFile)
		require.NoError(t, err)
		modTime2 := info2.ModTime()

		assert.True(t, modTime2.After(modTime1))
	})
}

func TestScanHistory_ConcurrentAccess(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test-concurrent-access.log")

	sh, err := NewScanHistory(tmpFile, "txt", "host", 0)
	require.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			target := fmt.Sprintf("target%d.com", id)
			sh.Record(target, fmt.Sprintf("1.2.3.%d", id))
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			target := fmt.Sprintf("target%d.com", id)
			sh.IsScanned(target)
		}(i)
	}

	wg.Wait()

	// Verify all entries recorded
	assert.Equal(t, numGoroutines, len(sh.entries))

	// Verify no data corruption
	for i := 0; i < numGoroutines; i++ {
		target := fmt.Sprintf("target%d.com", i)
		assert.True(t, sh.IsScanned(target))
	}
}

func TestScanHistory_EdgeCases(t *testing.T) {
	t.Run("empty target", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test-empty-target.log")

		sh, err := NewScanHistory(tmpFile, "txt", "host", 0)
		require.NoError(t, err)
		err = sh.Record("", "")
	})

	t.Run("malformed txt file", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test-malformed.log")

		// Write malformed data
		malformedContent := `# Naabu Scan History
invalid|data|here
too|few|fields
way|too|many|fields|here|extra|stuff
example.com|1.2.3.4|2026-01-01T00:00:00Z|2026-01-01T00:00:00Z|1
`
		err := os.WriteFile(tmpFile, []byte(malformedContent), 0644)
		require.NoError(t, err)

		// Should handle gracefully and only load valid entries
		sh, err := NewScanHistory(tmpFile, "txt", "host", 0)
		assert.NoError(t, err)
		assert.NotNil(t, sh)

		// Should have loaded the one valid entry
		assert.True(t, sh.IsScanned("example.com"))
	})

	t.Run("invalid json file", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test-invalid-json.json")

		err := os.WriteFile(tmpFile, []byte("{invalid json}"), 0644)
		require.NoError(t, err)

		_, err = NewScanHistory(tmpFile, "json", "host", 0)
		assert.Error(t, err) // Should fail on invalid JSON
	})

	t.Run("comments and blank lines in txt", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test-comments.log")

		content := `# Header comment

# Another comment
example.com|1.2.3.4|2026-01-01T00:00:00Z|2026-01-01T00:00:00Z|1

# Comment in the middle

google.com|8.8.8.8|2026-01-01T00:00:00Z|2026-01-01T00:00:00Z|2
`
		err := os.WriteFile(tmpFile, []byte(content), 0644)
		require.NoError(t, err)

		sh, err := NewScanHistory(tmpFile, "txt", "host", 0)
		require.NoError(t, err)

		assert.True(t, sh.IsScanned("example.com"))
		assert.True(t, sh.IsScanned("google.com"))
		assert.Equal(t, 2, len(sh.entries))
	})

	t.Run("unsupported format returns error on save", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test-unsupported.db")

		sh, err := NewScanHistory(tmpFile, "unsupported", "host", 0)
		require.NoError(t, err) // Creation succeeds

		sh.Record("example.com", "1.2.3.4")
		err = sh.Save()
		assert.Error(t, err) // Save should fail
		assert.Contains(t, err.Error(), "unsupported format")
	})

	t.Run("directory creation on save", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "nested", "dir", "test-scan.log")

		sh, err := NewScanHistory(tmpFile, "txt", "host", 0)
		require.NoError(t, err)

		sh.Record("example.com", "1.2.3.4")
		err = sh.Save()
		assert.NoError(t, err)

		// Verify directory was created
		assert.FileExists(t, tmpFile)
	})

	t.Run("special characters in targets", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test-special-chars.log")

		sh, _ := NewScanHistory(tmpFile, "txt", "host", 0)

		specialTargets := []string{
			"sub-domain.example.com",
			"under_score.example.com",
			"123.numeric.com",
			"mixed-123_domain.com",
		}

		for _, target := range specialTargets {
			err := sh.Record(target, "1.2.3.4")
			assert.NoError(t, err)
			assert.True(t, sh.IsScanned(target))
		}

		// Save and reload
		sh.Save()
		sh2, _ := NewScanHistory(tmpFile, "txt", "host", 0)

		for _, target := range specialTargets {
			assert.True(t, sh2.IsScanned(target))
		}
	})
}

func TestScanHistory_PersistenceRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		format string
	}{
		{"txt format round trip", "txt"},
		{"json format round trip", "json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := filepath.Join(t.TempDir(), fmt.Sprintf("test-roundtrip-%s.%s", tt.format, tt.format))

			// First instance: write data
			sh1, err := NewScanHistory(tmpFile, tt.format, "host", time.Hour)
			require.NoError(t, err)

			testData := []struct {
				host string
				ip   string
			}{
				{"example.com", "1.2.3.4"},
				{"google.com", "8.8.8.8"},
				{"github.com", "140.82.112.3"},
			}

			for _, td := range testData {
				err := sh1.Record(td.host, td.ip)
				require.NoError(t, err)
			}

			err = sh1.Save()
			require.NoError(t, err)

			// Second instance: read data
			sh2, err := NewScanHistory(tmpFile, tt.format, "host", time.Hour)
			require.NoError(t, err)

			// Verify all data persisted correctly
			for _, td := range testData {
				assert.True(t, sh2.IsScanned(td.host))

				sh2.mutex.RLock()
				entry := sh2.entries[td.host]
				sh2.mutex.RUnlock()

				assert.Equal(t, td.host, entry.Target)
				assert.Equal(t, td.ip, entry.IP)
				assert.NotZero(t, entry.FirstScan)
				assert.NotZero(t, entry.LastScan)
				assert.Greater(t, entry.ScanCount, 0)
			}

			// Record more data in second instance
			sh2.Record("newsite.com", "9.9.9.9")
			err = sh2.Save()
			require.NoError(t, err)

			// Third instance: verify cumulative data
			sh3, err := NewScanHistory(tmpFile, tt.format, "host", time.Hour)
			require.NoError(t, err)

			assert.Equal(t, len(testData)+1, len(sh3.entries))
			assert.True(t, sh3.IsScanned("newsite.com"))
		})
	}
}

func TestScanHistory_IPScope(t *testing.T) {
	t.Run("ip scope stores by IP", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test-ip-scope.log")
		sh, err := NewScanHistory(tmpFile, "txt", "ip", 0)
		require.NoError(t, err)

		// Record with hostname and IP
		err = sh.Record("example.com", "1.2.3.4")
		require.NoError(t, err)

		// Should be found by IP, not hostname
		assert.True(t, sh.IsScanned("example.com", "1.2.3.4"), "Should find by IP")
		assert.False(t, sh.IsScanned("example.com"), "Should not find by hostname alone when scope is ip")
		assert.True(t, sh.IsScanned("other.com", "1.2.3.4"), "Should find by IP regardless of hostname")
	})

	t.Run("ip scope with different hosts same IP", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test-ip-scope-shared.log")
		sh, err := NewScanHistory(tmpFile, "txt", "ip", 0)
		require.NoError(t, err)

		// Record same IP with different hostnames
		err = sh.Record("example.com", "1.2.3.4")
		require.NoError(t, err)

		err = sh.Record("another.com", "1.2.3.4")
		require.NoError(t, err)

		// Both should be tracked as scanned (same IP)
		assert.True(t, sh.IsScanned("example.com", "1.2.3.4"))
		assert.True(t, sh.IsScanned("another.com", "1.2.3.4"))
		assert.True(t, sh.IsScanned("yetanother.com", "1.2.3.4"), "Any hostname with this IP should be marked as scanned")

		// Different IP should not be scanned
		assert.False(t, sh.IsScanned("example.com", "5.6.7.8"))
	})

	t.Run("ip scope persistence", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test-ip-scope-persist.log")

		// First instance
		sh1, err := NewScanHistory(tmpFile, "txt", "ip", 0)
		require.NoError(t, err)

		err = sh1.Record("example.com", "192.168.1.1")
		require.NoError(t, err)
		err = sh1.Record("google.com", "8.8.8.8")
		require.NoError(t, err)

		err = sh1.Save()
		require.NoError(t, err)

		// Second instance: load and verify
		sh2, err := NewScanHistory(tmpFile, "txt", "ip", 0)
		require.NoError(t, err)

		assert.True(t, sh2.IsScanned("example.com", "192.168.1.1"))
		assert.True(t, sh2.IsScanned("google.com", "8.8.8.8"))
		assert.True(t, sh2.IsScanned("other.com", "192.168.1.1"), "Should find by IP")
		assert.False(t, sh2.IsScanned("example.com", "10.0.0.1"), "Different IP should not be found")
	})

	t.Run("ip scope with scan count", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test-ip-scope-count.log")
		sh, err := NewScanHistory(tmpFile, "txt", "ip", 0)
		require.NoError(t, err)

		// Record same IP multiple times
		sh.Record("example.com", "1.2.3.4")
		sh.Record("example.com", "1.2.3.4")
		sh.Record("another.com", "1.2.3.4") // Same IP, different host

		// Scan count should increment for the IP
		assert.Equal(t, 3, sh.GetScanCount("example.com", "1.2.3.4"))
		assert.Equal(t, 3, sh.GetScanCount("another.com", "1.2.3.4"), "Same IP should have same count")
		assert.Equal(t, 0, sh.GetScanCount("example.com"), "Without IP should return 0 for ip scope")
	})

	t.Run("ip scope with TTL", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test-ip-scope-ttl.log")
		sh, err := NewScanHistory(tmpFile, "txt", "ip", 100*time.Millisecond)
		require.NoError(t, err)

		err = sh.Record("example.com", "1.2.3.4")
		require.NoError(t, err)

		// Should be found within TTL
		assert.True(t, sh.IsScanned("example.com", "1.2.3.4"))

		// Wait for TTL to expire
		time.Sleep(150 * time.Millisecond)

		// Should not be found after TTL
		assert.False(t, sh.IsScanned("example.com", "1.2.3.4"))
	})

	t.Run("host scope vs ip scope comparison", func(t *testing.T) {
		// Host scope
		tmpFileHost := filepath.Join(t.TempDir(), "test-host-scope.log")
		shHost, err := NewScanHistory(tmpFileHost, "txt", "host", 0)
		require.NoError(t, err)

		err = shHost.Record("example.com", "1.2.3.4")
		require.NoError(t, err)

		// IP scope
		tmpFileIP := filepath.Join(t.TempDir(), "test-ip-scope.log")
		shIP, err := NewScanHistory(tmpFileIP, "txt", "ip", 0)
		require.NoError(t, err)

		err = shIP.Record("example.com", "1.2.3.4")
		require.NoError(t, err)

		// Host scope: finds by hostname
		assert.True(t, shHost.IsScanned("example.com"), "Host scope should find by hostname")
		assert.True(t, shHost.IsScanned("example.com", "1.2.3.4"), "Host scope should find by hostname even with IP")
		assert.True(t, shHost.IsScanned("example.com", "9.9.9.9"), "Host scope should find by hostname with any IP")

		// IP scope: only finds by IP
		assert.False(t, shIP.IsScanned("example.com"), "IP scope should not find by hostname alone")
		assert.True(t, shIP.IsScanned("example.com", "1.2.3.4"), "IP scope should find by IP")
		assert.False(t, shIP.IsScanned("example.com", "9.9.9.9"), "IP scope should not find with wrong IP")
	})

	t.Run("domain scope behavior", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test-domain-scope.log")
		sh, err := NewScanHistory(tmpFile, "txt", "domain", 0)
		require.NoError(t, err)

		// Record with port in hostname
		err = sh.Record("example.com:8080", "1.2.3.4")
		require.NoError(t, err)

		// Domain scope should strip port and match by domain
		assert.True(t, sh.IsScanned("example.com:8080"))
		assert.True(t, sh.IsScanned("example.com:443"), "Domain scope should match without port")
		assert.True(t, sh.IsScanned("example.com"), "Domain scope should match domain only")
	})
}

func TestScanHistory_IPScopeIntegration(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test-ip-scope-integration.log")

	t.Run("multiple IPs for same host", func(t *testing.T) {
		sh, err := NewScanHistory(tmpFile, "txt", "ip", 0)
		require.NoError(t, err)

		// Record multiple IPs for same hostname (e.g., DNS round-robin)
		ips := []string{"1.2.3.4", "1.2.3.5", "1.2.3.6"}
		for _, ip := range ips {
			err = sh.Record("example.com", ip)
			require.NoError(t, err)
		}

		// Each IP should be tracked separately
		for _, ip := range ips {
			assert.True(t, sh.IsScanned("example.com", ip))
			assert.Equal(t, 1, sh.GetScanCount("example.com", ip))
		}

		// Unrecorded IP should not be found
		assert.False(t, sh.IsScanned("example.com", "9.9.9.9"))
	})

	t.Run("save and reload with multiple IPs", func(t *testing.T) {
		sh1, err := NewScanHistory(tmpFile, "txt", "ip", 0)
		require.NoError(t, err)

		testData := map[string][]string{
			"example.com": {"1.2.3.4", "1.2.3.5"},
			"google.com":  {"8.8.8.8", "8.8.4.4"},
		}

		for host, ips := range testData {
			for _, ip := range ips {
				err = sh1.Record(host, ip)
				require.NoError(t, err)
			}
		}

		err = sh1.Save()
		require.NoError(t, err)

		// Reload and verify
		sh2, err := NewScanHistory(tmpFile, "txt", "ip", 0)
		require.NoError(t, err)

		for host, ips := range testData {
			for _, ip := range ips {
				assert.True(t, sh2.IsScanned(host, ip),
					"Should find %s with IP %s", host, ip)
			}
		}
	})
}
