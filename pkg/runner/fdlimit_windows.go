//go:build windows

package runner

// raiseOpenFileLimit is a no-op on Windows, which does not expose a per-process
// file-descriptor rlimit. Returning 0 leaves connect concurrency at the
// configured rate.
func raiseOpenFileLimit() uint64 { return 0 }
