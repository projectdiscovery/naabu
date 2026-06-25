//go:build !windows

package runner

import "golang.org/x/sys/unix"

// raiseOpenFileLimit best-effort raises the RLIMIT_NOFILE soft limit to the
// hard limit and returns the resulting soft limit (0 if it cannot be read).
// This lets high-rate connect scans use the FDs the kernel already permits
// without the user having to run `ulimit -n` manually.
func raiseOpenFileLimit() uint64 {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		return 0
	}
	if lim.Cur >= lim.Max {
		return lim.Cur
	}
	target := lim
	target.Cur = lim.Max
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &target); err == nil {
		return lim.Max
	}
	// Darwin rejects a soft limit above OPEN_MAX even when the hard limit is
	// higher, so retry with a conservative ceiling.
	const darwinCeil = 24576
	if lim.Cur < darwinCeil {
		target.Cur = darwinCeil
		if lim.Max < darwinCeil {
			target.Cur = lim.Max
		}
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &target); err == nil {
			return target.Cur
		}
	}
	return lim.Cur
}
