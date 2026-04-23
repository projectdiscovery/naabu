package fingerprint

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const probeFileName = "nmap-service-probes"

// LocateNmapProbes searches common nmap installation paths for the service probes file.
// Returns the path to the file, or empty string if not found.
func LocateNmapProbes() string {
	candidates := nmapProbePaths()
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// last resort: ask nmap itself via --datadir or locate the binary
	if nmapPath, err := exec.LookPath("nmap"); err == nil {
		dir := filepath.Dir(nmapPath)
		// nmap binary is typically in bin/, probes in share/nmap/
		shareDir := filepath.Join(filepath.Dir(dir), "share", "nmap", probeFileName)
		if _, err := os.Stat(shareDir); err == nil {
			return shareDir
		}
		// some installs put data next to the binary
		nextTo := filepath.Join(dir, probeFileName)
		if _, err := os.Stat(nextTo); err == nil {
			return nextTo
		}
	}

	return ""
}

func nmapProbePaths() []string {
	var paths []string

	switch runtime.GOOS {
	case "darwin":
		paths = append(paths,
			"/opt/homebrew/share/nmap/"+probeFileName,
			"/usr/local/share/nmap/"+probeFileName,
			"/opt/local/share/nmap/"+probeFileName,
		)
	case "linux":
		paths = append(paths,
			"/usr/share/nmap/"+probeFileName,
			"/usr/local/share/nmap/"+probeFileName,
			"/snap/nmap/current/usr/share/nmap/"+probeFileName,
		)
	case "windows":
		programFiles := os.Getenv("ProgramFiles")
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		programFilesX86 := os.Getenv("ProgramFiles(x86)")
		if programFilesX86 == "" {
			programFilesX86 = `C:\Program Files (x86)`
		}
		paths = append(paths,
			filepath.Join(programFiles, "Nmap", probeFileName),
			filepath.Join(programFilesX86, "Nmap", probeFileName),
		)
	}

	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".nmap", probeFileName))
	}

	if nmapDir := os.Getenv("NMAPDIR"); nmapDir != "" {
		paths = append([]string{filepath.Join(nmapDir, probeFileName)}, paths...)
	}

	// XDG data dirs on Linux
	if xdg := os.Getenv("XDG_DATA_DIRS"); xdg != "" {
		for _, dir := range strings.Split(xdg, ":") {
			paths = append(paths, filepath.Join(dir, "nmap", probeFileName))
		}
	}

	return paths
}
