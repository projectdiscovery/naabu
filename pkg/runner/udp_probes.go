package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/fingerprint"
)

// loadProbeDB parses the nmap-service-probes file at path the first
// time it is asked and memoises the result on the runner, so a follow
// up call from a different feature (e.g. -uP after -sV) reuses the
// already-parsed database instead of paying the parse cost twice.
func (r *Runner) loadProbeDB(path string) (*fingerprint.ProbeDB, error) {
	if r.probeDB != nil {
		return r.probeDB, nil
	}
	db, err := fingerprint.ParseProbeFile(path)
	if err != nil {
		return nil, err
	}
	gologger.Info().Msgf("Loaded %d probes from %s", len(db.Probes), path)
	r.probeDB = db
	return db, nil
}

// udpProbeAdapter satisfies scan.UDPProbeProvider by delegating to the
// loaded fingerprint database. Keeping it in the runner package avoids
// pulling pkg/fingerprint into pkg/scan and the import cycle that
// would imply.
type udpProbeAdapter struct {
	db *fingerprint.ProbeDB
}

func (a udpProbeAdapter) UDPProbe(port int) []byte {
	if a.db == nil {
		return nil
	}
	return a.db.UDPProbeForPort(port)
}

// initUDPProbes wires the runner's parsed probe database into its
// scanner. The feature is opt-in via -uP; when disabled or when no
// probe file is available the call is a no-op and UDP scanning keeps
// its historical empty-payload behavior.
//
// The provider is reset on the scanner up-front so a previous
// SetUDPProbeProvider call on this scanner cannot leak into a follow
// up run that no longer wants probing; the real adapter is installed
// only after the probe database is parsed successfully.
func (r *Runner) initUDPProbes() {
	if r.scanner == nil {
		return
	}
	r.scanner.SetUDPProbeProvider(nil)
	if !r.options.UDPProbes {
		return
	}
	probeFile := r.options.ServiceProbesFile
	if probeFile == "" {
		probeFile = fingerprint.LocateNmapProbes()
	}
	if probeFile == "" {
		gologger.Info().Label("WRN").Msgf("could not find nmap-service-probes, -uP has nothing to send. Install nmap or specify the path with --sV-probes")
		r.options.UDPProbes = false
		return
	}
	db, err := r.loadProbeDB(probeFile)
	if err != nil {
		gologger.Info().Label("WRN").Msgf("could not load service probes from %s for -uP: %s", probeFile, err)
		r.options.UDPProbes = false
		return
	}
	r.scanner.SetUDPProbeProvider(udpProbeAdapter{db: db})
}
