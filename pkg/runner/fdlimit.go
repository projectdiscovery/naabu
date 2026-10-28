package runner

// fdLimitReserve is the number of file descriptors kept aside for everything
// that is not an in-flight connect probe: stdio, pcap handles, output files,
// DNS sockets, the metrics server and service-version workers.
const fdLimitReserve = 128

// connectConcurrency returns how many concurrent connect probes are safe given
// the process open-file soft limit. Connect scan opens one socket per in-flight
// probe, so running rate goroutines with rate > ulimit yields "too many open
// files". A soft of 0 means the limit is unknown (or unlimited) and rate is
// used unchanged.
func connectConcurrency(rate int, soft uint64) int {
	if rate < 1 {
		rate = 1
	}
	if soft == 0 {
		return rate
	}
	if soft <= fdLimitReserve {
		return 1
	}
	avail := soft - fdLimitReserve
	// avail is only narrowed to int when it is smaller than rate, so the
	// conversion can never overflow regardless of how large the limit is.
	if avail >= uint64(rate) {
		return rate
	}
	return int(avail)
}
