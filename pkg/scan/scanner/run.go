package scanner

/*
func handleHostPortSyn(swg *sizedwaitgroup.SizedWaitGroup, host string, port int) {
	defer swg.Done()

	// performs cdn scan exclusions checks
	if !r.canIScanIfCDN(host, port) {
		gologger.Debugf("Skipping cdn target: %s:%d\n", host, port)
		return
	}

	r.scanner.SynPortAsync(host, port)
}

func RawSocketEnumeration() {
	r.scanner.State = scan.Scan
	swg := sizedwaitgroup.New(r.options.Rate)

	for retry := 0; retry < r.options.Retries; retry++ {
		for port := range r.scanner.Ports {
			for target := range r.scanner.Targets {
				swg.Add()
				go r.handleHostPortSyn(&swg, target, port)
			}
		}
	}
	swg.Wait()
}
*/
