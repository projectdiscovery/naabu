package runner

import "time"

const (
	DefaultPortTimeoutSynScan     = time.Second
	DefaultPortTimeoutConnectScan = time.Duration(3 * time.Second)

	DefaultRateSynScan     = 1000
	DefaultRateConnectScan = 1500

	DefaultRetriesSynScan     = 3
	DefaultRetriesConnectScan = 3

	SynScan             = "s"
	ConnectScan         = "c"
	DefautStatsInterval = 5

	// DefaultThreadsNum is the default number of threads to use for the scan
	// the default value of 25 is a good balance between performance and resource usage
	DefaultThreadsNum = 25
)
