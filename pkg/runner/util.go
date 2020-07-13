package runner

import "os"

func isRoot() bool {
	return os.Geteuid() == 0
}
