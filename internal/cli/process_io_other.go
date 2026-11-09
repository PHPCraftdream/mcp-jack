//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package cli

import "os"

func prepareProcessIO(_, _ *os.File) (IO, error) {
	return IO{}, errConfig
}
