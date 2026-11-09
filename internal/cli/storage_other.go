//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package cli

import "os"

func owned(os.FileInfo) bool     { return false }
func privateParent(string) error { return errConfig }
