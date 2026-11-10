//go:build !linux

package durable

import "os"

func privateDirectory(string) error {
	return ErrUnsupported
}

func openPrivateFile(string, int, os.FileMode, bool) (*os.File, error) {
	return nil, ErrUnsupported
}
