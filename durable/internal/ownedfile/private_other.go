//go:build !linux

package ownedfile

import "os"

func PrivateDirectory(string) error {
	return ErrUnsupported
}

func openPrivateFile(string, int, os.FileMode, bool) (*os.File, error) {
	return nil, ErrUnsupported
}
