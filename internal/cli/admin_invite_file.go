package cli

import (
	"os"
	"path/filepath"
)

// Пустой reservation остаётся и при неизвестном результате remote call.
func reserveInviteOutput(path string) (*os.File, error) {
	if privateParent(path) != nil {
		return nil, errConfig
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, errConfig
	}
	ready := false
	defer func() {
		if !ready {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !owned(info) || file.Sync() != nil {
		return nil, errConfig
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, errConfig
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return nil, errConfig
	}
	ready = true
	return file, nil
}
