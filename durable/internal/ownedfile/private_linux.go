//go:build linux

package ownedfile

import (
	"os"
	"path/filepath"
	"syscall"
)

// Only explicitly listed local filesystems are accepted; this is not power-loss certification.
func PrivateDirectory(path string) error {
	if os.Getpagesize() != PageBytes {
		return ErrUnsupported
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrUnavailable
	}
	parent := filepath.Dir(path)
	for current := parent; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnavailable
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0) {
			return ErrUnavailable
		}
		if current == parent {
			if stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0700 {
				return ErrUnavailable
			}
		} else if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return ErrUnavailable
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(parent, &fs); err != nil {
		return ErrUnavailable
	}
	switch uint64(fs.Type) & 0xffffffff {
	case 0xef53, 0x58465342, 0x9123683e: // ext4, XFS, Btrfs.
		return nil
	default:
		return ErrUnsupported
	}
}

func openPrivateFile(path string, flags int, mode os.FileMode, create bool) (*os.File, error) {
	file, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return nil, ErrUnavailable
	}
	info, err := file.Stat()
	valid := err == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600
	if valid {
		stat, ok := info.Sys().(*syscall.Stat_t)
		valid = ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
	}
	if valid {
		valid = info.Size() <= MaxFileBytes && (create || info.Size() >= 4*PageBytes)
	}
	if !valid {
		_ = file.Close()
		return nil, ErrInvalidStore
	}
	return file, nil
}
