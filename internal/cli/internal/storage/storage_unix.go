//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package storage

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
)

func Owned(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid())
}

func PrivateParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return command.ErrConfig
	}
	parent := filepath.Dir(path)
	p, err := os.Lstat(parent)
	if err != nil || !p.IsDir() || p.Mode().Perm() != 0700 || !Owned(p) {
		return command.ErrConfig
	}
	for dir := parent; ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return command.ErrConfig
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) {
			return command.ErrConfig
		}
		if info.Mode().Perm()&0022 != 0 && !(info.Mode()&os.ModeSticky != 0 && owner.Uid == 0) {
			return command.ErrConfig
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return nil
}
