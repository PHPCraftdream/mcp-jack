//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package storage

import (
	"os"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
)

func Owned(os.FileInfo) bool { return false }
func PrivateParent(string) error {
	return command.ErrConfig
}
