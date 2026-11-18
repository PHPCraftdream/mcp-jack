//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package stdio

import (
	"os"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
)

func PrepareProcessIO(_, _ *os.File) (IO, error) {
	return IO{}, command.ErrConfig
}
