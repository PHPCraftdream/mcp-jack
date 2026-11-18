//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package storage_test

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	cli "github.com/PHPCraftdream/mcp-jack/internal/cli"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
)

func TestUnsupportedPlatformStorageFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if storage.Exclusive(p, []byte("secret")) == nil {
		t.Fatal("unsupported secret creation accepted")
	}
	if _, err := storage.ReadPrivate(p, 4096); err == nil {
		t.Fatal("unsupported secret loading accepted")
	}
	if cli.Run(context.Background(), []string{"keygen", "user", "--secret", p, "--public", p + ".public"}, cli.IO{Err: io.Discard}) == 0 {
		t.Fatal("unsupported secret operation accepted")
	}
}
