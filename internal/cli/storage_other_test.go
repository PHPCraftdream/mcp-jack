//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package cli

import (
	"context"
	"io"
	"path/filepath"
	"testing"
)

func TestUnsupportedPlatformStorageFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if exclusive(p, []byte("secret")) == nil {
		t.Fatal("unsupported secret creation accepted")
	}
	if _, err := readPrivate(p, 4096); err == nil {
		t.Fatal("unsupported secret loading accepted")
	}
	if Run(context.Background(), []string{"keygen", "user", "--secret", p, "--public", p + ".public"}, IO{Err: io.Discard}) == 0 {
		t.Fatal("unsupported secret operation accepted")
	}
}
