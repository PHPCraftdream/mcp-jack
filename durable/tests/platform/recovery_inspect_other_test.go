//go:build !linux

package platform_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/durable"
)

func TestUnsupportedRecoveryInspectionHasNoClockOrFileEffect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	opts := durable.Options{DeploymentID: "public-unsupported-recovery", Window: 30, Now: func() int64 { panic("unsupported inspection sampled clock") }}
	if _, err := durable.InspectRecovery(path, opts); !errors.Is(err, durable.ErrUnsupported) {
		t.Fatalf("unsupported recovery platform accepted: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported inspection touched store: %v", err)
	}
}
