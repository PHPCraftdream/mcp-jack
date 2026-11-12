//go:build !linux

package durable

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedPlatformNeverCreatesOrSamples(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces.db")
	samples := 0
	opts := Options{DeploymentID: "public-test", Window: 30, Now: func() int64 { samples++; return 100 }}
	if err := InitializeUnused(path, opts); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported init: %v", err)
	}
	if _, err := Open(path, opts); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported open: %v", err)
	}
	if samples != 0 {
		t.Fatal("unsupported backend used the clock")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsupported backend created data")
	}
}
