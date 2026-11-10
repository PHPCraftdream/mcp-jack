//go:build linux

package durable

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testOptions(now *int64) Options {
	return Options{DeploymentID: "public-test-deployment", Window: 30, Now: func() int64 { return *now }}
}

func TestOpenMissingNeverCreates(t *testing.T) {
	now := int64(100)
	path := filepath.Join(t.TempDir(), "nonces.db")
	if _, err := Open(path, testOptions(&now)); err == nil {
		t.Fatal("missing store opened")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("serving-open created a missing store")
	}
}

func TestInitializeRefusesReplacementAndCleanRestart(t *testing.T) {
	now := int64(100)
	path := filepath.Join(t.TempDir(), "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil { t.Fatal(err) }
	before, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if err := InitializeUnused(path, opts); err == nil { t.Fatal("existing store replaced") }
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) { t.Fatal("failed initialization changed existing bytes") }
	owner, err := Open(path, opts)
	if err != nil { t.Fatal(err) }
	if !owner.meta.Dirty || owner.meta.HighWater != 100 { t.Fatal("owner exposed before dirty/H receipt") }
	generation := owner.meta.Owner
	if _, err := Open(path, opts); err == nil { t.Fatal("second owner admitted") }
	if err := owner.Close(); err != nil { t.Fatal(err) }
	if err := owner.Close(); err != nil { t.Fatal("close is not idempotent") }
	now = 101
	reopened, err := Open(path, opts)
	if err != nil { t.Fatal(err) }
	defer reopened.Close()
	if reopened.meta.Owner != generation+1 || reopened.meta.HighWater != 101 { t.Fatal("restart did not preserve owner/H ordering") }
}

func TestFenceRemainsDirtyAcrossRestart(t *testing.T) {
	now := int64(100)
	path := filepath.Join(t.TempDir(), "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil { t.Fatal(err) }
	owner, err := Open(path, opts)
	if err != nil { t.Fatal(err) }
	owner.Fence()
	if err := owner.Close(); err != nil { t.Fatal(err) }
	if _, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) { t.Fatalf("fenced store reopened: %v", err) }
}

func TestStartupRollbackDoesNotClearAtCatchUp(t *testing.T) {
	now := int64(100)
	path := filepath.Join(t.TempDir(), "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil { t.Fatal(err) }
	now = 99
	if _, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) { t.Fatalf("rollback admitted: %v", err) }
	now = 100
	if _, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) { t.Fatal("clock catch-up cleared rollback fence") }
}

func TestEmptyOversizedAndSymlinkStoresRefused(t *testing.T) {
	now := int64(100)
	directory := t.TempDir()
	opts := testOptions(&now)
	for _, size := range []int64{0, maxFileBytes + pageBytes} {
		path := filepath.Join(directory, "size.db")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil { t.Fatal(err) }
		if err := file.Truncate(size); err != nil { t.Fatal(err) }
		if err := file.Close(); err != nil { t.Fatal(err) }
		if _, err := Open(path, opts); err == nil { t.Fatal("uninitialized/oversized store opened") }
		info, err := os.Stat(path)
		if err != nil || info.Size() != size { t.Fatal("refusal changed file size") }
		if err := os.Remove(path); err != nil { t.Fatal(err) }
	}
	path := filepath.Join(directory, "original.db")
	if err := InitializeUnused(path, opts); err != nil { t.Fatal(err) }
	link := filepath.Join(directory, "alias.db")
	if err := os.Symlink(path, link); err != nil { t.Fatal(err) }
	if _, err := Open(link, opts); err == nil { t.Fatal("symlink store opened") }
}
