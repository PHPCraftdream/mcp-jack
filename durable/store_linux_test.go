//go:build linux

package durable

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "private")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := privateDirectory(filepath.Join(directory, "nonces.db")); err != nil {
		t.Fatalf("private fixture: %v", err)
	}
	return directory
}

func testOptions(now *int64) Options {
	return Options{DeploymentID: "public-test-deployment", Window: 30, Now: func() int64 { return *now }}
}

func TestOpenMissingNeverCreates(t *testing.T) {
	now := int64(100)
	path := filepath.Join(privateTestDirectory(t), "nonces.db")
	if _, err := Open(path, testOptions(&now)); err == nil {
		t.Fatal("missing store opened")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("serving-open created a missing store")
	}
}

func TestInitializeRefusesReplacementAndCleanRestart(t *testing.T) {
	now := int64(100)
	path := filepath.Join(privateTestDirectory(t), "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := InitializeUnused(path, opts); err == nil {
		t.Fatal("existing store replaced")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed initialization changed existing bytes")
	}
	owner, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !owner.meta.Dirty || owner.meta.HighWater != 100 {
		t.Fatal("owner exposed before dirty/H receipt")
	}
	generation := owner.meta.Owner
	if _, err := Open(path, opts); err == nil {
		t.Fatal("second owner admitted")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal("close is not idempotent")
	}
	now = 101
	reopened, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.meta.Owner != generation+1 || reopened.meta.HighWater != 101 {
		t.Fatal("restart did not preserve owner/H ordering")
	}
}

func TestDirectorySyncFailureLeavesInitializationFenced(t *testing.T) {
	now := int64(100)
	path := filepath.Join(privateTestDirectory(t), "nonces.db")
	opts := testOptions(&now)
	calls := 0
	err := initializeUnused(path, opts, func(directory string) error {
		calls++
		if directory != filepath.Dir(path) {
			t.Fatal("wrong directory sync target")
		}
		return errors.New("public injected directory sync failure")
	})
	if err == nil || calls != 1 {
		t.Fatal("initialization did not report failed sync")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("uncertain initialization file was removed")
	}
	if owner, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		if owner != nil {
			owner.Fence()
			_ = owner.Close()
		}
		t.Fatalf("uncertain initialization admitted: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refusal silently repaired/reset uncertain initialization")
	}
}

func TestUnsafePermissionsRefuseBeforeCreation(t *testing.T) {
	now := int64(100)
	directory := privateTestDirectory(t)
	path := filepath.Join(directory, "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if owner, err := Open(path, opts); err == nil {
		_ = owner.Close()
		t.Fatal("public-readable database admitted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(directory, "new.db")
	if err := InitializeUnused(missing, opts); err == nil {
		t.Fatal("unsafe directory admitted")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsafe initialization created a file")
	}
}

func TestFenceRemainsDirtyAcrossRestart(t *testing.T) {
	now := int64(100)
	path := filepath.Join(privateTestDirectory(t), "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	owner, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	owner.Fence()
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("fenced store reopened: %v", err)
	}
}

func TestStartupClockPanicClosesActualOwnedFile(t *testing.T) {
	now := int64(100)
	path := filepath.Join(privateTestDirectory(t), "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	options := dbOptions(false)
	originalOpen := options.OpenFile
	var owned *os.File
	options.OpenFile = func(name string, flags int, mode os.FileMode) (*os.File, error) {
		file, err := originalOpen(name, flags, mode)
		if err == nil {
			owned = file
			t.Cleanup(func() { _ = file.Close() })
		}
		return file, err
	}
	broken := opts
	broken.Now = func() int64 { panic("public startup clock panic") }
	var observed any
	func() {
		defer func() { observed = recover() }()
		_, _ = openStore(path, broken, options)
	}()
	if observed != "public startup clock panic" || owned == nil {
		t.Fatal("startup clock panic was not exercised")
	}
	if _, err := owned.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("actual owned file was not closed: %v", err)
	}
	if owner, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		if owner != nil {
			owner.Fence()
			_ = owner.Close()
		}
		t.Fatalf("dirty startup after panic was not fenced: %v", err)
	}
}

func TestStartupRollbackDoesNotClearAtCatchUp(t *testing.T) {
	now := int64(100)
	path := filepath.Join(privateTestDirectory(t), "nonces.db")
	opts := testOptions(&now)
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	now = 99
	if _, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("rollback admitted: %v", err)
	}
	now = 100
	if _, err := Open(path, opts); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatal("clock catch-up cleared rollback fence")
	}
}

func TestEmptyOversizedAndSymlinkStoresRefused(t *testing.T) {
	now := int64(100)
	directory := privateTestDirectory(t)
	opts := testOptions(&now)
	for _, size := range []int64{0, maxFileBytes + pageBytes} {
		path := filepath.Join(directory, "size.db")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(size); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, opts); err == nil {
			t.Fatal("uninitialized/oversized store opened")
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() != size {
			t.Fatal("refusal changed file size")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(directory, "original.db")
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "alias.db")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, opts); err == nil {
		t.Fatal("symlink store opened")
	}
}
