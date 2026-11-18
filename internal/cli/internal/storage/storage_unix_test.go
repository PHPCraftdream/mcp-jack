//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package storage_test

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
)

func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	var err error
	d, err = filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	return d
}

func save(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := storage.Exclusive(p, b); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPrivateStorageRefusals(t *testing.T) {
	d := privateDir(t)
	p := save(t, d, "key", bytes.Repeat([]byte{7}, 32))
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.ReadPrivate(p, 32); err == nil {
		t.Fatal("public-readable secret accepted")
	}
	if err := os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.ReadPrivate(link, 32); err == nil || storage.Exclusive(link, []byte("overwrite")) == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := storage.ReadPrivate(p, 31); err == nil {
		t.Fatal("oversized read accepted")
	}
	if err := os.Chmod(d, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.ReadPrivate(p, 32); err == nil {
		t.Fatal("nonprivate parent accepted")
	}
}

func TestPrivateStorageRejectsMalformedBoundsAndRollsBackReservations(t *testing.T) {
	dir := privateDir(t)
	path := save(t, dir, "secret", []byte("0123456789"))
	if got, err := storage.ReadPrivate(path, 10); err != nil || string(got) != "0123456789" {
		t.Fatalf("exact-bound private read = %q, %v", got, err)
	}
	if got, err := storage.ReadPrivate(path, 9); err != command.ErrConfig || got != nil {
		t.Fatalf("oversized private read = %q, %v; want command.ErrConfig", got, err)
	}
	for _, tc := range []struct {
		name string
		path string
	}{
		{"directory", dir},
		{"relative-path", "relative-secret"},
		{"unclean-path", dir + string(os.PathSeparator) + "sub" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "secret"},
	} {
		if got, err := storage.ReadPrivate(tc.path, 100); err != command.ErrConfig || got != nil {
			t.Errorf("%s read = %q, %v; want command.ErrConfig", tc.name, got, err)
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.ReadPrivate(path, 10); err != command.ErrConfig {
		t.Fatalf("group-readable secret refusal = %v, want command.ErrConfig", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "secret-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.ReadPrivate(link, 10); err != command.ErrConfig {
		t.Fatalf("symlink read refusal = %v, want command.ErrConfig", err)
	}

	newPath := filepath.Join(dir, "reserved-before-conflict")
	existingPath := save(t, dir, "already-exists", []byte("preserve"))
	if err := storage.CreateFiles([]string{newPath, existingPath}, [][]byte{[]byte("new"), []byte("overwrite")}); err != command.ErrConfig {
		t.Fatalf("existing target refusal = %v, want command.ErrConfig", err)
	}
	if _, err := os.Lstat(newPath); !os.IsNotExist(err) {
		t.Fatalf("partial reservation survived rollback: %v", err)
	}
	if got, err := storage.ReadPrivate(existingPath, 32); err != nil || string(got) != "preserve" {
		t.Fatalf("existing target changed: %q err=%v", got, err)
	}
	invalidParentPath := filepath.Join(dir, "missing-parent", "second")
	if err := storage.CreateFiles([]string{newPath, invalidParentPath}, [][]byte{[]byte("new"), []byte("second")}); err != command.ErrConfig {
		t.Fatalf("invalid-parent refusal = %v, want command.ErrConfig", err)
	}
	if _, err := os.Lstat(newPath); !os.IsNotExist(err) {
		t.Fatalf("reservation survived invalid-parent rollback: %v", err)
	}
	if err := storage.CreateFiles([]string{newPath}, [][]byte{}); err != command.ErrConfig {
		t.Fatalf("path/content count mismatch = %v, want command.ErrConfig", err)
	}
}

func TestPrivateStorageConfigDecoderAndParentMode(t *testing.T) {
	dir := privateDir(t)
	type config struct {
		Value string `json:"value"`
	}
	valid := save(t, dir, "valid.json", []byte(`{"value":"accepted"}`))
	var got config
	if err := storage.DecodeConfig(valid, &got); err != nil || got.Value != "accepted" {
		t.Fatalf("valid private config = %#v, %v", got, err)
	}
	for index, raw := range []string{
		`null`, `[]`, `{"unknown":true}`, `{"value":"first"}{"value":"second"}`, `{"value":`,
	} {
		path := save(t, dir, "bad-"+string(rune('a'+index))+".json", []byte(raw))
		var decoded config
		if err := storage.DecodeConfig(path, &decoded); err != command.ErrConfig {
			t.Errorf("malformed config %q refusal = %v, want command.ErrConfig", raw, err)
		}
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := storage.PrivateParent(valid); err != command.ErrConfig {
		t.Fatalf("non-private parent refusal = %v, want command.ErrConfig", err)
	}
	if _, err := storage.ReadPrivate(valid, 100); err != command.ErrConfig {
		t.Fatalf("read through non-private parent = %v, want command.ErrConfig", err)
	}
}

type storageUnixFileInfo struct {
	os.FileInfo
	sys any
}

func (info storageUnixFileInfo) Sys() any { return info.sys }

func TestUnixStorageOwnershipAndAncestorRefusals(t *testing.T) {
	dir := privateDir(t)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !storage.Owned(info) {
		t.Fatal("current effective user did not own its private test directory")
	}
	if storage.Owned(storageUnixFileInfo{FileInfo: info, sys: "not a Unix stat record"}) {
		t.Fatal("unknown ownership metadata was accepted")
	}
	foreignUID := uint32(0)
	if uint32(os.Geteuid()) == foreignUID {
		foreignUID = 1
	}
	if storage.Owned(storageUnixFileInfo{FileInfo: info, sys: &syscall.Stat_t{Uid: foreignUID}}) {
		t.Fatal("foreign owner was accepted")
	}
	if storage.PrivateParent("relative/file") != command.ErrConfig {
		t.Fatal("relative private path was accepted")
	}
	unclean := dir + string(os.PathSeparator) + "child" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "secret"
	if storage.PrivateParent(unclean) != command.ErrConfig {
		t.Fatal("unclean private path was accepted")
	}
	link := filepath.Join(t.TempDir(), "directory-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if storage.PrivateParent(filepath.Join(link, "secret")) != command.ErrConfig {
		t.Fatal("symlink parent was accepted")
	}
}
