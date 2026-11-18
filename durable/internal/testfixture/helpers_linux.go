//go:build linux

package testfixture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/durable/internal/ownedfile"
)

func PrivateDirectory(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "private")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ownedfile.PrivateDirectory(filepath.Join(directory, "nonces.db")); err != nil {
		t.Fatalf("private fixture: %v", err)
	}
	return directory
}

type ScriptedClock struct {
	values []int64
	index  int
}

func NewScriptedClock(values ...int64) *ScriptedClock {
	return &ScriptedClock{values: values}
}

func (c *ScriptedClock) Push(values ...int64) {
	c.values = append(c.values, values...)
}

func (c *ScriptedClock) Now() int64 {
	if c.index >= len(c.values) {
		return c.values[len(c.values)-1]
	}
	value := c.values[c.index]
	c.index++
	return value
}
