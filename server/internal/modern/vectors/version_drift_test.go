package modernvectors

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	modern "github.com/PHPCraftdream/mcp-jack/server/internal/modern"
)

func TestImplementationVersionMatchesCargoPackage(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..", "..")
	manifest, err := os.ReadFile(filepath.Join(repoRoot, "rust", "Cargo.toml"))
	if err != nil {
		t.Fatalf("read rust/Cargo.toml: %v", err)
	}
	match := regexp.MustCompile(`(?m)^version\s*=\s*"([^"]+)"`).FindSubmatch(manifest)
	if match == nil {
		t.Fatal("rust/Cargo.toml has no package version")
	}
	cargoVersion := string(match[1])
	if modern.ImplementationVersion != cargoVersion {
		t.Fatalf("ImplementationVersion = %q, Cargo.toml version = %q", modern.ImplementationVersion, cargoVersion)
	}

	want := `"version": "` + cargoVersion + `"`
	for _, path := range []string{
		filepath.Join(repoRoot, "internal", "cli", "internal", "bridge", "bridge_modern.go"),
		filepath.Join(repoRoot, "client", "rpc.go"),
	} {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if count := strings.Count(string(source), want); count != 1 {
			t.Fatalf("%s contains %d occurrences of %q; want exactly 1", path, count, want)
		}
	}
}
