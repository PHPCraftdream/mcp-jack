//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Package clitest provides shared test fixtures for the internal/cli tests.
package clitest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

func PrivateDir(t *testing.T) string {
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

func Save(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := storage.Exclusive(p, b); err != nil {
		t.Fatal(err)
	}
	return p
}

func SaveJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return Save(t, dir, name, b)
}

func SignedFixture(t *testing.T, next http.Handler) (string, transport.Config, *server.MemoryState) {
	t.Helper()
	return SignedFixtureWithNative(t, next, nil)
}

func SignedFixtureWithNative(t *testing.T, next http.Handler, native server.NativeTools) (string, transport.Config, *server.MemoryState) {
	t.Helper()
	d := PrivateDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	issued, retained, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	state := server.NewMemoryState()
	if err := state.Update(func(e *server.StateEdit) error {
		e.PutKey(server.RegistryEntry{Kid: retained.KID(), PublicKey: jack.EncodeBase64URL(retained.PublicKey()), Name: "alice"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	v, err := server.NewVerifier(server.Config{Aud: "svc", State: state, Nonces: server.NewNonceStore(), Native: native})
	if err != nil {
		t.Fatal(err)
	}
	h, err := server.NewHandler(server.HandlerConfig{Verifier: v, ServerKey: priv}, next)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	cfg := transport.Config{Version: 1, Endpoint: s.URL + "/mcp", Aud: "svc", ServerPublicKey: jack.EncodeBase64URL(pub), ServerKID: jack.KeyID(pub), KeyFile: Save(t, d, "user.seed", issued.Secret()), KeyFormat: "raw-seed", CallTimeoutMS: 1000}
	return SaveJSON(t, d, "client.json", cfg), cfg, state
}
