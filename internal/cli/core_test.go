//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
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
	if err := exclusive(p, b); err != nil {
		t.Fatal(err)
	}
	return p
}

func saveJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return save(t, dir, name, b)
}

func TestExclusiveGenerationAndBootstrap(t *testing.T) {
	d := privateDir(t)
	secret, public := filepath.Join(d, "user.seed"), filepath.Join(d, "user.public")
	if err := keygen("user", secret, public); err != nil {
		t.Fatal(err)
	}
	seed, _ := readPrivate(secret, 32)
	pub, _ := readPrivate(public, 4096)
	if len(seed) != 32 || bytes.HasSuffix(pub, []byte("\n")) {
		t.Fatal("raw seed / no-newline public envelope contract")
	}
	clientKey, err := userkey.ImportClientKey(seed)
	retained, e := userkey.ImportServerPublicEnvelope(pub)
	if err != nil || e != nil || retained.KID() != clientKey.KID() {
		t.Fatal("role handoff mismatch")
	}
	if keygen("user", secret, public) == nil {
		t.Fatal("overwrite accepted")
	}
	after, _ := readPrivate(secret, 32)
	if !bytes.Equal(seed, after) {
		t.Fatal("secret changed")
	}
	newPublic := filepath.Join(d, "new.public")
	if keygen("user", secret, newPublic) == nil {
		t.Fatal("existing secret accepted")
	}
	if _, err := os.Lstat(newPublic); !os.IsNotExist(err) {
		t.Fatal("reservation was not rolled back")
	}
	statePath, invitePath := filepath.Join(d, "state.json"), filepath.Join(d, "invite")
	if err := bootstrap(statePath, invitePath); err != nil {
		t.Fatal(err)
	}
	original, _ := readPrivate(statePath, maxBody)
	s, err := server.OpenFileState(statePath)
	if err != nil || len(s.View().Keys) != 0 || len(s.View().Invites) != 1 || !s.View().Invites[0].Admin {
		t.Fatal("bootstrap did not create one admin invite")
	}
	if bootstrap(statePath, filepath.Join(d, "second-invite")) == nil {
		t.Fatal("repeat bootstrap accepted")
	}
	after, _ = readPrivate(statePath, maxBody)
	if !bytes.Equal(original, after) {
		t.Fatal("repeat bootstrap mutated state")
	}
	if err := os.WriteFile(filepath.Join(d, "corrupt"), []byte("not state"), 0600); err != nil {
		t.Fatal(err)
	}
	if bootstrap(filepath.Join(d, "corrupt"), filepath.Join(d, "unused")) == nil {
		t.Fatal("corrupt state reset")
	}
	corrupt, _ := readPrivate(filepath.Join(d, "corrupt"), 64)
	if string(corrupt) != "not state" {
		t.Fatal("corrupt state changed")
	}
	serverSecret, serverPublic := filepath.Join(d, "server.seed"), filepath.Join(d, "server.public")
	if keygen("server", serverSecret, serverPublic) != nil {
		t.Fatal("server generation failed")
	}
	serverSeed, _ := readPrivate(serverSecret, 32)
	serverDoc, _ := readPrivate(serverPublic, 4096)
	var serverIdentity struct {
		Public string `json:"server_public_key"`
		KID    string `json:"server_kid"`
	}
	if json.Unmarshal(serverDoc, &serverIdentity) != nil || len(serverSeed) != 32 || bytes.Equal(serverSeed, seed) {
		t.Fatal("server/user custody not distinct")
	}
	derived := ed25519.NewKeyFromSeed(serverSeed).Public().(ed25519.PublicKey)
	if serverIdentity.Public != jack.EncodeBase64URL(derived) || serverIdentity.KID != jack.KeyID(derived) {
		t.Fatal("server identity mismatch")
	}
	unlock, err := lockState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := lockState(statePath); err == nil {
		t.Fatal("duplicate owner accepted")
	}
}

func TestCredentialTupleMismatchNoNetworkOrLeak(t *testing.T) {
	d := privateDir(t)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(500)
	}))
	defer upstream.Close()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	expected := userkey.ExpectedIdentity{URL: upstream.URL + "/mcp", Aud: "svc", ServerPublicKey: pub, ServerKID: jack.KeyID(pub)}
	issued, err := userkey.IssueUserKey(expected, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential := issued.CredentialBytes()
	keyPath := save(t, d, "credential", credential)
	invite := save(t, d, "invite", []byte(jack.EncodeBase64URL(make([]byte, 32))))
	base := clientConfig{Version: 1, Endpoint: expected.URL, Aud: expected.Aud, ServerPublicKey: jack.EncodeBase64URL(pub), ServerKID: expected.ServerKID, KeyFile: keyPath, KeyFormat: "credential", CallTimeoutMS: 500}
	mutations := []func(*clientConfig){
		func(c *clientConfig) { c.Endpoint += "/different" },
		func(c *clientConfig) { c.Aud += "other" },
		func(c *clientConfig) { c.ServerPublicKey = jack.EncodeBase64URL(other) },
		func(c *clientConfig) { c.ServerKID = jack.KeyID(other) },
		func(c *clientConfig) {
			c.ServerPublicKey = jack.EncodeBase64URL(other)
			c.ServerKID = jack.KeyID(other)
		},
	}
	for i, mutate := range mutations {
		c := base
		mutate(&c)
		path := saveJSON(t, d, string(rune('a'+i))+".json", c)
		var stderr bytes.Buffer
		if Run(context.Background(), []string{"enroll", "--config", path, "--invite-file", invite, "--name", "alice"}, IO{Err: &stderr}) == 0 {
			t.Fatal("mismatch accepted")
		}
		if bytes.Contains(stderr.Bytes(), credential) || bytes.Contains(stderr.Bytes(), []byte("client_key")) || bytes.Contains(stderr.Bytes(), []byte(keyPath)) {
			t.Fatal("diagnostic leaked supplied data")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("mismatch reached network")
	}
	if _, err := loadConnection(saveJSON(t, d, "valid.json", base)); err != nil {
		t.Fatal("matching independently supplied tuple refused")
	}
	if _, err := userkey.ImportCredential(append(credential, '\n'), expected); err == nil {
		t.Fatal("credential newline was normalized")
	}
}

func TestPrivateStorageRefusals(t *testing.T) {
	d := privateDir(t)
	p := save(t, d, "key", bytes.Repeat([]byte{7}, 32))
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(p, 32); err == nil {
		t.Fatal("public-readable secret accepted")
	}
	if err := os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(link, 32); err == nil || exclusive(link, []byte("overwrite")) == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := readPrivate(p, 31); err == nil {
		t.Fatal("oversized read accepted")
	}
	if err := os.Chmod(d, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(p, 32); err == nil {
		t.Fatal("nonprivate parent accepted")
	}
}

func signedFixture(t *testing.T, next http.Handler) (string, clientConfig, *server.MemoryState) {
	t.Helper()
	return signedFixtureWithNative(t, next, nil)
}

func signedFixtureWithNative(t *testing.T, next http.Handler, native server.NativeTools) (string, clientConfig, *server.MemoryState) {
	t.Helper()
	d := privateDir(t)
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
	cfg := clientConfig{Version: 1, Endpoint: s.URL + "/mcp", Aud: "svc", ServerPublicKey: jack.EncodeBase64URL(pub), ServerKID: jack.KeyID(pub), KeyFile: save(t, d, "user.seed", issued.Secret()), KeyFormat: "raw-seed", CallTimeoutMS: 1000}
	return saveJSON(t, d, "client.json", cfg), cfg, state
}
