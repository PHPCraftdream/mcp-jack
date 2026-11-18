//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package keys_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/internal/cli"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/keys"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

func TestExclusiveGenerationAndBootstrap(t *testing.T) {
	d := clitest.PrivateDir(t)
	secret, public := filepath.Join(d, "user.seed"), filepath.Join(d, "user.public")
	if err := keys.Keygen("user", secret, public); err != nil {
		t.Fatal(err)
	}
	seed, _ := storage.ReadPrivate(secret, 32)
	pub, _ := storage.ReadPrivate(public, 4096)
	if len(seed) != 32 || bytes.HasSuffix(pub, []byte("\n")) {
		t.Fatal("raw seed / no-newline public envelope contract")
	}
	clientKey, err := userkey.ImportClientKey(seed)
	retained, e := userkey.ImportServerPublicEnvelope(pub)
	if err != nil || e != nil || retained.KID() != clientKey.KID() {
		t.Fatal("role handoff mismatch")
	}
	if keys.Keygen("user", secret, public) == nil {
		t.Fatal("overwrite accepted")
	}
	after, _ := storage.ReadPrivate(secret, 32)
	if !bytes.Equal(seed, after) {
		t.Fatal("secret changed")
	}
	newPublic := filepath.Join(d, "new.public")
	if keys.Keygen("user", secret, newPublic) == nil {
		t.Fatal("existing secret accepted")
	}
	if _, err := os.Lstat(newPublic); !os.IsNotExist(err) {
		t.Fatal("reservation was not rolled back")
	}
	statePath, invitePath := filepath.Join(d, "state.json"), filepath.Join(d, "invite")
	if err := keys.Bootstrap(statePath, invitePath); err != nil {
		t.Fatal(err)
	}
	original, _ := storage.ReadPrivate(statePath, wire.MaxBody)
	s, err := server.OpenFileState(statePath)
	if err != nil || len(s.View().Keys) != 0 || len(s.View().Invites) != 1 || !s.View().Invites[0].Admin {
		t.Fatal("bootstrap did not create one admin invite")
	}
	if keys.Bootstrap(statePath, filepath.Join(d, "second-invite")) == nil {
		t.Fatal("repeat bootstrap accepted")
	}
	after, _ = storage.ReadPrivate(statePath, wire.MaxBody)
	if !bytes.Equal(original, after) {
		t.Fatal("repeat bootstrap mutated state")
	}
	if err := os.WriteFile(filepath.Join(d, "corrupt"), []byte("not state"), 0600); err != nil {
		t.Fatal(err)
	}
	if keys.Bootstrap(filepath.Join(d, "corrupt"), filepath.Join(d, "unused")) == nil {
		t.Fatal("corrupt state reset")
	}
	corrupt, _ := storage.ReadPrivate(filepath.Join(d, "corrupt"), 64)
	if string(corrupt) != "not state" {
		t.Fatal("corrupt state changed")
	}
	serverSecret, serverPublic := filepath.Join(d, "server.seed"), filepath.Join(d, "server.public")
	if keys.Keygen("server", serverSecret, serverPublic) != nil {
		t.Fatal("server generation failed")
	}
	serverSeed, _ := storage.ReadPrivate(serverSecret, 32)
	serverDoc, _ := storage.ReadPrivate(serverPublic, 4096)
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
	unlock, err := storage.LockState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := storage.LockState(statePath); err == nil {
		t.Fatal("duplicate owner accepted")
	}
}

func TestCredentialTupleMismatchNoNetworkOrLeak(t *testing.T) {
	d := clitest.PrivateDir(t)
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
	keyPath := clitest.Save(t, d, "credential", credential)
	invite := clitest.Save(t, d, "invite", []byte(jack.EncodeBase64URL(make([]byte, 32))))
	base := transport.Config{Version: 1, Endpoint: expected.URL, Aud: expected.Aud, ServerPublicKey: jack.EncodeBase64URL(pub), ServerKID: expected.ServerKID, KeyFile: keyPath, KeyFormat: "credential", CallTimeoutMS: 500}
	mutations := []func(*transport.Config){
		func(c *transport.Config) { c.Endpoint += "/different" },
		func(c *transport.Config) { c.Aud += "other" },
		func(c *transport.Config) { c.ServerPublicKey = jack.EncodeBase64URL(other) },
		func(c *transport.Config) { c.ServerKID = jack.KeyID(other) },
		func(c *transport.Config) {
			c.ServerPublicKey = jack.EncodeBase64URL(other)
			c.ServerKID = jack.KeyID(other)
		},
	}
	for i, mutate := range mutations {
		c := base
		mutate(&c)
		path := clitest.SaveJSON(t, d, string(rune('a'+i))+".json", c)
		var stderr bytes.Buffer
		if cli.Run(context.Background(), []string{"enroll", "--config", path, "--invite-file", invite, "--name", "alice"}, cli.IO{Err: &stderr}) == 0 {
			t.Fatal("mismatch accepted")
		}
		if bytes.Contains(stderr.Bytes(), credential) || bytes.Contains(stderr.Bytes(), []byte("client_key")) || bytes.Contains(stderr.Bytes(), []byte(keyPath)) {
			t.Fatal("diagnostic leaked supplied data")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("mismatch reached network")
	}
	if _, err := transport.LoadConnection(clitest.SaveJSON(t, d, "valid.json", base)); err != nil {
		t.Fatal("matching independently supplied tuple refused")
	}
	if _, err := userkey.ImportCredential(append(credential, '\n'), expected); err == nil {
		t.Fatal("credential newline was normalized")
	}
}

func TestKeyAndEnrollmentRefusalsAreSpecificAndNoWrite(t *testing.T) {
	dir := clitest.PrivateDir(t)
	path := filepath.Join(dir, "same-path")
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"unknown-role", func() error { return keys.Keygen("root", filepath.Join(dir, "secret"), filepath.Join(dir, "public")) }},
		{"same-keygen-path", func() error { return keys.Keygen("user", path, path) }},
		{"relative-keygen-path", func() error { return keys.Keygen("user", "relative-secret", filepath.Join(dir, "public")) }},
		{"same-bootstrap-path", func() error { return keys.Bootstrap(path, path) }},
		{"relative-bootstrap-path", func() error { return keys.Bootstrap("relative-state", filepath.Join(dir, "invite")) }},
	} {
		if err := tc.call(); err != command.ErrConfig {
			t.Errorf("%s refusal = %v, want command.ErrConfig", tc.name, err)
		}
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("preflight refusals created output: %v", err)
	}

	statePath := filepath.Join(dir, "locked-state")
	unlock, err := storage.LockState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Bootstrap(statePath, filepath.Join(dir, "locked-invite")); err != command.ErrConfig {
		t.Fatalf("preexisting owner refusal = %v, want command.ErrConfig", err)
	}
	unlock()
	if _, err := os.Lstat(filepath.Join(dir, "locked-invite")); !os.IsNotExist(err) {
		t.Fatalf("bootstrap wrote invite despite owner conflict: %v", err)
	}

	var upstreamCalls atomic.Int32
	clientPath, _, _ := clitest.SignedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	validCode := clitest.Save(t, dir, "valid-shaped-invite", []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	for _, tc := range []struct {
		name       string
		configPath string
		invitePath string
		nameArg    string
		want       error
	}{
		{"invalid-name-before-config", "not-read", validCode, "bad/name", command.ErrConfig},
		{"unreadable-config", filepath.Join(dir, "absent-config"), validCode, "alice", command.ErrConfig},
		{"missing-invite", clientPath, filepath.Join(dir, "absent-invite"), "alice", command.ErrConfig},
	} {
		if err := keys.Enroll(context.Background(), tc.configPath, tc.invitePath, tc.nameArg); err != tc.want {
			t.Errorf("%s refusal = %v, want %v", tc.name, err, tc.want)
		}
	}
	malformed := clitest.Save(t, dir, "malformed-invite", []byte("not-base64"))
	if err := keys.Enroll(context.Background(), clientPath, malformed, "alice"); err != command.ErrConfig {
		t.Fatalf("malformed invite refusal = %v, want command.ErrConfig", err)
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("invalid enrollment reached upstream %d times", upstreamCalls.Load())
	}
}

func TestEnrollSignedNativeRefusalsRemainDistinct(t *testing.T) {
	clientPath, _, _ := clitest.SignedFixtureWithNative(t, http.NotFoundHandler(), server.NewNativeTools(server.NativeOptions{}))
	dir := filepath.Dir(clientPath)
	var config transport.Config
	if err := storage.DecodeConfig(clientPath, &config); err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverKID := jack.KeyID(serverPublic)
	var requests atomic.Int32
	unauthorized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		auth, err := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
		if err != nil {
			t.Error("401 fixture received no signed request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body := []byte(`{"error":"invite rejected"}`)
		ts := time.Now().Unix()
		signature := ed25519.Sign(serverPrivate, []byte(jack.ResponseSigningString(http.StatusUnauthorized, auth.Sig, serverKID, ts, body)))
		w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: serverKID, TS: ts, Sig: jack.EncodeBase64URL(signature)}))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(body)
	}))
	defer unauthorized.Close()
	config.Endpoint = unauthorized.URL + "/mcp"
	config.ServerPublicKey, config.ServerKID = jack.EncodeBase64URL(serverPublic), serverKID
	unauthorizedConfig := clitest.SaveJSON(t, dir, "signed-401-client.json", config)
	code := clitest.Save(t, dir, "unused-code", []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err := keys.Enroll(context.Background(), unauthorizedConfig, code, "new-user"); err == nil || err.Error() != "enroll rejected with HTTP 401; the invite may be invalid, expired or already used, or the key unknown" || requests.Load() != 1 {
		t.Fatalf("signed 401 enrollment refusal = %T %v requests=%d", err, err, requests.Load())
	}

	// The fixture identity is already registered, so native enrollment rejects
	// it with authenticated HTTP 409 before invite validation.
	err = keys.Enroll(context.Background(), clientPath, code, "another-user")
	var statusErr *transport.VerifiedStatusError
	if !errors.As(err, &statusErr) || statusErr.Status != http.StatusConflict || err.Error() != "authenticated HTTP 409; no retry performed" {
		t.Fatalf("registered-key enrollment refusal = %T %v, want authenticated HTTP 409", err, err)
	}
}
