// Standalone Go consumer smoke for the staged mcp-jack module snapshot.
// Standard library ONLY. Mirrors the TS/Rust consumer smokes: (a) client key
// lifecycle and verify-only identity, (b) credential issuance/import with the
// server identity tuple, (c) a real signed loopback client/server round trip,
// including a wrong server pin and a tampered request. It prints static
// labels and error codes only — never keys, seeds, or message content.

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

const (
	aud      = "https://consumer-smoke.test"
	fixedSec = int64(1700000000)
)

var fixedNow = time.Unix(fixedSec, 0)

// fail prints a static label and exits nonzero. errorOf is optional; only
// its stable error code is printed, never a message that could carry data.
func fail(label string, err error) {
	if err != nil {
		var jErr *jack.Error
		if errors.As(err, &jErr) {
			fmt.Printf("FAIL %s (code=%s)\n", label, jErr.Code)
			os.Exit(1)
		}
	}
	fmt.Printf("FAIL %s\n", label)
	os.Exit(1)
}

func expect(cond bool, label string) {
	if !cond {
		fail(label, nil)
	}
}

func expectCode(err error, code, label string) {
	if err == nil {
		fail(label+" (expected an error)", nil)
		return
	}
	var jErr *jack.Error
	if !errors.As(err, &jErr) || jErr.Code != code {
		fail(label+" (wrong error shape)", nil)
	}
}

// tamperRT is an ordinary RoundTripper used as the SDK transport's Base: the
// SDK signs the buffered body exactly once, then hands the signed request to
// this Base, which flips one body byte so the server's body hash mismatches.
type tamperRT struct{ base http.RoundTripper }

func (t tamperRT) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(body) > 0 {
			body[0] ^= 0xff
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}
	return t.base.RoundTrip(req)
}

func main() {
	// (a) Client key lifecycle.
	clientKey, err := userkey.GenerateClientKey()
	if err != nil {
		fail("generate client key", err)
	}
	message := []byte("consumer smoke message")
	signature, err := clientKey.Sign(message)
	if err != nil {
		fail("sign", err)
	}
	expect(jack.Verify(clientKey.PublicKey(), message, signature), "verify accept")
	expect(!jack.Verify(clientKey.PublicKey(), []byte("tampered message"), signature), "verify wrong message")
	flipped := append([]byte(nil), signature...)
	flipped[0] ^= 0xff
	expect(!jack.Verify(clientKey.PublicKey(), message, flipped), "verify bit-flipped signature")
	expect(!jack.Verify(clientKey.PublicKey(), message, signature[:32]), "verify truncated signature")

	envelope, err := userkey.ExportPublicEnvelope(clientKey)
	if err != nil {
		fail("export public envelope", err)
	}
	identity, err := userkey.ImportClientPublicEnvelope(envelope)
	if err != nil {
		fail("import client public envelope", err)
	}
	expect(identity.Verify(message, signature), "public identity verify accept")
	expect(!identity.Verify(message, flipped), "public identity verify reject")
	_, err = identity.Sign(message)
	expectCode(err, userkey.ClassNotPrivate, "public identity sign must be not_private")

	// Service keypair: IssueLocalPair gives the server-local IssuedKey whose
	// Secret() is the documented private-handoff seed for the HTTP handler,
	// plus the retained public ServerKey half.
	issued, serverHalf, err := userkey.IssueLocalPair()
	if err != nil {
		fail("issue local pair", err)
	}
	servicePriv := ed25519.NewKeyFromSeed(issued.Secret())
	servicePub := serverHalf.PublicKey()
	serviceKID := jack.KeyID(servicePub)
	expect(serviceKID == serverHalf.KID(), "service KID agreement")

	serverEnvelope, err := userkey.ExportPublicEnvelope(clientKey)
	if err != nil {
		fail("export client public envelope", err)
	}
	serverIdentity, err := userkey.ImportServerPublicEnvelope(serverEnvelope)
	if err != nil {
		fail("import server public envelope", err)
	}
	expect(serverIdentity.Verify(message, signature), "server key verify accept")
	expect(!serverIdentity.Verify(message, flipped), "server key verify reject")

	// (b) Credential flow against a real loopback endpoint (literal 127.x so
	// the URL policy admits http).
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("listen", err)
	}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d/mcp", listener.Addr().(*net.TCPAddr).Port)

	expected := userkey.ExpectedIdentity{
		URL:             baseURL,
		Aud:             aud,
		ServerPublicKey: servicePub,
		ServerKID:       serviceKID,
	}
	issuance, err := userkey.IssueUserKey(expected, rand.Reader)
	if err != nil {
		fail("issue user key", err)
	}
	credential := issuance.CredentialBytes()
	if err := userkey.ValidateCredential(credential, expected); err != nil {
		fail("validate credential", err)
	}
	imported, err := userkey.ImportCredential(credential, expected)
	if err != nil {
		fail("import credential", err)
	}
	conn := imported.Connection
	expect(conn.BaseURL == expected.URL, "connection base url")
	expect(conn.Aud == expected.Aud, "connection aud")
	expect(conn.ServerKID == expected.ServerKID, "connection server kid")
	expect(bytes.Equal(conn.ServerKey, expected.ServerPublicKey), "connection server key")

	wrong := expected
	wrong.ServerPublicKey = clientKey.PublicKey()
	wrong.ServerKID = clientKey.KID()
	_, err = userkey.ImportCredential(credential, wrong)
	expectCode(err, userkey.ClassServerIdentityMismatch, "wrong identity tuple must be server_identity_mismatch")

	// Server state: register the imported signer's public key.
	state := server.NewMemoryState()
	entry := server.RegistryEntry{
		Kid:       imported.Signer.KID(),
		PublicKey: jack.EncodeBase64URL(imported.Signer.PublicKey()),
		Name:      "consumer-smoke",
		Kind:      server.KindHuman,
		Scopes:    []string{},
	}
	err = state.Update(func(edit *server.StateEdit) error {
		edit.PutKey(entry)
		return nil
	})
	if err != nil {
		fail("register key", err)
	}

	// Minimal policy: allow tools/call consumer.echo for any authenticated key.
	policyJSON := `{"version":1,"rules":[{"match":{"method":"tools/call","tool":"consumer.echo"},"scope":null}]}`
	policy, err := server.ParsePolicy([]byte(policyJSON))
	if err != nil {
		fail("parse policy", err)
	}
	verifier, err := server.NewVerifier(server.Config{
		Aud:    aud,
		State:  state,
		Nonces: server.NewNonceStore(),
		Policy: policy,
		Now:    func() int64 { return fixedSec },
	})
	if err != nil {
		fail("new verifier", err)
	}

	// (c) Real loopback client/server. The wrapped handler echoes a
	// structuredContent payload exactly like the TS smoke's upstream server.
	echoNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		var req struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.Method != "tools/call" {
			http.Error(w, "unsupported", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result": map[string]any{
				"content":           []any{},
				"isError":           false,
				"structuredContent": map[string]any{"echoed": true},
			},
		})
	})
	handler, err := server.NewHandler(server.HandlerConfig{
		Verifier:  verifier,
		ServerKey: servicePriv,
	}, echoNext)
	if err != nil {
		fail("new handler", err)
	}
	httpServer := &http.Server{
		Handler:           handler,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() { _ = httpServer.Serve(listener) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	verified, err := client.NewClient(client.Config{
		BaseURL:   imported.Connection.BaseURL,
		Aud:       aud,
		Signer:    imported.Signer,
		ServerKey: imported.Connection.ServerKey,
		Now:       func() time.Time { return fixedNow },
	})
	if err != nil {
		fail("new client", err)
	}
	var echoed struct {
		Echoed bool `json:"echoed"`
	}
	if err := verified.CallTool(ctx, "consumer.echo", nil, &echoed); err != nil {
		fail("verified call", err)
	}
	expect(echoed.Echoed, "echo payload")

	// Wrong pin: pin the client's own key; the response is signed by the
	// service key, so verification fails with unknown_server_key.
	wrongPinned, err := client.NewClient(client.Config{
		BaseURL:   imported.Connection.BaseURL,
		Aud:       aud,
		Signer:    imported.Signer,
		ServerKey: clientKey.PublicKey(),
		Now:       func() time.Time { return fixedNow },
	})
	if err != nil {
		fail("new wrong-pinned client", err)
	}
	err = wrongPinned.CallTool(ctx, "consumer.echo", nil, nil)
	expectCode(err, jack.CodeUnknownServerKey, "wrong pin must be unknown_server_key")

	// Tampered request: the ordinary RoundTripper Base mutates the signed
	// body; the server answers an unsigned 401 and the client must surface
	// UnauthenticatedResponseError.
	tampered, err := client.NewClient(client.Config{
		BaseURL:   imported.Connection.BaseURL,
		Aud:       aud,
		Signer:    imported.Signer,
		ServerKey: imported.Connection.ServerKey,
		Now:       func() time.Time { return fixedNow },
		HTTP:      &http.Client{Transport: tamperRT{base: http.DefaultTransport}},
	})
	if err != nil {
		fail("new tampering client", err)
	}
	err = tampered.CallTool(ctx, "consumer.echo", nil, nil)
	if err == nil {
		fail("tampered call must fail", nil)
	}
	var unauth *client.UnauthenticatedResponseError
	if !errors.As(err, &unauth) {
		fail("tampered call must be unauthenticated", nil)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		fail("shutdown", err)
	}

	fmt.Println("PASS: go consumer smoke (key lifecycle, credential flow, signed loopback round trip, wrong pin, tamper)")
}
