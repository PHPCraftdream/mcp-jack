package portable

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	rotationclient "github.com/PHPCraftdream/mcp-jack/client/rotation"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

type portableSigner struct{ key ed25519.PrivateKey }

func portableKey(seed byte) portableSigner {
	return portableSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))}
}
func (s portableSigner) PublicKey() []byte             { return s.key.Public().(ed25519.PublicKey) }
func (s portableSigner) Sign(b []byte) ([]byte, error) { return ed25519.Sign(s.key, b), nil }
func (s portableSigner) KID() string                   { return jack.KeyID(s.PublicKey()) }
func portableSetup(t *testing.T) (*memStore, portableSigner, rotation.Record) {
	t.Helper()
	anchor, next := portableKey(31), portableKey(32)
	binding := rotation.Binding{Endpoint: "http://127.0.0.1:12345/mcp", Audience: "portable-test"}
	cp := rotation.Checkpoint{Hash: "-", KID: jack.KeyID(anchor.PublicKey())}
	copy(cp.PublicKey[:], anchor.PublicKey())
	record, err := rotation.CreateRecord(binding, cp, anchor, next, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return newMemStore(binding, 30, cp, anchor, 1200), anchor, record
}
func signedResponse(t *testing.T, key portableSigner, ts int64, body []byte) rotationclient.Response {
	t.Helper()
	kid := jack.KeyID(key.PublicKey())
	req := "portable-request-signature"
	msg := jack.ResponseSigningString(200, req, kid, ts, body)
	header := jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: ts, Sig: jack.EncodeBase64URL(ed25519.Sign(key.key, []byte(msg)))})
	return rotationclient.Response{Status: 200, Headers: []string{header}, RequestSignature: req, Body: body}
}
func pageEnvelope(t *testing.T, key portableSigner, records []rotation.Record, head rotation.ResultCursor) []byte {
	t.Helper()
	wires := make([]string, len(records))
	for i, r := range records {
		wires[i] = r.Wire
	}
	payload := map[string]any{"current": map[string]any{"kid": key.KID(), "public_key": jack.EncodeBase64URL(key.PublicKey())}, "records": wires, "head": map[string]any{"ordinal": head.Ordinal, "hash": head.Hash}, "complete": true}
	text, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"isError": false, "content": []any{map[string]any{"type": "text", "text": string(text)}}, "structuredContent": payload}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func portableCode(t *testing.T, err error, want string) {
	t.Helper()
	var e *jack.Error
	if !errors.As(err, &e) || e.Code != want || e.HTTPStatus != 0 {
		t.Fatalf("got %v want %s", err, want)
	}
}
func TestPortableNewNilStates(t *testing.T) {
	if _, err := rotationclient.New(nil); err == nil {
		t.Fatal("New accepted nil state")
	} else {
		portableCode(t, err, "rotation_state_unknown")
	}
	var state *memStore
	if _, err := rotationclient.New(state); err == nil {
		t.Fatal("New accepted typed nil state")
	} else {
		portableCode(t, err, "rotation_state_unknown")
	}
	if _, err := rotationclient.NewHTTP(nil, portableKey(61), 5*time.Second); err == nil {
		t.Fatal("NewHTTP accepted nil state")
	} else {
		portableCode(t, err, "rotation_state_unknown")
	}
	if _, err := rotationclient.NewHTTP(state, portableKey(61), 5*time.Second); err == nil {
		t.Fatal("NewHTTP accepted typed nil state")
	} else {
		portableCode(t, err, "rotation_state_unknown")
	}
}

func TestPortableNewAndVerify(t *testing.T) {
	s, anchor, _ := portableSetup(t)
	c, err := rotationclient.New(s)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("ordinary body")
	got, err := c.VerifyResponse(signedResponse(t, anchor, 1200, body))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("verify: %q %v", got, err)
	}
}
func TestPortableNewFailuresAndDrift(t *testing.T) {
	s, _, _ := portableSetup(t)
	s.snapshotErr = &rotation.Error{Code: "rotation_state_unknown"}
	_, err := rotationclient.New(s)
	portableCode(t, err, "rotation_state_unknown")
	s, _, _ = portableSetup(t)
	s.clockErr = &rotation.Error{Code: "rotation_clock_unavailable"}
	_, err = rotationclient.New(s)
	portableCode(t, err, "rotation_clock_unavailable")
	s, anchor, _ := portableSetup(t)
	c, err := rotationclient.New(s)
	if err != nil {
		t.Fatal(err)
	}
	s.drift = true
	_, err = c.VerifyResponse(signedResponse(t, anchor, 1200, []byte("hidden")))
	portableCode(t, err, "rotation_state_unknown")
}
func TestPortableAcceptRefresh(t *testing.T) {
	s, anchor, record := portableSetup(t)
	c, err := rotationclient.New(s)
	if err != nil {
		t.Fatal(err)
	}
	head := rotation.ResultCursor{Ordinal: 1, Hash: record.Hash}
	body := pageEnvelope(t, anchor, []rotation.Record{record}, head)
	result, err := c.AcceptRefresh(signedResponse(t, anchor, 1200, body), json.RawMessage("1"), rotation.ResultCursor{Hash: "-"})
	if err != nil || !result.Committed || result.Revision != 2 || s.current.Head != head {
		t.Fatalf("refresh %+v %v", result, err)
	}
}
func TestPortableCASConflictAndClockErrors(t *testing.T) {
	s, anchor, record := portableSetup(t)
	c, err := rotationclient.New(s)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), s.encoded...)
	s.casConflict = true
	body := pageEnvelope(t, anchor, []rotation.Record{record}, rotation.ResultCursor{Ordinal: 1, Hash: record.Hash})
	_, err = c.AcceptRefresh(signedResponse(t, anchor, 1200, body), json.RawMessage("1"), rotation.ResultCursor{Hash: "-"})
	portableCode(t, err, "rotation_state_changed")
	if !bytes.Equal(before, s.encoded) {
		t.Fatal("conflict changed snapshot")
	}
	s, anchor, _ = portableSetup(t)
	c, err = rotationclient.New(s)
	if err != nil {
		t.Fatal(err)
	}
	s.rawErr = &rotation.Error{Code: "rotation_clock_unavailable"}
	_, err = c.VerifyResponse(signedResponse(t, anchor, 1200, []byte("hidden")))
	portableCode(t, err, "rotation_clock_unavailable")
	s, anchor, _ = portableSetup(t)
	c, err = rotationclient.New(s)
	if err != nil {
		t.Fatal(err)
	}
	s.clockErr = &rotation.Error{Code: "rotation_clock_unavailable"}
	got, err := c.VerifyResponse(signedResponse(t, anchor, 1200, []byte("hidden")))
	portableCode(t, err, "rotation_clock_unavailable")
	if got != nil {
		t.Fatal("returned body on refused outer clock check")
	}
}

func TestPortableFinalGateRefusesBody(t *testing.T) {
	s, anchor, _ := portableSetup(t)
	c, err := rotationclient.New(s)
	if err != nil {
		t.Fatal(err)
	}
	s.lateClockErr = true // New is call 1; VerifyResponse outer is 2; final gate is 3.
	got, err := c.VerifyResponse(signedResponse(t, anchor, 1200, []byte("hidden")))
	portableCode(t, err, "rotation_clock_unavailable")
	if got != nil {
		t.Fatal("returned body on failed final gate")
	}
}
