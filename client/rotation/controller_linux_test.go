//go:build linux

package rotationclient_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	rotationclient "github.com/PHPCraftdream/mcp-jack/client/rotation"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

type signer struct{ key ed25519.PrivateKey }

func fixtureSigner(seed byte) signer {
	return signer{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))}
}
func (key signer) PublicKey() []byte                   { return key.key.Public().(ed25519.PublicKey) }
func (key signer) Sign(message []byte) ([]byte, error) { return ed25519.Sign(key.key, message), nil }

type fixture struct {
	controller *rotationclient.Controller
	store      *durable.TrustStore
	anchor     signer
	next       signer
	last       signer
	first      rotation.Record
	second     rotation.Record
}

func setup(t *testing.T, now func() int64) fixture {
	t.Helper()
	anchor, next, last := fixtureSigner(11), fixtureSigner(12), fixtureSigner(13)
	checkpoint := rotation.Checkpoint{Hash: "-", KID: jack.KeyID(anchor.PublicKey())}
	copy(checkpoint.PublicKey[:], anchor.PublicKey())
	binding := rotation.Binding{Endpoint: "https://public.invalid/mcp", Audience: "public-controller-test"}
	first, err := rotation.CreateRecord(binding, checkpoint, anchor, next, 1000)
	if err != nil {
		t.Fatal(err)
	}
	previous := rotation.Checkpoint{Ordinal: first.Ordinal, Hash: first.Hash, KID: first.NewKID, PublicKey: first.PublicKey, PublishedAt: first.PublishedAt}
	second, err := rotation.CreateRecord(binding, previous, next, last, 1100)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "trust.db")
	options := durable.TrustOptions{Binding: binding, Window: 30, Checkpoint: checkpoint, Now: now}
	if err := durable.InitializeTrustUnused(path, options); err != nil {
		t.Fatal(err)
	}
	store, err := durable.OpenTrust(path, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	controller, err := rotationclient.New(store)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{controller: controller, store: store, anchor: anchor, next: next, last: last, first: first, second: second}
}

func response(t *testing.T, key signer, timestamp int64, body []byte) rotationclient.Response {
	t.Helper()
	kid := jack.KeyID(key.PublicKey())
	request := "public-bound-request-signature"
	message := jack.ResponseSigningString(200, request, kid, timestamp, body)
	header := jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: timestamp, Sig: jack.EncodeBase64URL(ed25519.Sign(key.key, []byte(message)))})
	return rotationclient.Response{Status: 200, Headers: []string{header}, RequestSignature: request, Body: body}
}

func envelope(t *testing.T, key signer, records []rotation.Record, head rotation.ResultCursor, complete bool) []byte {
	t.Helper()
	wires := make([]string, len(records))
	for index, record := range records {
		wires[index] = record.Wire
	}
	payload := map[string]any{"current": map[string]any{"kid": jack.KeyID(key.PublicKey()), "public_key": jack.EncodeBase64URL(key.PublicKey())}, "records": wires, "head": map[string]any{"ordinal": head.Ordinal, "hash": head.Hash}, "complete": complete}
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

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var refusal *jack.Error
	if !errors.As(err, &refusal) || refusal.Code != code || refusal.HTTPStatus != 0 {
		t.Fatalf("got %v; want local %s", err, code)
	}
}

func TestControllerOrdinaryResponseUnknownPrecedenceAndDurableClock(t *testing.T) {
	var now atomic.Int64
	now.Store(1000)
	var samples atomic.Int64
	f := setup(t, func() int64 { samples.Add(1); return now.Load() })
	before := samples.Load()
	unknown := response(t, f.next, 0, []byte("not JSON"))
	_, err := f.controller.VerifyResponse(unknown)
	requireCode(t, err, jack.CodeUnknownServerKey)
	if samples.Load() != before {
		t.Fatal("unknown carrier sampled or advanced clock")
	}
	body := []byte("public non-JSON response")
	valid := response(t, f.anchor, 1000, body)
	now.Store(1001)
	verified, err := f.controller.VerifyResponse(valid)
	if err != nil || !bytes.Equal(verified, body) {
		t.Fatalf("ordinary signed response failed: %v", err)
	}
	body[0] ^= 1
	if bytes.Equal(verified, body) {
		t.Fatal("verified bytes alias caller buffer")
	}
	snapshot, clock, err := f.store.Snapshot()
	if err != nil || clock.HighWater != 1001 || snapshot.Revision != 1 || snapshot.Clock.HighWater != 1000 {
		t.Fatal("ordinary response changed trust or failed separate durable clock advance")
	}
	stale := response(t, f.anchor, 0, nil)
	_, err = f.controller.VerifyResponse(stale)
	requireCode(t, err, jack.CodeTimestampOutOfWindow)
}

func TestControllerRefreshACKDuplicateAndFinalRollback(t *testing.T) {
	var now atomic.Int64
	now.Store(1200)
	f := setup(t, now.Load)
	head := rotation.ResultCursor{Ordinal: 2, Hash: f.second.Hash}
	body := envelope(t, f.anchor, []rotation.Record{f.first, f.second}, head, true)
	result, err := f.controller.AcceptRefresh(response(t, f.anchor, 1200, body), json.RawMessage("1"), rotation.ResultCursor{Hash: "-"})
	if err != nil || !result.Committed || result.Revision != 2 || result.Terminal != head {
		t.Fatalf("refresh ACK failed: %+v %v", result, err)
	}
	now.Store(1201)
	duplicate, err := f.controller.AcceptRefresh(response(t, f.anchor, 1201, body), json.RawMessage("1"), head)
	if err != nil || duplicate.Committed || duplicate.Revision != 2 {
		t.Fatal("duplicate repeated trust CAS or changed revision")
	}
	now.Store(f.first.ActivatesAt)
	if _, err := f.controller.VerifyResponse(response(t, f.next, f.first.ActivatesAt, []byte("new carrier"))); err != nil {
		t.Fatal(err)
	}
	now.Store(f.first.ActivatesAt - 1)
	_, err = f.controller.VerifyResponse(response(t, f.anchor, f.first.ActivatesAt-1, []byte("old carrier")))
	requireCode(t, err, "rotation_clock_unsafe")
	now.Store(f.first.ActivatesAt + 1)
	if _, err := f.store.AdvanceAndCheck(); err == nil {
		t.Fatal("catch-up cleared rollback latch")
	}
}

func TestControllerLateACKRetainsCommittedStateButRejectsCarrier(t *testing.T) {
	const activation int64 = 1000 + rotation.GraceSeconds
	var armed atomic.Bool
	var calls atomic.Int64
	f := setup(t, func() int64 {
		if armed.Load() && calls.Add(1) == 4 {
			return activation
		}
		return activation - 2
	})
	body := envelope(t, f.anchor, []rotation.Record{f.first}, rotation.ResultCursor{Ordinal: 1, Hash: f.first.Hash}, true)
	armed.Store(true)
	result, err := f.controller.AcceptRefresh(response(t, f.anchor, activation-1, body), json.RawMessage("1"), rotation.ResultCursor{Hash: "-"})
	requireCode(t, err, "rotation_key_interval")
	if !result.Committed || result.Revision != 2 || calls.Load() != 4 {
		t.Fatal("late exact ACK lost or clock phases changed")
	}
	armed.Store(false)
	snapshot, _, err := f.store.Snapshot()
	if err != nil || snapshot.Head.Ordinal != 1 || snapshot.Revision != 2 {
		t.Fatal("late final refusal rolled back committed trust")
	}
}

func TestControllerRefreshNeverDiscoversCarrierAndRejectsConflictingDuplicate(t *testing.T) {
	f := setup(t, func() int64 { return 1200 })
	head := rotation.ResultCursor{Ordinal: 1, Hash: f.first.Hash}
	unknownBody := envelope(t, f.next, []rotation.Record{f.first}, head, true)
	_, err := f.controller.AcceptRefresh(response(t, f.next, 1200, unknownBody), json.RawMessage("1"), rotation.ResultCursor{Hash: "-"})
	requireCode(t, err, jack.CodeUnknownServerKey)
	body := envelope(t, f.anchor, []rotation.Record{f.first}, head, true)
	if _, err := f.controller.AcceptRefresh(response(t, f.anchor, 1200, body), json.RawMessage("1"), rotation.ResultCursor{Hash: "-"}); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := f.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	alternative, err := rotation.CreateRecord(snapshot.Binding, snapshot.Checkpoint, f.anchor, fixtureSigner(14), 1000)
	if err != nil {
		t.Fatal(err)
	}
	conflicting := envelope(t, f.anchor, []rotation.Record{alternative}, head, true)
	_, err = f.controller.AcceptRefresh(response(t, f.anchor, 1200, conflicting), json.RawMessage("1"), head)
	requireCode(t, err, "rotation_conflict")
	after, _, err := f.store.Snapshot()
	if err != nil || after.Revision != 2 || after.Head != head {
		t.Fatal("conflicting duplicate changed ACKed state")
	}
}

func TestControllerOrdinaryFinalClockRollbackNeverExposesBody(t *testing.T) {
	var armed atomic.Bool
	var samples atomic.Int64
	f := setup(t, func() int64 {
		if armed.Load() && samples.Add(1) == 3 {
			return 999
		}
		return 1000
	})
	armed.Store(true)
	body, err := f.controller.VerifyResponse(response(t, f.anchor, 1000, []byte("must stay private until final gate")))
	requireCode(t, err, "rotation_clock_unsafe")
	if body != nil || samples.Load() != 3 {
		t.Fatal("final rollback exposed body or skipped final guard")
	}
}

func TestControllerExpiredBridgeNeverCommitsTrust(t *testing.T) {
	const activation int64 = 1000 + rotation.GraceSeconds
	f := setup(t, func() int64 { return activation })
	body := envelope(t, f.anchor, []rotation.Record{f.first}, rotation.ResultCursor{Ordinal: 1, Hash: f.first.Hash}, true)
	result, err := f.controller.AcceptRefresh(response(t, f.anchor, activation, body), json.RawMessage("1"), rotation.ResultCursor{Hash: "-"})
	requireCode(t, err, "rotation_bridge_expired")
	snapshot, _, readErr := f.store.Snapshot()
	if result.Committed || readErr != nil || snapshot.Revision != 1 || snapshot.Head.Ordinal != 0 {
		t.Fatal("expired bridge changed trust")
	}
}
