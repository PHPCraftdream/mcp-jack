//go:build linux

package durable

// Candidate nonce-vector conformance driver. It loads
// spec/fixtures/candidate/nonce-vectors.json (format
// "mcp-jack-candidate-durable-nonce-v1") and replays every drivable admission
// case against the real bbolt-backed store plus the real server.Verifier
// durable path. Cases that cannot be expressed against the Go seam are listed
// in vectorExclusions with a reason and spec quote; cases driven with a
// documented deviation are listed in vectorDeviations. Exclusions and
// deviations are data, not scattered comments.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
	bolt "go.etcd.io/bbolt"
)

const vectorFixtureFormat = "mcp-jack-candidate-durable-nonce-v1"
const vectorAud = "candidate-vector-test"
const vectorToolName = "jack.whoami"
const vectorDefaultDeployment = "candidate-test-deployment"

// ---------------------------------------------------------------------------
// Fixture schema.
// ---------------------------------------------------------------------------

type vectorFixture struct {
	Format      string         `json:"format"`
	StatusCodes map[string]int `json:"status_codes"`
	Cases       []vectorCase   `json:"cases"`
}

type vectorCase struct {
	ID          string        `json:"id"`
	Description string        `json:"description"`
	State       *vectorState  `json:"state"`
	Event       *vectorEvent  `json:"event"`
	Sequence    []vectorEvent `json:"sequence"`
	Expect      vectorExpect  `json:"expect"`
}

type vectorState struct {
	Deployment string            `json:"deployment"`
	Generation uint64            `json:"generation"`
	Window     int64             `json:"window"`
	HighWater  int64             `json:"highWater"`
	Intents    []vectorSeedRow   `json:"intents"`
	Live       []vectorSeedRow   `json:"live"`
	Tombstones []vectorTombstone `json:"tombstones"`
}

type vectorSeedRow struct {
	Key         string `json:"key"`
	IntentID    string `json:"intentId"`
	TS          int64  `json:"ts"`
	RetainUntil int64  `json:"retainUntil"`
	OperationID string `json:"operationId"`
}

type vectorTombstone struct {
	IntentID string `json:"intentId"`
	Outcome  string `json:"outcome"`
}

type vectorEvent struct {
	KID             string `json:"kid"`
	Nonce           string `json:"nonce"`
	Authenticated   bool   `json:"authenticated"`
	RequestIdentity string `json:"requestIdentity"`
	Window          int64  `json:"window"`
	TS              int64  `json:"ts"`
	EntryNow        int64  `json:"entryNow"`
	IntentNow       int64  `json:"intentNow"`
	FinalNow        int64  `json:"finalNow"`
	Authorization   string `json:"authorization"`
	HandlerEffect   string `json:"handlerEffect"`
}

type vectorExpect struct {
	Statuses   []json.RawMessage `json:"statuses"`
	Status     *int              `json:"status"`
	Code       string            `json:"code"`
	Callbacks  json.RawMessage   `json:"callbacks"`
	Writes     json.RawMessage   `json:"writes"`
	Dispatches json.RawMessage   `json:"dispatches"`

	ConfirmedCommits int   `json:"confirmedCommits"`
	HighWater        int64 `json:"highWater"`
	LiveCount        int   `json:"liveCount"`
	IntentCount      int   `json:"intentCount"`
	TombstoneCount   int   `json:"tombstoneCount"`
	Fenced           bool  `json:"fenced"`
	Effects          struct {
		Authorization int `json:"authorization"`
		Handler       int `json:"handler"`
		StateMutation int `json:"stateMutation"`
	} `json:"effects"`
	TombstoneOutcome   string `json:"tombstoneOutcome"`
	Reconciliation     string `json:"reconciliation"`
	PreserveLive       bool   `json:"preserveLive"`
	PreserveTombstones bool   `json:"preserveTombstones"`

	// Decoded lists; not part of the JSON schema.
	statusPairs    []vectorStatusPair
	callbackList   []int
	writesList     []int
	dispatchesList []int
}

type vectorStatusPair struct {
	Status int
	Code   string
}

func decodeCountField(t *testing.T, id, field string, raw json.RawMessage) []int {
	t.Helper()
	if len(raw) == 0 {
		return nil
	}
	var single int
	if err := json.Unmarshal(raw, &single); err == nil {
		return []int{single}
	}
	var list []int
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("%s: cannot decode expect.%s: %v", id, field, err)
	}
	return list
}

func (e *vectorExpect) decode(t *testing.T, id string) {
	t.Helper()
	e.callbackList = decodeCountField(t, id, "callbacks", e.Callbacks)
	e.writesList = decodeCountField(t, id, "writes", e.Writes)
	e.dispatchesList = decodeCountField(t, id, "dispatches", e.Dispatches)
	for index, raw := range e.Statuses {
		var pair []any
		if err := json.Unmarshal(raw, &pair); err != nil || len(pair) != 2 {
			t.Fatalf("%s: cannot decode expect.statuses[%d]: %v", id, index, err)
		}
		status, okStatus := pair[0].(float64)
		code, okCode := pair[1].(string)
		if !okStatus || !okCode {
			t.Fatalf("%s: expect.statuses[%d] is not [number,string]", id, index)
		}
		e.statusPairs = append(e.statusPairs, vectorStatusPair{Status: int(status), Code: code})
	}
}

func loadVectorFixture(t *testing.T) vectorFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "spec", "fixtures", "candidate", "nonce-vectors.json"))
	if err != nil {
		t.Fatalf("candidate nonce vectors fixture: %v", err)
	}
	var fixture vectorFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("candidate nonce vectors fixture: %v", err)
	}
	if fixture.Format != vectorFixtureFormat {
		t.Fatalf("fixture format %q, want %q", fixture.Format, vectorFixtureFormat)
	}
	for _, code := range []string{"durability_unavailable", "state_changed", "clock_unsafe", "capacity_exhausted"} {
		if fixture.StatusCodes[code] != 503 {
			t.Fatalf("status_codes[%s] = %d, want 503", code, fixture.StatusCodes[code])
		}
	}
	for index := range fixture.Cases {
		fixture.Cases[index].Expect.decode(t, fixture.Cases[index].ID)
	}
	return fixture
}

// ---------------------------------------------------------------------------
// Exclusions and deviations: data, not comments.
// ---------------------------------------------------------------------------

type vectorExclusion struct {
	reason string
	spec   string
}

var vectorExclusions = map[string]vectorExclusion{
	"generation-change-zero-commit": {
		reason: "Not expressible against the Go seam: the fixture supplies a mismatched owner/store " +
			"generation, but NonceAdmission carries no caller-captured generation to compare with the " +
			"open store. Go validates the captured registry snapshot and compares full persisted metadata " +
			"structurally under the admission mutex; lifetime-exclusive ownership prevents a second owner. " +
			"This fixture-only generation mismatch has no injection point.",
		spec: "spec/candidate/durable-nonces.md L42: \"capture immutable active-key/registered-caller/" +
			"enrollment snapshot, positive immutable W, accepting owner and store generation\"; L44: " +
			"\"Store admission uses a lifetime-exclusive owner; a second process opening it is refused.\"",
	},
}

var vectorDeviations = map[string][]string{
	"crash-after-commit-no-dispatch": {
		"expect.status 503/durability_unavailable and expect.effects zeros are the JS model's " +
			"lost-response placeholder; the Go store returns the committed response in-process and " +
			"there is no in-process crash. This driver asserts the durable claims instead: commit " +
			"succeeded (live=1, 2 writes), no native/dispatch side effect, clean Close, reopen " +
			"succeeds unfenced, and the same pair replays 401 replayed_nonce with zero further " +
			"writes and no re-dispatch.",
		"Spec quote, spec/candidate/durable-nonces.md L74: \"crash after confirmed reservation but " +
			"before dispatch leaves the pair consumed and never auto-redelivers.\"",
	},
	"capacity-live-plus-intent": {
		"Vector state (highWater=0 with ts=100 rows) is loader-rejectable per spec L58 and record.go " +
			"validateRecord; seeded with metadata.HighWater=100 (the derivable floor). expect.highWater=0 " +
			"is therefore not assertable; the driver asserts highWater=100 and everything else exactly " +
			"(503 capacity_exhausted, 4096 live rows preserved row-for-row, unfenced, effects 0).",
		"expect.callbacks=0/expect.writes=0 count committed mutations in the JS model; Go performs the " +
			"atomic capacity check inside the intent transaction (spec L48 step 5), so one aborted " +
			"transact call is observed. The driver asserts exactly one transact call and zero committed " +
			"writes (metadata and row counts unchanged).",
	},
	"capacity-tombstones": {
		"Same high-water floor and aborted-transaction counting deviations as capacity-live-plus-intent.",
	},
	"unknown-final-present": {
		"The reservationFound distinction is unobservable in bbolt single-transaction semantics: an " +
			"injected error after apply rolls the final transaction back, so both variants rest with the " +
			"prepared intent row. The driver asserts the identical terminal state for both variants: " +
			"fenced, 503 durability_unavailable, 2 transact calls, exactly one unresolved row in " +
			"InspectRecovery, ReconcileUnknown producing exactly one terminal tombstone " +
			"(tombstoneCount=1), and Open refused after reconciliation. expect.tombstoneOutcome " +
			"unknown_found/unknown_absent is not separately assertable.",
	},
	"unknown-final-absent": {
		"Same rollback-resting-state deviation as unknown-final-present.",
	},
	"unknown-intent-absent": {
		"Partially driven. Unassertable expect fields: highWater=100 and writes=1 (committed) because " +
			"the H advance and the intent commit are one atomic transaction per spec L62 (\"durably " +
			"advance H to the raw sample in an atomic ordered transaction\"); a failed intent " +
			"transaction leaves H=0 with zero committed writes and one aborted transact call. Asserted " +
			"instead: 503 durability_unavailable, one transact call, fenced, no rows, the Dirty recovery " +
			"gate, ReconcileUnknown refusal on empty history (manual fence), and a refused reopen.",
	},
}

// ---------------------------------------------------------------------------
// Deterministic synthetic identities.
// ---------------------------------------------------------------------------

func vectorDigest(name string) []byte {
	sum := sha256.Sum256([]byte(name))
	return sum[:]
}

func vectorKidRaw(name string) [32]byte {
	var raw [32]byte
	copy(raw[:], vectorDigest("candidate-vector/kid/"+name))
	return raw
}

func vectorKid(name string) string {
	raw := vectorKidRaw(name)
	return jack.EncodeBase64URL(raw[:])
}

func vectorNonceRaw(name string) [16]byte {
	var raw [16]byte
	copy(raw[:], vectorDigest("candidate-vector/nonce/"+name))
	return raw
}

func vectorNonce(name string) string {
	raw := vectorNonceRaw(name)
	return jack.EncodeBase64URL(raw[:])
}

func vectorSigRaw(name string) [64]byte {
	var raw [64]byte
	copy(raw[:32], vectorDigest("candidate-vector/sig-a/"+name))
	copy(raw[32:], vectorDigest("candidate-vector/sig-b/"+name))
	return raw
}

func vectorSig(name string) string {
	raw := vectorSigRaw(name)
	return jack.EncodeBase64URL(raw[:])
}

func vectorOperation(name string) [16]byte {
	var raw [16]byte
	copy(raw[:], vectorDigest("candidate-vector/op/"+name))
	return raw
}

// ---------------------------------------------------------------------------
// Seeding: fresh store + scripted clock + direct bucket writes.
// ---------------------------------------------------------------------------

type scriptedClock struct {
	values []int64
	index  int
}

func newScriptedClock(values ...int64) *scriptedClock {
	return &scriptedClock{values: values}
}

func (c *scriptedClock) push(values ...int64) {
	c.values = append(c.values, values...)
}

func (c *scriptedClock) Now() int64 {
	if c.index >= len(c.values) {
		return c.values[len(c.values)-1]
	}
	value := c.values[c.index]
	c.index++
	return value
}

// vectorRowHighWater picks a receipt HighWater satisfying validateRecord:
// 0 <= Hw <= metadata.HighWater and |Hw - ts| <= W.
func vectorRowHighWater(metadataHighWater, ts int64) int64 {
	if metadataHighWater > 0 {
		return metadataHighWater
	}
	return ts
}

func vectorSeedRowRecord(t *testing.T, m metadata, kind byte, kidName, nonceName string, ts, retainUntil, highWater int64) nonceRecord {
	t.Helper()
	var key [48]byte
	kidRaw := vectorKidRaw(kidName)
	nonceRaw := vectorNonceRaw(nonceName)
	copy(key[:32], kidRaw[:])
	copy(key[32:], nonceRaw[:])
	signing := jack.RequestSigningString("GET", "/mcp", vectorAud, vectorKid(kidName), ts, vectorNonce(nonceName), nil)
	requestHash, err := jack.DecodeBase64URLFixed(jack.BodyHash([]byte(signing)), 32)
	if err != nil {
		t.Fatalf("seed row %s/%s request hash: %v", kidName, nonceName, err)
	}
	operation := vectorOperation(kidName + "/" + nonceName)
	sigRaw := vectorSigRaw(kidName + ":" + nonceName)
	row := nonceRecord{
		kind: kind, storeID: m.StoreID, key: key,
		receipt: server.NonceReceipt{
			Version:         formatVersion,
			DeploymentID:    m.Deployment,
			StoreGeneration: m.Generation,
			OwnerGeneration: m.Owner,
			IntentID:        storageIntentID(m, key, sigRaw[:], requestHash, operation),
			OperationID:     operation,
			KID:             vectorKid(kidName),
			Nonce:           vectorNonce(nonceName),
			Signature:       vectorSig(kidName + ":" + nonceName),
			RequestHash:     jack.BodyHash([]byte(signing)),
			Timestamp:       ts,
			RetainUntil:     retainUntil,
			HighWater:       highWater,
		},
	}
	if err := validateRecord(row, m); err != nil {
		t.Fatalf("seed row %s/%s invalid: %v", kidName, nonceName, err)
	}
	return row
}

// vectorSplitRowKey derives the deterministic identity names of a seed row.
// Pair rows are written "kid:nonce"; generated capacity rows ("seed-N") carry
// a single name, so the nonce name falls back to a whole-key derivative.
func vectorSplitRowKey(key string) (string, string) {
	for index := 0; index < len(key); index++ {
		if key[index] == ':' {
			return key[:index], key[index+1:]
		}
	}
	return key, key + "/nonce"
}

// vectorCaseRows builds every seed row of a case; encodeRecord (via
// validateRecord) already rejects any row inconsistent with the metadata.
func vectorCaseRows(t *testing.T, fc vectorCase, m metadata) []nonceRecord {
	t.Helper()
	var rows []nonceRecord
	for _, row := range fc.State.Live {
		kidName, nonceName := vectorSplitRowKey(row.Key)
		rows = append(rows, vectorSeedRowRecord(t, m, liveRecord, kidName, nonceName,
			row.TS, row.RetainUntil, vectorRowHighWater(m.HighWater, row.TS)))
	}
	for _, row := range fc.State.Intents {
		kidName, nonceName := vectorSplitRowKey(row.Key)
		rows = append(rows, vectorSeedRowRecord(t, m, intentRecord, kidName, nonceName,
			row.TS, row.RetainUntil, vectorRowHighWater(m.HighWater, row.TS)))
	}
	for _, row := range fc.State.Tombstones {
		rows = append(rows, vectorSeedRowRecord(t, m, tombstoneRecord, row.IntentID, row.IntentID+"-pair",
			100, 130, vectorRowHighWater(m.HighWater, 100)))
	}
	return rows
}

// seedVectorState writes the rows, their operation index, the live expiry
// index, and matching metadata in one transaction, then re-checks the exact
// graph invariants the loader itself uses (validateRows) and syncs the
// in-memory metadata the transaction layer compares against.
func seedVectorState(t *testing.T, owner *Store, fc vectorCase, highWater int64) {
	t.Helper()
	if fc.State == nil {
		return // sequence cases start from a fresh empty store
	}
	seedMeta := owner.meta
	seedMeta.HighWater = highWater
	rows := vectorCaseRows(t, fc, seedMeta)
	m := seedMeta
	err := owner.db.Update(func(tx *bolt.Tx) error {
		for _, row := range rows {
			encoded, err := encodeRecord(row, seedMeta)
			if err != nil {
				return err
			}
			bucket := "intent"
			switch row.kind {
			case liveRecord:
				bucket = "live"
			case tombstoneRecord:
				bucket = "tombstone"
			}
			if err := tx.Bucket([]byte(bucket)).Put(row.key[:], encoded); err != nil {
				return err
			}
			if err := tx.Bucket([]byte("operation")).Put(row.receipt.OperationID[:], row.key[:]); err != nil {
				return err
			}
			if row.kind == liveRecord {
				index := expiryKey(row)
				if err := tx.Bucket([]byte("expiry")).Put(index[:], []byte{}); err != nil {
					return err
				}
			}
			switch row.kind {
			case liveRecord:
				m.Live++
			case intentRecord:
				m.Intents++
			case tombstoneRecord:
				m.Tombstones++
			}
		}
		if err := validateRows(tx, m); err != nil {
			return err
		}
		return tx.Bucket([]byte("metadata")).Put(headerKey, encodeMetadata(m))
	})
	if err != nil {
		t.Fatalf("%s: seed state: %v", fc.ID, err)
	}
	owner.meta = m
}

// ---------------------------------------------------------------------------
// Driving: full-path Verifier, store-direct, counters.
// ---------------------------------------------------------------------------

type vectorCounters struct {
	transactCalls int
	nativeCalls   int
	accepted      int
	eventCalls    int
	eventAccepted int
}

func countTransact(owner *Store, counters *vectorCounters) {
	original := owner.transact
	owner.transact = func(apply func(*bolt.Tx) error) error {
		counters.transactCalls++
		counters.eventCalls++
		return original(apply)
	}
}

func resetEventCounters(counters *vectorCounters) {
	counters.eventCalls = 0
	counters.eventAccepted = 0
}

type refusingNative struct {
	counters *vectorCounters
}

func (n refusingNative) Call(*server.NativeCall) (server.NativeResult, *jack.Error) {
	n.counters.nativeCalls++
	return server.NativeResult{}, &jack.Error{HTTPStatus: 403, Code: "authorization_refused", Message: "authorization refused"}
}

func vectorRegisteredKey(t *testing.T, state *server.MemoryState, kidName string) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("candidate-vector/key/" + kidName))
	key := ed25519.NewKeyFromSeed(seed[:])
	public := key.Public().(ed25519.PublicKey)
	if err := state.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{
			Kid:       vectorKid(kidName),
			PublicKey: jack.EncodeBase64URL(public),
			Name:      "candidate-vector-" + kidName,
		})
		return nil
	}); err != nil {
		t.Fatalf("register vector key %s: %v", kidName, err)
	}
	return key
}

func vectorToolBody(tool string) []byte {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": tool, "arguments": map[string]any{}},
	})
	if err != nil {
		panic(err) // constant-shaped body; marshal cannot fail
	}
	return body
}

func vectorRequest(t *testing.T, state *server.MemoryState, ev vectorEvent, target string, body []byte) server.Request {
	t.Helper()
	key := vectorRegisteredKey(t, state, ev.KID)
	kid, nonce := vectorKid(ev.KID), vectorNonce(ev.Nonce)
	method := "GET"
	if body != nil {
		method = "POST"
	}
	signing := jack.RequestSigningString(method, target, vectorAud, kid, ev.TS, nonce, body)
	signature := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	if !ev.Authenticated {
		// Tamper after signing so signature verification must fail pre-admission.
		target += "/tampered"
	}
	return server.Request{
		Method:     method,
		Target:     target,
		AuthValues: []string{jack.FormatRequestAuth(jack.RequestAuth{Kid: kid, TS: ev.TS, Nonce: nonce, Sig: signature})},
		Body:       body,
	}
}

func vectorVerifier(t *testing.T, owner *Store, state *server.MemoryState, clock *scriptedClock, counters *vectorCounters, window int64, refuseNative bool) *server.Verifier {
	t.Helper()
	cfg := server.Config{Aud: vectorAud, State: state, DurableNonces: owner, Now: clock.Now, Window: window}
	if refuseNative {
		cfg.Native = refusingNative{counters: counters}
	}
	verifier, err := server.NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return verifier
}

// driveVectorEvent runs one full-path event: the Verifier consumes the entry
// clock sample, the store consumes entry/intent/final samples, and the
// Verifier consumes the post-commit sample (5 pushes per event).
func driveVectorEvent(t *testing.T, owner *Store, state *server.MemoryState, clock *scriptedClock, counters *vectorCounters, ev vectorEvent, target string) server.Result {
	t.Helper()
	clock.push(ev.EntryNow, ev.EntryNow, ev.IntentNow, ev.FinalNow, ev.FinalNow)
	var body []byte
	refuseNative := ev.Authorization == "refused"
	if refuseNative {
		body = vectorToolBody(vectorToolName)
	}
	request := vectorRequest(t, state, ev, target, body)
	verifier := vectorVerifier(t, owner, state, clock, counters, ev.Window, refuseNative)
	result := verifier.Verify(request)
	result.Done()
	if result.Accepted {
		counters.accepted++
		counters.eventAccepted++
	}
	return result
}

// vectorEffects derives the harness-local effect counters:
// authorization = post-commit authorization gate reached (native call entered
// or accepted forward); handler = dispatch permission observed;
// stateMutation = 0 (the Verifier harness never runs a wrapped handler).
func vectorEffects(counters *vectorCounters) (int, int, int) {
	return counters.nativeCalls + counters.accepted, counters.accepted, 0
}

// ---------------------------------------------------------------------------
// Assertions.
// ---------------------------------------------------------------------------

func assertVectorStatus(t *testing.T, id string, result server.Result, status int, code string) {
	t.Helper()
	if code == "committed" {
		if !result.Accepted {
			t.Fatalf("%s: expected committed accept, got %d/%q accepted=%v", id, result.HTTPStatus, result.Code, result.Accepted)
		}
		return
	}
	if result.HTTPStatus != status || result.Code != code {
		t.Fatalf("%s: status/code = %d/%q, want %d/%q", id, result.HTTPStatus, result.Code, status, code)
	}
}

func assertCount(t *testing.T, id, field string, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: %s = %d, want %d", id, field, got, want)
	}
}

func bucketSize(t *testing.T, owner *Store, name string) int {
	t.Helper()
	count := 0
	if err := owner.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(name)).ForEach(func([]byte, []byte) error {
			count++
			return nil
		})
	}); err != nil {
		t.Fatalf("bucket %s: %v", name, err)
	}
	return count
}

// assertVectorEnd checks the shared terminal expectations against the live
// store: metadata, row counts (rows and counters), high-water, fence state,
// storage-callback/write counts, and effect counters. skip keys turn off
// individual assertions where a documented deviation applies.
func assertVectorEnd(t *testing.T, id string, owner *Store, counters *vectorCounters, exp vectorExpect, skip map[string]bool) {
	t.Helper()
	var m metadata
	err := owner.db.View(func(tx *bolt.Tx) error {
		decoded, err := decodeMetadata(tx.Bucket([]byte("metadata")).Get(headerKey))
		if err != nil {
			return err
		}
		m = decoded
		return validateRows(tx, decoded)
	})
	if err != nil {
		t.Fatalf("%s: store view: %v", id, err)
	}
	if !skip["highWater"] && m.HighWater != exp.HighWater {
		t.Fatalf("%s: highWater = %d, want %d", id, m.HighWater, exp.HighWater)
	}
	if !skip["counts"] {
		assertCount(t, id, "liveRows", bucketSize(t, owner, "live"), exp.LiveCount)
		assertCount(t, id, "intentRows", bucketSize(t, owner, "intent"), exp.IntentCount)
		assertCount(t, id, "tombstoneRows", bucketSize(t, owner, "tombstone"), exp.TombstoneCount)
		assertCount(t, id, "metadata.live", int(m.Live), exp.LiveCount)
		assertCount(t, id, "metadata.intents", int(m.Intents), exp.IntentCount)
		assertCount(t, id, "metadata.tombstones", int(m.Tombstones), exp.TombstoneCount)
	}
	if !skip["fence"] && owner.fenced.Load() != exp.Fenced {
		t.Fatalf("%s: fenced = %v, want %v", id, owner.fenced.Load(), exp.Fenced)
	}
	if !skip["writes"] {
		if len(exp.callbackList) > 0 {
			assertCount(t, id, "callbacks", counters.transactCalls, exp.callbackList[0])
		}
		if len(exp.writesList) > 0 {
			assertCount(t, id, "writes", counters.transactCalls, exp.writesList[0])
		}
	}
	if !skip["dispatches"] && len(exp.dispatchesList) > 0 {
		assertCount(t, id, "dispatches", counters.eventAccepted, exp.dispatchesList[0])
	}
	if !skip["effects"] {
		auth, handler, mutation := vectorEffects(counters)
		if auth != exp.Effects.Authorization || handler != exp.Effects.Handler || mutation != exp.Effects.StateMutation {
			t.Fatalf("%s: effects = (%d,%d,%d), want (%d,%d,%d)", id, auth, handler, mutation,
				exp.Effects.Authorization, exp.Effects.Handler, exp.Effects.StateMutation)
		}
	}
}

func assertVectorRecorded(t *testing.T, id string, result server.Result, recorded bool) {
	t.Helper()
	if result.NonceRecorded != recorded {
		t.Fatalf("%s: nonceRecorded = %v, want %v", id, result.NonceRecorded, recorded)
	}
}

func assertRefusesReopen(t *testing.T, id, path string, opts Options) {
	t.Helper()
	reopened, err := Open(path, opts)
	if !errors.Is(err, ErrRecoveryRequired) {
		if reopened != nil {
			reopened.Fence()
			_ = reopened.Close()
		}
		t.Fatalf("%s: reopened a fenced store: %v", id, err)
	}
}

// ---------------------------------------------------------------------------
// Per-case plans and runners.
// ---------------------------------------------------------------------------

type vectorPlan struct {
	run func(t *testing.T, fc vectorCase, plan vectorPlan)
	// openNow is the startup clock sample: it becomes metadata.HighWater at
	// Open, so it must equal the vector's starting high-water.
	openNow int64
	// assertRecorded: nil means do not assert the field.
	assertRecorded *bool
	assertUnsafe   bool
	skip           map[string]bool
}

func boolPtr(value bool) *bool { return &value }

func vectorDeployment(fc vectorCase) string {
	if fc.State != nil && fc.State.Deployment != "" {
		return fc.State.Deployment
	}
	return vectorDefaultDeployment
}

func vectorWindow(fc vectorCase) int64 {
	if fc.State != nil {
		return fc.State.Window
	}
	return 30
}

func openNowFor(fc vectorCase) int64 {
	if fc.State != nil {
		return fc.State.HighWater
	}
	return 100 // sequence cases expect highWater=100 on a fresh store
}

// newSingleStore creates a fresh store for one case, seeds the vector state,
// and installs the transact-call counter. The clock holds the init/open
// samples; runners push the per-event samples afterwards.
func newSingleStore(t *testing.T, fc vectorCase, plan vectorPlan) (*Store, string, Options, *scriptedClock, *vectorCounters, *server.MemoryState) {
	t.Helper()
	clock := newScriptedClock(plan.openNow, plan.openNow)
	path := filepath.Join(privateTestDirectory(t), "candidate-vectors.db")
	opts := Options{DeploymentID: vectorDeployment(fc), Window: vectorWindow(fc), Now: clock.Now}
	if err := InitializeUnused(path, opts); err != nil {
		t.Fatalf("%s: InitializeUnused: %v", fc.ID, err)
	}
	owner, err := Open(path, opts)
	if err != nil {
		t.Fatalf("%s: Open: %v", fc.ID, err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	seedVectorState(t, owner, fc, plan.openNow)
	if owner.meta.Generation != 1 || owner.meta.Window != vectorWindow(fc) {
		t.Fatalf("%s: store metadata generation/window = %d/%d after open", fc.ID, owner.meta.Generation, owner.meta.Window)
	}
	counters := &vectorCounters{}
	countTransact(owner, counters)
	return owner, path, opts, clock, counters, server.NewMemoryState()
}

func runSingleVector(t *testing.T, fc vectorCase, plan vectorPlan) {
	owner, _, _, clock, counters, state := newSingleStore(t, fc, plan)
	result := driveVectorEvent(t, owner, state, clock, counters, *fc.Event, "/mcp")
	if fc.Expect.Status != nil {
		assertVectorStatus(t, fc.ID, result, *fc.Expect.Status, fc.Expect.Code)
	}
	if plan.assertRecorded != nil {
		assertVectorRecorded(t, fc.ID, result, *plan.assertRecorded)
	}
	if plan.assertUnsafe && !owner.meta.Unsafe {
		t.Fatalf("%s: unsafe latch not durably set", fc.ID)
	}
	assertVectorEnd(t, fc.ID, owner, counters, fc.Expect, plan.skip)
}

func runSequenceVector(t *testing.T, fc vectorCase, plan vectorPlan) {
	owner, _, _, clock, counters, state := newSingleStore(t, fc, plan)
	recorded := 0
	for index, ev := range fc.Sequence {
		resetEventCounters(counters)
		target := "/mcp"
		if index > 0 && ev.RequestIdentity != fc.Sequence[0].RequestIdentity {
			// A different signed request identity: different exact signing bytes.
			target = "/alternate"
		}
		result := driveVectorEvent(t, owner, state, clock, counters, ev, target)
		if len(fc.Expect.statusPairs) <= index {
			t.Fatalf("%s: missing expect.statuses[%d]", fc.ID, index)
		}
		assertVectorStatus(t, fc.ID, result, fc.Expect.statusPairs[index].Status, fc.Expect.statusPairs[index].Code)
		if result.NonceRecorded {
			recorded++
		}
		if len(fc.Expect.callbackList) > index {
			assertCount(t, fc.ID, fmt.Sprintf("callbacks[%d]", index), counters.eventCalls, fc.Expect.callbackList[index])
		}
		if len(fc.Expect.writesList) > index {
			assertCount(t, fc.ID, fmt.Sprintf("writes[%d]", index), counters.eventCalls, fc.Expect.writesList[index])
		}
		if len(fc.Expect.dispatchesList) > index {
			assertCount(t, fc.ID, fmt.Sprintf("dispatches[%d]", index), counters.eventAccepted, fc.Expect.dispatchesList[index])
		}
	}
	assertCount(t, fc.ID, "confirmedCommits", recorded, fc.Expect.ConfirmedCommits)
	assertVectorEnd(t, fc.ID, owner, counters, fc.Expect, plan.skip)
}

// runStoreDirectVector drives snapshot-change vectors directly through
// owner.Reserve: the harness Validate closure accepts the entry sample and
// rejects every later sample, which is the Go expression of a snapshot that
// changed after cryptography (the Verifier builds this closure from registry
// state and cannot be forced to flip mid-request from outside).
func runStoreDirectVector(t *testing.T, fc vectorCase, plan vectorPlan) {
	owner, _, _, clock, counters, _ := newSingleStore(t, fc, plan)
	ev := *fc.Event
	clock.push(ev.EntryNow, ev.IntentNow, ev.FinalNow)
	kid, nonce := vectorKid(ev.KID), vectorNonce(ev.Nonce)
	validateCalls := 0
	admission := server.NonceAdmission{
		KID: kid, Nonce: nonce,
		Signature:    vectorSig(ev.KID + ":" + ev.Nonce),
		SigningBytes: jack.RequestSigningString("GET", "/mcp", vectorAud, kid, ev.TS, nonce, nil),
		Timestamp:    ev.TS,
		Window:       ev.Window,
		Validate: func(int64) bool {
			validateCalls++
			return validateCalls == 1
		},
	}
	_, lease, reserveErr := owner.Reserve(admission)
	if lease != nil {
		lease.Release()
	}
	if reserveErr == nil || reserveErr.HTTPStatus != 503 || reserveErr.Code != "state_changed" {
		t.Fatalf("%s: reserve error = %+v, want 503/state_changed", fc.ID, reserveErr)
	}
	assertCount(t, fc.ID, "validateCalls", validateCalls, 2)
	assertVectorEnd(t, fc.ID, owner, counters, fc.Expect, plan.skip)
}

// runUnknownFinalVector drives an unknown final outcome (injected error inside
// the final transaction), then recovers through InspectRecovery +
// ReconcileUnknown and asserts the terminal no-redelivery tombstone and the
// surviving startup fence.
func runUnknownFinalVector(t *testing.T, fc vectorCase, plan vectorPlan) {
	owner, path, opts, clock, counters, state := newSingleStore(t, fc, plan)
	injected := errors.New("candidate-vector injected unknown final outcome")
	counting := owner.transact
	owner.transact = func(apply func(*bolt.Tx) error) error {
		counters.eventCalls++
		// counting (installed by newSingleStore) is the only place the
		// transaction ordinal advances; wrapping it again would double-count
		// and mis-time the fault against the intent/final transactions.
		return counting(func(tx *bolt.Tx) error {
			if counters.transactCalls != 2 {
				return apply(tx)
			}
			// Apply then fail: bbolt rolls the final transaction back, which is
			// exactly the unknown-outcome ambiguity being exercised.
			if err := apply(tx); err != nil {
				return err
			}
			return injected
		})
	}
	result := driveVectorEvent(t, owner, state, clock, counters, *fc.Event, "/mcp")
	assertVectorStatus(t, fc.ID, result, 503, "durability_unavailable")
	if result.Accepted || result.NonceRecorded {
		t.Fatalf("%s: unknown outcome dispatched or recorded: %+v", fc.ID, result)
	}
	assertCount(t, fc.ID, "transactCalls", counters.transactCalls, 2)
	if !owner.fenced.Load() {
		t.Fatalf("%s: unknown outcome did not fence the owner", fc.ID)
	}
	if auth, handler, mutation := vectorEffects(counters); auth != 0 || handler != 0 || mutation != 0 {
		t.Fatalf("%s: effects = (%d,%d,%d), want zeros", fc.ID, auth, handler, mutation)
	}
	// The intent transaction durably advances H via purgeExpired (transaction.go
	// sets m.HighWater=now even without expired rows), and the rolled-back final
	// transaction leaves that advance intact, so expect.highWater is assertable.
	if owner.meta.HighWater != fc.Expect.HighWater {
		t.Fatalf("%s: highWater = %d, want %d", fc.ID, owner.meta.HighWater, fc.Expect.HighWater)
	}
	if err := owner.Close(); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("%s: fenced close: %v", fc.ID, err)
	}
	report, err := InspectRecovery(path, opts)
	if err != nil {
		t.Fatalf("%s: InspectRecovery: %v", fc.ID, err)
	}
	if !report.Dirty {
		t.Fatalf("%s: recovery report lost the dirty gate", fc.ID)
	}
	if len(report.Live)+len(report.Intents)+len(report.Tombstones) != 1 {
		t.Fatalf("%s: unresolved rows = %d/%d/%d, want exactly one", fc.ID,
			len(report.Live), len(report.Intents), len(report.Tombstones))
	}
	var claim server.NonceReceipt
	if len(report.Live) == 1 {
		claim = report.Live[0]
	} else {
		claim = report.Intents[0]
	}
	if err := ReconcileUnknown(path, opts, report.Hash, claim); err != nil {
		t.Fatalf("%s: ReconcileUnknown: %v", fc.ID, err)
	}
	after, err := InspectRecovery(path, opts)
	if err != nil {
		t.Fatalf("%s: post-reconcile inspection: %v", fc.ID, err)
	}
	assertCount(t, fc.ID, "tombstones", len(after.Tombstones), fc.Expect.TombstoneCount)
	assertCount(t, fc.ID, "live", len(after.Live), fc.Expect.LiveCount)
	assertCount(t, fc.ID, "intents", len(after.Intents), fc.Expect.IntentCount)
	assertRefusesReopen(t, fc.ID, path, opts)
}

// runUnknownIntentVector drives unknown-intent-absent as far as the Go seam
// allows: the H advance and the intent commit are one atomic transaction
// (spec L62), so expect.highWater=100 and expect.writes=1 (committed) are not
// assertable; the driver asserts the spec-conformant part: unknown fencing,
// zero rows, the Dirty recovery gate, ReconcileUnknown refusal on empty
// history, and a refused reopen.
func runUnknownIntentVector(t *testing.T, fc vectorCase, plan vectorPlan) {
	owner, path, opts, clock, counters, state := newSingleStore(t, fc, plan)
	injected := errors.New("candidate-vector injected unknown intent creation")
	owner.transact = func(func(*bolt.Tx) error) error {
		counters.transactCalls++
		counters.eventCalls++
		return injected
	}
	result := driveVectorEvent(t, owner, state, clock, counters, *fc.Event, "/mcp")
	assertVectorStatus(t, fc.ID, result, 503, "durability_unavailable")
	if result.Accepted || result.NonceRecorded {
		t.Fatalf("%s: unknown intent admitted or recorded: %+v", fc.ID, result)
	}
	assertCount(t, fc.ID, "transactCalls", counters.transactCalls, 1)
	if !owner.fenced.Load() {
		t.Fatalf("%s: unknown intent did not fence the owner", fc.ID)
	}
	skip := map[string]bool{"highWater": true, "writes": true}
	assertVectorEnd(t, fc.ID, owner, counters, fc.Expect, skip)
	if owner.meta.HighWater != 0 {
		t.Fatalf("%s: failed intent transaction persisted an H advance", fc.ID)
	}
	claim := testRecord(t, owner.meta, intentRecord).receipt
	// Store.Close only reports ErrRecoveryRequired when metadata or I/O leaves
	// an unclean trail; the injected transact failure fences inside Reserve
	// while owner.meta stays clean, so Close returns nil here. The dirty gate
	// is asserted via InspectRecovery below.
	_ = owner.Close()
	report, err := InspectRecovery(path, opts)
	if err != nil || !report.Dirty || len(report.Live)+len(report.Intents)+len(report.Tombstones) != 0 {
		t.Fatalf("%s: absent unknown operation lost the dirty gate: %+v %v", fc.ID, report, err)
	}
	if err := ReconcileUnknown(path, opts, report.Hash, claim); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("%s: empty unknown history treated as abort: %v", fc.ID, err)
	}
	assertRefusesReopen(t, fc.ID, path, opts)
}

// runCrashVector covers crash-after-commit-no-dispatch with the documented
// deviation: Go returns the committed response in-process (no in-process 503),
// so the driver asserts the durable claims plus clean reopen and replay.
func runCrashVector(t *testing.T, fc vectorCase, plan vectorPlan) {
	owner, path, opts, clock, counters, state := newSingleStore(t, fc, plan)
	result := driveVectorEvent(t, owner, state, clock, counters, *fc.Event, "/mcp")
	if !result.Accepted || !result.NonceRecorded {
		t.Fatalf("%s: committed reservation did not survive to the response: %+v", fc.ID, result)
	}
	assertCount(t, fc.ID, "writes", counters.transactCalls, 2)
	assertCount(t, fc.ID, "nativeCalls", counters.nativeCalls, 0)
	assertCount(t, fc.ID, "liveRows", bucketSize(t, owner, "live"), 1)
	if owner.meta.HighWater != fc.Expect.HighWater {
		t.Fatalf("%s: highWater = %d, want %d", fc.ID, owner.meta.HighWater, fc.Expect.HighWater)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("%s: clean close after commit: %v", fc.ID, err)
	}
	clock.push(fc.Expect.HighWater)
	reopened, err := Open(path, opts)
	if err != nil {
		t.Fatalf("%s: reopen after committed reservation: %v", fc.ID, err)
	}
	if reopened.fenced.Load() {
		reopened.Fence()
		_ = reopened.Close()
		t.Fatalf("%s: reopen was fenced; commit is not durable", fc.ID)
	}
	// The same pair replays without any further write and never re-dispatches.
	replayCounters := &vectorCounters{}
	countTransact(reopened, replayCounters)
	replay := driveVectorEvent(t, reopened, state, clock, replayCounters, *fc.Event, "/mcp")
	if replay.Accepted || replay.NonceRecorded || replay.Code != jack.CodeReplayedNonce {
		t.Fatalf("%s: committed pair re-dispatched after crash: %+v", fc.ID, replay)
	}
	assertCount(t, fc.ID, "replayWrites", replayCounters.transactCalls, 0)
	if err := reopened.Close(); err != nil {
		t.Fatalf("%s: reopen close: %v", fc.ID, err)
	}
}

// runCapacityVector asserts the exact capacity refusal plus row preservation.
// The capacity high-water floor is applied by the plan (openNow=100); see
// vectorDeviations for the floor and aborted-transaction counting deviations.
func runCapacityVector(t *testing.T, fc vectorCase, plan vectorPlan) {
	owner, _, _, clock, counters, state := newSingleStore(t, fc, plan)
	result := driveVectorEvent(t, owner, state, clock, counters, *fc.Event, "/mcp")
	if fc.Expect.Status != nil {
		assertVectorStatus(t, fc.ID, result, *fc.Expect.Status, fc.Expect.Code)
	}
	if result.NonceRecorded {
		t.Fatalf("%s: capacity refusal recorded a nonce", fc.ID)
	}
	// Deviation: one aborted transact call (atomic in-transaction capacity
	// check), zero committed writes.
	assertCount(t, fc.ID, "transactCalls", counters.transactCalls, 1)
	skip := map[string]bool{"highWater": true, "writes": true}
	assertVectorEnd(t, fc.ID, owner, counters, fc.Expect, skip)
	assertCount(t, fc.ID, "highWater", int(owner.meta.HighWater), int(plan.openNow))
	if owner.fenced.Load() {
		t.Fatalf("%s: capacity refusal fenced the owner", fc.ID)
	}
	if auth, handler, mutation := vectorEffects(counters); auth != 0 || handler != 0 || mutation != 0 {
		t.Fatalf("%s: effects = (%d,%d,%d), want zeros", fc.ID, auth, handler, mutation)
	}
	if fc.Expect.PreserveLive {
		assertCount(t, fc.ID, "preservedLive", bucketSize(t, owner, "live"), fc.Expect.LiveCount)
	}
	if fc.Expect.PreserveTombstones {
		assertCount(t, fc.ID, "preservedTombstones", bucketSize(t, owner, "tombstone"), fc.Expect.TombstoneCount)
	}
}

var candidateVectorPlans = map[string]vectorPlan{
	"same-second-restart-replay":            {run: runSingleVector, assertRecorded: boolPtr(false)},
	"future-ts-restart-replay":              {run: runSingleVector, assertRecorded: boolPtr(false)},
	"concurrent-same-pair":                  {run: runSequenceVector, openNow: 100, skip: map[string]bool{"dispatches": true}},
	"concurrent-different-request-identity": {run: runSequenceVector, openNow: 100, skip: map[string]bool{"dispatches": true}},
	"expiry-equality":                       {run: runSingleVector, assertRecorded: boolPtr(false)},
	"expiry-plus-one-fresh-timestamp":       {run: runSingleVector, assertRecorded: boolPtr(true)},
	"delayed-crypto-final-freshness":        {run: runSingleVector, assertRecorded: boolPtr(false)},
	"delayed-final-after-confirmed-intent":  {run: runSingleVector},
	// Spec §2/§48 reports the freshness-step status after confirmed cleanup (Go: checkSample).
	"definite-abort-confirmed-cleanup":       {run: runSingleVector},
	"purge-highwater-rollback":               {run: runSingleVector, assertRecorded: boolPtr(false), assertUnsafe: true},
	"window-decrease-refused":                {run: runSingleVector, assertRecorded: boolPtr(false)},
	"window-increase-refused":                {run: runSingleVector, assertRecorded: boolPtr(false)},
	"key-snapshot-change-zero-commit":        {run: runStoreDirectVector},
	"enrollment-snapshot-change-zero-commit": {run: runStoreDirectVector},
	"bad-signature-zero-writes":              {run: runSingleVector, assertRecorded: boolPtr(false)},
	"commit-then-authorization-refusal":      {run: runSingleVector, assertRecorded: boolPtr(true)},
	"crash-after-commit-no-dispatch":         {run: runCrashVector},
	"unknown-final-present":                  {run: runUnknownFinalVector},
	"unknown-final-absent":                   {run: runUnknownFinalVector},
	"unknown-intent-absent":                  {run: runUnknownIntentVector},
	"capacity-live-plus-intent":              {run: runCapacityVector, openNow: 100},
	"capacity-tombstones":                    {run: runCapacityVector, openNow: 100},
	"no-effects-without-final-commit":        {run: runUnknownFinalVector},
}

// ---------------------------------------------------------------------------
// Test.
// ---------------------------------------------------------------------------

func TestCandidateNonceVectors(t *testing.T) {
	fixture := loadVectorFixture(t)
	var summaryPass, summaryExcluded, summaryDeviation int
	for _, fc := range fixture.Cases {
		_, driven := candidateVectorPlans[fc.ID]
		_, excluded := vectorExclusions[fc.ID]
		if !driven && !excluded {
			t.Fatalf("case %s is neither driven nor explicitly excluded", fc.ID)
		}
	}
	// Reverse guard: every plan, exclusion, and deviation id must correspond to
	// a fixture case, so renamed or dropped fixtures cannot leave silent stale
	// entries behind.
	fixtureIDs := make(map[string]bool, len(fixture.Cases))
	for _, fc := range fixture.Cases {
		fixtureIDs[fc.ID] = true
	}
	checkKnown := func(kind, id string) {
		if !fixtureIDs[id] {
			t.Fatalf("%s %s does not exist in the fixture", kind, id)
		}
	}
	for id := range candidateVectorPlans {
		checkKnown("plan", id)
	}
	for id := range vectorExclusions {
		checkKnown("exclusion", id)
	}
	for id := range vectorDeviations {
		checkKnown("deviation", id)
	}
	for id, lines := range vectorDeviations {
		for _, line := range lines {
			t.Logf("deviation %s: %s", id, line)
		}
	}
	for _, fc := range fixture.Cases {
		fc := fc
		t.Run(fc.ID, func(t *testing.T) {
			if exclusion, ok := vectorExclusions[fc.ID]; ok {
				t.Logf("excluded %s: %s; spec: %s", fc.ID, exclusion.reason, exclusion.spec)
				summaryExcluded++
				return
			}
			plan := candidateVectorPlans[fc.ID]
			if plan.openNow == 0 {
				plan.openNow = openNowFor(fc)
			}
			plan.run(t, fc, plan)
			if _, deviated := vectorDeviations[fc.ID]; deviated {
				summaryDeviation++
			} else {
				summaryPass++
			}
		})
	}
	t.Logf("VECTOR-SUMMARY corpus=nonce sdk=go pass=%d excluded=%d deviation=%d", summaryPass, summaryExcluded, summaryDeviation)
}
