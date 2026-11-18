//go:build linux

package rotationserver_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	"github.com/PHPCraftdream/mcp-jack/server"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

// Candidate rotation-state-vector conformance driver for the emission event
// family. It loads spec/fixtures/candidate/rotation-state-vectors.json
// (format "mcp-jack-candidate-rotation-state-v1") and replays the emission
// event cases against the real rotationserver.Provider over the real
// bbolt-backed durable.ServerStore (setup/publish helpers from
// helpers_linux_test.go). Every event_case id must have a plan or an entry
// in emissionVectorExclusions with a reason and spec quote; plans must exist
// in the fixture; no silent skips. The selection family is driven in
// rotation/ and the clock family in durable/.

const emissionVectorFixtureFormat = "mcp-jack-candidate-rotation-state-v1"
const emissionVectorFixturePath = "../../spec/fixtures/candidate/rotation-state-vectors.json"

type emissionVectorFixture struct {
	Format     string                `json:"format"`
	EventCases []emissionVectorEvent `json:"event_cases"`
}

type emissionVectorEvent struct {
	ID     string          `json:"id"`
	Input  json.RawMessage `json:"input"`
	Expect json.RawMessage `json:"expect"`
}

type emissionVectorExpect struct {
	Emit       bool `json:"emit"`
	Signatures int  `json:"signatures"`
	Resigns    int  `json:"resigns"`
}

type emissionVectorExclusion struct {
	reason string
	spec   string
}

var emissionVectorExclusions = map[string]emissionVectorExclusion{
	"server-final-generation-fence-no-fallback": {
		reason: "Not drivable against the Go seam: the vector's abstract clock generation 1 to 2 at " +
			"an unchanged whole second has no Go counterpart that can change while the store is " +
			"open. Final revalidates through CheckSnapshotClock: the whole committed snapshot bytes " +
			"and ownedGuard (store id, owner generation, dirty epoch, fence) inside one transaction, " +
			"so a changed generation, owner or fence already refuses with ErrUnavailable; the owner " +
			"generation only changes at an exclusive owner handoff, which cannot be injected from " +
			"outside. This is a mapping artefact, not a divergence. The state-change fence is " +
			"covered by the publication scenario in TestProviderFinalCutoffFreshnessRollbackAndStateChange.",
		spec: "spec/candidate/server-key-rotation.md L13: \"Immediately before emitting, take a fresh " +
			"whole-second sample and revalidate latest committed chain, generation/fence, signer " +
			"readiness, and that the selected key remains eligible at that fresh sample. If the " +
			"boundary was crossed or state changed, discard the prepared response and fail closed: " +
			"never switch kid or ts, re-sign under another key, fallback, or retry.\"",
	},
}

// vectorSeed reproduces the deterministic candidate test seed (spec/tools/candidate/crypto.mjs).
func vectorSeed(name string) ed25519.PrivateKey {
	sum := sha256.Sum256([]byte("mcp-jack test key: " + name))
	return ed25519.NewKeyFromSeed(sum[:])
}

func loadEmissionVectorFixture(t *testing.T) emissionVectorFixture {
	t.Helper()
	data, err := os.ReadFile(emissionVectorFixturePath)
	if err != nil {
		t.Fatalf("candidate rotation-state vectors fixture: %v", err)
	}
	var fixture emissionVectorFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("candidate rotation-state vectors fixture: %v", err)
	}
	if fixture.Format != emissionVectorFixtureFormat {
		t.Fatalf("fixture format %q, want %q", fixture.Format, emissionVectorFixtureFormat)
	}
	return fixture
}

func TestRotationStateEmissionVectors(t *testing.T) {
	fixture := loadEmissionVectorFixture(t)
	plans := map[string]bool{
		"server-final-eligible-single-signature": true,
		"server-final-cutoff-no-resign":          true,
	}

	// Event families driven by other packages (see rotation/rotation_state_vectors_test.go).
	otherPackageEvents := map[string]string{
		"same-second-greatest-ordinal-wins":           "rotation",
		"clock-rollback-latches":                      "durable",
		"clock-equal-is-noop":                         "durable",
		"clock-rollback-latch-unknown-is-unavailable": "durable",
		"clock-advance-persists-revision":             "durable",
	}

	summaryPass := 0
	summaryExcluded := 0
	summaryDeviation := 0
	seen := make(map[string]int, len(fixture.EventCases))
	for _, event := range fixture.EventCases {
		seen[event.ID]++
		switch {
		case plans[event.ID]:
			if t.Run(event.ID, func(t *testing.T) { driveEmissionVector(t, event) }) {
				summaryPass++
			}
		case emissionVectorExclusions[event.ID].reason != "":
			t.Run(event.ID, func(t *testing.T) {
				exclusion := emissionVectorExclusions[event.ID]
				summaryExcluded++
				t.Skipf("excluded: %s | spec: %s", exclusion.reason, exclusion.spec)
			})
		case otherPackageEvents[event.ID] != "":
			// Driven and reverse-guarded by the named package runner.
			continue
		default:
			t.Fatalf("event_case %q has no emission plan, exclusion or owning package", event.ID)
		}
	}
	for id := range plans {
		if seen[id] != 1 {
			t.Fatalf("planned event_case %q appears %d times in the fixture", id, seen[id])
		}
	}
	for id := range emissionVectorExclusions {
		if seen[id] != 1 {
			t.Fatalf("excluded event_case %q appears %d times in the fixture", id, seen[id])
		}
	}
	t.Logf("VECTOR-SUMMARY corpus=rotation-state sdk=go component=emission pass=%d excluded=%d deviation=%d", summaryPass, summaryExcluded, summaryDeviation)
}

// driveEmissionVector replays an emission vector: the committed ring is built
// with the real publish helper at the fixture's publication times (R1 at
// P=1000 activating 173800, R2 at P=4600 activating 177400), authorization is
// taken at signingTime with the real Provider.AuthorizeResponse, exactly one
// signature is produced with the pinned signer, and Final runs at
// emissionTime with a fresh whole-second sample.
func driveEmissionVector(t *testing.T, event emissionVectorEvent) {
	t.Helper()
	var input struct {
		Kind            string   `json:"kind"`
		SelectedKid     string   `json:"selectedKid"`
		SelectedOrdinal uint64   `json:"selectedOrdinal"`
		SigningTime     int64    `json:"signingTime"`
		EmissionTime    int64    `json:"emissionTime"`
		Records         []string `json:"records"`
	}
	if err := json.Unmarshal(event.Input, &input); err != nil {
		t.Fatalf("input: %v", err)
	}
	if input.Kind != "emission" {
		t.Fatalf("kind %q, want emission", input.Kind)
	}
	var expect emissionVectorExpect
	if err := json.Unmarshal(event.Expect, &expect); err != nil {
		t.Fatalf("expect: %v", err)
	}

	f := setup(t)
	// Build the committed chain at the fixture's publication samples.
	publish(t, f, 1)
	if len(input.Records) > 1 {
		f.now.Store(4600)
		publish(t, f, 2)
	}
	snapshot, _, err := f.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Public.Records) != len(input.Records) {
		t.Fatalf("committed records %d, want %d", len(snapshot.Public.Records), len(input.Records))
	}

	// Count physical signatures of the selected signer: exactly one signature,
	// never a re-sign under another key.
	signs := 0
	selected := 1
	if input.SelectedOrdinal == 0 {
		selected = 0
	}
	f.inventory[selected].Signer = signingHook{testSigner: f.keys[selected], onSign: func() { signs++ }}
	name := "candidate-server-next1"
	if input.SelectedOrdinal == 0 {
		name = "candidate-server-anchor"
	}
	fixtureKid := jack.KeyID(vectorSeed(name).Public().(ed25519.PublicKey))
	if input.SelectedKid != fixtureKid {
		t.Fatalf("selectedOrdinal %d maps to kid %s, fixture selected %s",
			input.SelectedOrdinal, fixtureKid, input.SelectedKid)
	}

	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}

	f.now.Store(input.SigningTime)
	authorization, err := provider.AuthorizeResponse(server.ResponseKeyRequest{})
	if err != nil {
		t.Fatalf("authorize at %d: %v", input.SigningTime, err)
	}
	defer authorization.Release()
	if authorization.Timestamp != input.SigningTime {
		t.Fatalf("authorization ts %d, want signingTime %d", authorization.Timestamp, input.SigningTime)
	}
	message := []byte("candidate-vector emission body")
	signature, err := authorization.Signer.Sign(message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	public := f.keys[selected].PublicKey()
	if len(signature) != 64 || !jack.Verify(public, message, signature) {
		t.Fatal("pinned selected signer did not sign the exact body")
	}
	if signs != expect.Signatures {
		t.Fatalf("signatures %d, want %d", signs, expect.Signatures)
	}

	// Emission-time gate with a fresh whole-second sample.
	f.now.Store(input.EmissionTime)
	finalErr := authorization.Final()
	if expect.Emit && finalErr != nil {
		t.Fatalf("final at %d: %v", input.EmissionTime, finalErr)
	}
	if !expect.Emit && finalErr == nil {
		t.Fatal("emission gate accepted a non-eligible final sample")
	}
	if !expect.Emit && !errors.Is(finalErr, rotationserver.ErrUnavailable) {
		t.Fatalf("final error %v, want rotationserver.ErrUnavailable", finalErr)
	}
	if signs != expect.Signatures {
		t.Fatalf("emission gate re-signed: %d signatures, want %d", signs, expect.Signatures)
	}
	if expect.Resigns != 0 {
		t.Fatalf("fixture expects %d resigns; Go structurally cannot re-sign", expect.Resigns)
	}
}

func TestAnnouncePendingTailAndSingleFixedPublicationSample(t *testing.T) {
	samples := &atomic.Int64{}
	f := setupWithClock(t, func(source func() int64) func() int64 {
		return func() int64 { samples.Add(1); return source() }
	})
	signs := [3]int{}
	for index := range f.inventory {
		f.inventory[index].Signer = signingHook{testSigner: f.keys[index], onSign: func() { signs[index]++ }}
	}
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	samples.Store(0)
	first, err := provider.Announce("next", jack.KeyID(f.keys[1].PublicKey()))
	if err != nil || first.Record.PublishedAt != 1000 || first.Revision != 2 || samples.Load() != 1 {
		t.Fatalf("first authorization: sample=%d err=%v", samples.Load(), err)
	}
	second, err := provider.Announce("tail", jack.KeyID(f.keys[2].PublicKey()))
	if err != nil || second.Record.PublishedAt != 1000 || second.Revision != 3 || second.Record.OldKID != first.Record.NewKID || samples.Load() != 2 {
		t.Fatal("pending tail could not authorize overlapping successor", err)
	}
	if signs != [3]int{1, 2, 1} {
		t.Fatalf("unexpected proof/authorization calls: %v", signs)
	}
	if _, err := provider.Announce("next", first.Record.NewKID); err == nil || samples.Load() != 2 || signs != [3]int{1, 2, 1} {
		t.Fatal("retained-key reuse reached clock or signers")
	}
	if _, err := provider.Announce("unknown", first.Record.NewKID); err == nil || samples.Load() != 2 {
		t.Fatal("unknown inventory entry sampled time")
	}
	loaded, _, err := f.store.Snapshot()
	if err != nil || loaded.Public.Revision != 3 || len(loaded.Public.Records) != 2 || loaded.Public.Records[0] != first.Record.Wire || loaded.Public.Records[1] != second.Record.Wire {
		t.Fatal("exact publication ACK not persisted")
	}
}

func TestAnnounceDelayedProofDoesNotResampleOrMoveP(t *testing.T) {
	samples := &atomic.Int64{}
	f := setupWithClock(t, func(source func() int64) func() int64 {
		return func() int64 { samples.Add(1); return source() }
	})
	f.inventory[1].Signer = signingHook{testSigner: f.keys[1], onSign: func() { f.now.Store(1100) }}
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	samples.Store(0)
	publication, err := provider.Announce("next", jack.KeyID(f.keys[1].PublicKey()))
	if err != nil || publication.Record.PublishedAt != 1000 || publication.Record.ActivatesAt != 1000+rotation.GraceSeconds || samples.Load() != 1 {
		t.Fatal("publication resampled or shifted fixed P", err)
	}
}

func TestAnnounceConcurrentClockConflictDoesNotRetryOrPublish(t *testing.T) {
	f := setup(t)
	proofs, authorizations := 0, 0
	f.inventory[0].Signer = signingHook{testSigner: f.keys[0], onSign: func() { authorizations++ }}
	f.inventory[1].Signer = signingHook{testSigner: f.keys[1], onSign: func() {
		proofs++
		f.now.Store(1001)
		if _, err := f.store.AdvanceAndCheck(); err != nil {
			t.Fatal(err)
		}
	}}
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := provider.Announce("next", jack.KeyID(f.keys[1].PublicKey()))
	var refusal *rotation.Error
	if !errors.As(err, &refusal) || refusal.Code != "rotation_state_changed" || publication.Record.Wire != "" || proofs != 1 || authorizations != 1 {
		t.Fatal("conflict retried or exposed tentative record", err)
	}
	snapshot, _, err := f.store.Snapshot()
	if err != nil || snapshot.Public.Revision != 1 || len(snapshot.Public.Records) != 0 {
		t.Fatal("definite conflict changed ring or fenced healthy owner")
	}
}

func setupCapacityFixture(t *testing.T, count int) fixture {
	t.Helper()
	keys := make([]testSigner, count)
	for index := range keys {
		keys[index] = makeSigner(byte(31 + index))
	}
	checkpoint := rotation.Checkpoint{Hash: "-", KID: jack.KeyID(keys[0].PublicKey())}
	copy(checkpoint.PublicKey[:], keys[0].PublicKey())
	now := &atomic.Int64{}
	now.Store(1000)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	options := durable.ServerOptions{TrustOptions: durable.TrustOptions{Binding: rotation.Binding{Endpoint: "https://public.invalid/mcp", Audience: "provider-test"}, Window: 30, Checkpoint: checkpoint, Now: now.Load}, AnchorReference: "anchor"}
	path := filepath.Join(directory, "server.db")
	if err := durable.InitializeServerUnused(path, options); err != nil {
		t.Fatal(err)
	}
	store, err := durable.OpenServer(path, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	inventory := make([]rotationserver.Key, count)
	inventory[0] = rotationserver.Key{Reference: "anchor", Signer: keys[0]}
	for index := 1; index < count; index++ {
		inventory[index] = rotationserver.Key{Reference: "next", Signer: keys[index]}
	}
	return fixture{store: store, now: now, keys: keys, inventory: inventory}
}

func TestAnnounceRefusesRingBeyondServableRetiredCapacity(t *testing.T) {
	if rotationserver.MaxAnnounceRingKeysForTest() != rotationserver.ServedRetiredKeysForTest()+1 {
		t.Fatal("announce bound does not match serving retired limit")
	}
	restore := rotationserver.SetMaxAnnounceRingKeysForTest(4)
	t.Cleanup(restore)
	f := setupCapacityFixture(t, 5)
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	for step := 1; step <= 3; step++ {
		publication, err := provider.Announce("next", jack.KeyID(f.keys[step].PublicKey()))
		if err != nil || publication.Record.ActivatesAt != f.now.Load()+rotation.GraceSeconds {
			t.Fatalf("announce %d refused: err=%v", step, err)
		}
	}
	before, _, err := f.store.Snapshot()
	if err != nil || len(before.Public.Keys) != 4 {
		t.Fatalf("ring after 3 announces: keys=%d err=%v", len(before.Public.Keys), err)
	}
	if _, err := provider.Announce("next", jack.KeyID(f.keys[4].PublicKey())); !errors.Is(err, rotationserver.ErrUnavailable) {
		t.Fatalf("announce with 4-key ring not refused: err=%v", err)
	}
	after, _, err := f.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if after.Public.Revision != before.Public.Revision || after.Public.Head != before.Public.Head || !reflect.DeepEqual(before.Public.Keys, after.Public.Keys) || !reflect.DeepEqual(before.Public.Records, after.Public.Records) {
		t.Fatal("refused announcement mutated committed ring")
	}
}

type faultyProof struct {
	testSigner
	panicInstead bool
}

func (signer faultyProof) Sign([]byte) ([]byte, error) {
	if signer.panicInstead {
		panic("private signer failure must not escape")
	}
	return make([]byte, 64), nil
}

func TestAnnounceInvalidOrPanickingProofNeverInvokesOldAuthorization(t *testing.T) {
	for _, panicInstead := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid-proof", true: "panic"}[panicInstead], func(t *testing.T) {
			f := setup(t)
			oldCalls := 0
			f.inventory[0].Signer = signingHook{testSigner: f.keys[0], onSign: func() { oldCalls++ }}
			f.inventory[1].Signer = faultyProof{testSigner: f.keys[1], panicInstead: panicInstead}
			provider, err := rotationserver.New(f.store, f.inventory)
			if err != nil {
				t.Fatal(err)
			}
			publication, err := provider.Announce("next", jack.KeyID(f.keys[1].PublicKey()))
			if !errors.Is(err, rotationserver.ErrUnavailable) || publication.Record.Wire != "" || oldCalls != 0 {
				t.Fatal("failed proof authorized/exposed successor", err)
			}
			snapshot, _, err := f.store.Snapshot()
			if err != nil || snapshot.Public.Revision != 1 || len(snapshot.Public.Records) != 0 {
				t.Fatal("proof failure mutated committed ring")
			}
			if err := f.store.Close(); err != nil {
				t.Fatal("failed proof leaked lease", err)
			}
		})
	}
}

func expectIdentity(t *testing.T, provider *rotationserver.Provider, key testSigner, timestamp int64) {
	t.Helper()
	authorization, err := provider.AuthorizeResponse(server.ResponseKeyRequest{Body: []byte("untrusted selector"), Tool: "not-a-key-authority"})
	if err != nil {
		t.Fatal(err)
	}
	defer authorization.Release()
	if authorization.Timestamp != timestamp || !bytes.Equal(authorization.Signer.PublicKey(), key.PublicKey()) {
		t.Fatal("wrong scheduled identity/time")
	}
	message := jack.ResponseSigningString(200, "request-signature", jack.KeyID(key.PublicKey()), timestamp, []byte("exact body"))
	signature, err := authorization.Signer.Sign([]byte(message))
	if err != nil || !jack.Verify(key.PublicKey(), []byte(message), signature) {
		t.Fatal("pinned signer did not sign exact response")
	}
	if err := authorization.Final(); err != nil {
		t.Fatal(err)
	}
	if err := authorization.Final(); err == nil {
		t.Fatal("final authority reused")
	}
}

func TestProviderOverlappingPendingTailAndEqualActivationOrdinal(t *testing.T) {
	f := setup(t)
	first := publish(t, f, 1)
	second := publish(t, f, 2)
	if first.ActivatesAt != second.ActivatesAt {
		t.Fatal("fixture is not equal-time overlap")
	}
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	f.inventory[0].Reference = "mutated caller slice"
	expectIdentity(t, provider, f.keys[0], 1000)
	f.now.Store(first.ActivatesAt - 1)
	expectIdentity(t, provider, f.keys[0], first.ActivatesAt-1)
	f.now.Store(first.ActivatesAt)
	expectIdentity(t, provider, f.keys[2], first.ActivatesAt)
}

func TestProviderMissingPendingOrCurrentSignerNeverFallsBack(t *testing.T) {
	f := setup(t)
	first := publish(t, f, 1)
	if provider, err := rotationserver.New(f.store, f.inventory[:1]); err == nil || provider != nil {
		t.Fatal("missing pending signer ignored")
	}
	f.now.Store(first.ActivatesAt)
	if provider, err := rotationserver.New(f.store, f.inventory[:1]); err == nil || provider != nil {
		t.Fatal("missing current signer fell back to old")
	}
	provider, err := rotationserver.New(f.store, f.inventory[1:2])
	if err != nil {
		t.Fatal("retired old signer unnecessarily required", err)
	}
	expectIdentity(t, provider, f.keys[1], first.ActivatesAt)
}

func TestProviderFinalCutoffFreshnessRollbackAndStateChange(t *testing.T) {
	for _, scenario := range []string{"cutoff", "freshness", "rollback", "publication", "released"} {
		t.Run(scenario, func(t *testing.T) {
			f := setup(t)
			first := publish(t, f, 1)
			provider, err := rotationserver.New(f.store, f.inventory)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "cutoff" {
				f.now.Store(first.ActivatesAt - 1)
			}
			authorization, err := provider.AuthorizeResponse(server.ResponseKeyRequest{})
			if err != nil {
				t.Fatal(err)
			}
			defer authorization.Release()
			switch scenario {
			case "cutoff":
				f.now.Store(first.ActivatesAt)
			case "freshness":
				f.now.Store(1031)
			case "rollback":
				f.now.Store(999)
			case "publication":
				publish(t, f, 2)
			case "released":
				authorization.Release()
			}
			if err := authorization.Final(); err == nil {
				t.Fatal("late gate exposed stale authority")
			}
		})
	}
}

func TestProviderFinalFreshnessEqualityAndReleaseIdempotence(t *testing.T) {
	f := setup(t)
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := provider.AuthorizeResponse(server.ResponseKeyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	f.now.Store(1030)
	if err := authorization.Final(); err != nil {
		t.Fatal("inclusive freshness equality refused", err)
	}
	authorization.Release()
	authorization.Release()
	if err := f.store.Close(); err != nil {
		t.Fatal("lease leaked or double-released", err)
	}
	if _, err := provider.AuthorizeResponse(server.ResponseKeyRequest{}); err == nil {
		t.Fatal("closed owner served")
	}
}
