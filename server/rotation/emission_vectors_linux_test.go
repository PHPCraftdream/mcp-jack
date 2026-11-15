//go:build linux

package rotationserver_test

// Candidate rotation-state-vector conformance driver for the emission event
// family. It loads spec/fixtures/candidate/rotation-state-vectors.json
// (format "mcp-jack-candidate-rotation-state-v1") and replays the emission
// event cases against the real rotationserver.Provider over the real
// bbolt-backed durable.ServerStore (setup/publish helpers from
// provider_linux_test.go). Every event_case id must have a plan or an entry
// in emissionVectorExclusions with a reason and spec quote; plans must exist
// in the fixture; no silent skips. The selection family is driven in
// rotation/ and the clock family in durable/.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

const emissionVectorFixtureFormat = "mcp-jack-candidate-rotation-state-v1"
const emissionVectorFixturePath = "../spec/fixtures/candidate/rotation-state-vectors.json"

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

	seen := make(map[string]int, len(fixture.EventCases))
	for _, event := range fixture.EventCases {
		seen[event.ID]++
		switch {
		case plans[event.ID]:
			t.Run(event.ID, func(t *testing.T) { driveEmissionVector(t, event) })
		case emissionVectorExclusions[event.ID].reason != "":
			t.Run(event.ID, func(t *testing.T) {
				exclusion := emissionVectorExclusions[event.ID]
				t.Skipf("excluded: %s | spec: %s", exclusion.reason, exclusion.spec)
			})
		default:
			t.Fatalf("event_case %q has no emission plan or exclusion", event.ID)
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
