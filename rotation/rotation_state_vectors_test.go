package rotation_test

// Candidate rotation-state-vector conformance driver for the selection event
// family. It loads spec/fixtures/candidate/rotation-state-vectors.json
// (format "mcp-jack-candidate-rotation-state-v1") and replays the selection
// event cases through the real rotation.Parse + rotation.SelectedOrdinal
// implementations. Every event_case id must appear either in a plan below or
// in stateVectorDrivenElsewhere/stateVectorExclusions with a named reason and
// spec quote; the reverse guard asserts every plan id exists in the fixture. The clock
// and emission event families are driven in durable/ and server/rotation/
// respectively.

import (
	"encoding/json"
	"os"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

const stateVectorFixtureFormat = "mcp-jack-candidate-rotation-state-v1"
const stateVectorFixturePath = "../spec/fixtures/candidate/rotation-state-vectors.json"

type stateVectorFixture struct {
	Format      string             `json:"format"`
	ClientCases []json.RawMessage  `json:"client_cases"`
	EventCases  []stateVectorEvent `json:"event_cases"`
}

type stateVectorEvent struct {
	ID     string          `json:"id"`
	Input  json.RawMessage `json:"input"`
	Expect json.RawMessage `json:"expect"`
}

type stateVectorSelectionInput struct {
	Kind    string   `json:"kind"`
	Records []string `json:"records"`
	Before  int64    `json:"before"`
	At      int64    `json:"at"`
	After   int64    `json:"after"`
}

type stateVectorSelectionExpect struct {
	SelectedBefore uint64 `json:"selectedBefore"`
	SelectedAt     uint64 `json:"selectedAt"`
	SelectedAfter  uint64 `json:"selectedAfter"`
}

type stateVectorAnchor struct {
	PublicKey string `json:"public_key"`
	KID       string `json:"kid"`
}

type stateVectorSnapshot struct {
	Endpoint string            `json:"endpoint"`
	Audience string            `json:"aud"`
	Anchor   stateVectorAnchor `json:"anchor"`
}

type stateVectorClientCase struct {
	Input struct {
		Snapshot stateVectorSnapshot `json:"snapshot"`
	} `json:"input"`
}

type stateVectorExclusion struct {
	reason string
	spec   string
}

// Event-case accounting. The clock family is driven in durable, the emission
// family in server/rotation; this portable file drives only selection cases.
var stateVectorDrivenElsewhere = map[string]string{
	"clock-rollback-latches":                      "durable/rotation_clock_vectors_linux_test.go",
	"clock-equal-is-noop":                         "durable/rotation_clock_vectors_linux_test.go",
	"clock-rollback-latch-unknown-is-unavailable": "durable/rotation_clock_vectors_linux_test.go",
	"clock-advance-persists-revision":             "durable/rotation_clock_vectors_linux_test.go",
	"server-final-eligible-single-signature":      "server/rotation/emission_vectors_linux_test.go",
	"server-final-cutoff-no-resign":               "server/rotation/emission_vectors_linux_test.go",
}

var stateVectorExclusions = map[string]stateVectorExclusion{
	"server-final-generation-fence-no-fallback": {
		reason: "Not drivable against the Go seam: the vector's abstract clock generation 1 to 2 at " +
			"an unchanged whole second has no Go counterpart that can change while the store is " +
			"open. The Final closure revalidates through CheckSnapshotClock: the whole committed " +
			"snapshot bytes and ownedGuard (store id, owner generation, dirty epoch, fence) inside " +
			"one transaction, so a changed generation, owner or fence already refuses with " +
			"ErrUnavailable; the owner generation only changes at an exclusive owner handoff. " +
			"This is a mapping artefact, not a divergence.",
		spec: "spec/candidate/server-key-rotation.md L13: \"Immediately before emitting, take a fresh " +
			"whole-second sample and revalidate latest committed chain, generation/fence, signer " +
			"readiness, and that the selected key remains eligible at that fresh sample.\"",
	},
}

func loadStateVectorFixture(t *testing.T) stateVectorFixture {
	t.Helper()
	data, err := os.ReadFile(stateVectorFixturePath)
	if err != nil {
		t.Fatalf("candidate rotation-state vectors fixture: %v", err)
	}
	var fixture stateVectorFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("candidate rotation-state vectors fixture: %v", err)
	}
	if fixture.Format != stateVectorFixtureFormat {
		t.Fatalf("fixture format %q, want %q", fixture.Format, stateVectorFixtureFormat)
	}
	return fixture
}

func stateVectorBinding(t *testing.T, fixture stateVectorFixture) (rotation.Binding, map[string][]byte) {
	t.Helper()
	if len(fixture.ClientCases) == 0 {
		t.Fatal("fixture has no client_cases to derive the binding/anchor from")
	}
	var client stateVectorClientCase
	if err := json.Unmarshal(fixture.ClientCases[0], &client); err != nil {
		t.Fatalf("client_cases[0]: %v", err)
	}
	snapshot := client.Input.Snapshot
	if snapshot.Endpoint == "" || snapshot.Audience == "" || snapshot.Anchor.KID == "" {
		t.Fatal("client_cases[0].input.snapshot lacks binding/anchor")
	}
	public, err := jack.DecodeBase64URLFixed(snapshot.Anchor.PublicKey, 32)
	if err != nil {
		t.Fatalf("anchor public key: %v", err)
	}
	if jack.KeyID(public) != snapshot.Anchor.KID {
		t.Fatalf("anchor kid %s does not match public key", snapshot.Anchor.KID)
	}
	binding := rotation.Binding{Endpoint: snapshot.Endpoint, Audience: snapshot.Audience}
	authorizers := map[string][]byte{snapshot.Anchor.KID: append([]byte{}, public...)}
	return binding, authorizers
}

func TestRotationStateSelectionVectors(t *testing.T) {
	fixture := loadStateVectorFixture(t)
	plans := map[string]bool{"same-second-greatest-ordinal-wins": true}
	binding, authorizers := stateVectorBinding(t, fixture)

	seen := make(map[string]int, len(fixture.EventCases))
	driven := 0
	for _, event := range fixture.EventCases {
		seen[event.ID]++
		switch {
		case plans[event.ID]:
			if t.Run(event.ID, func(t *testing.T) { driveSelectionVector(t, event, binding, authorizers) }) {
				driven++
			}
		case stateVectorDrivenElsewhere[event.ID] != "":
			// Driven and reverse-guarded by the named package runner.
			t.Run(event.ID, func(t *testing.T) { t.Logf("driven in %s", stateVectorDrivenElsewhere[event.ID]) })
		case stateVectorExclusions[event.ID].reason != "":
			if !t.Run(event.ID, func(t *testing.T) {
				exclusion := stateVectorExclusions[event.ID]
				t.Skipf("excluded: %s | spec: %s", exclusion.reason, exclusion.spec)
			}) {
				t.Errorf("excluded event %q subtest failed", event.ID)
			}
		default:
			t.Fatalf("event_case %q has no plan, exclusion, or cross-package assignment", event.ID)
		}
	}
	for id := range plans {
		if seen[id] != 1 {
			t.Fatalf("planned event_case %q appears %d times in the fixture", id, seen[id])
		}
	}
	for id := range stateVectorDrivenElsewhere {
		if seen[id] != 1 {
			t.Fatalf("cross-package event_case %q appears %d times in the fixture", id, seen[id])
		}
	}
	for id := range stateVectorExclusions {
		if seen[id] != 1 {
			t.Fatalf("excluded event_case %q appears %d times in the fixture", id, seen[id])
		}
	}
	if driven != len(plans) {
		t.Fatalf("drove %d selection cases, planned %d", driven, len(plans))
	}
	t.Logf("VECTOR-SUMMARY corpus=rotation-state sdk=go component=selection pass=%d excluded=%d deviation=%d", driven, 0, 0)
}

func driveSelectionVector(t *testing.T, event stateVectorEvent, binding rotation.Binding, authorizers map[string][]byte) {
	t.Helper()
	var input stateVectorSelectionInput
	if err := json.Unmarshal(event.Input, &input); err != nil {
		t.Fatalf("input: %v", err)
	}
	if input.Kind != "selection" {
		t.Fatalf("kind %q, want selection", input.Kind)
	}
	if len(input.Records) != 2 {
		t.Fatalf("records: %d, want the equal-time tieR1/tieR2 pair", len(input.Records))
	}
	keys := make(map[string][]byte, len(authorizers))
	for kid, public := range authorizers {
		keys[kid] = append([]byte{}, public...)
	}
	records := make([]rotation.Record, 0, len(input.Records))
	for index, wire := range input.Records {
		record, err := rotation.Parse([]byte(wire), binding, keys)
		if err != nil {
			t.Fatalf("record %d: %v", index, err)
		}
		keys[record.NewKID] = append([]byte{}, record.PublicKey[:]...)
		records = append(records, record)
	}
	if records[0].Ordinal != 1 || records[1].Ordinal != 2 ||
		records[0].ActivatesAt != records[1].ActivatesAt {
		t.Fatalf("fixture is not the documented equal-time tie (ordinals %d/%d, activations %d/%d)",
			records[0].Ordinal, records[1].Ordinal, records[0].ActivatesAt, records[1].ActivatesAt)
	}
	var expect stateVectorSelectionExpect
	if err := json.Unmarshal(event.Expect, &expect); err != nil {
		t.Fatalf("expect: %v", err)
	}
	if got := rotation.SelectedOrdinal(records, input.Before); got != expect.SelectedBefore {
		t.Fatalf("selected(before=%d) = %d, want %d", input.Before, got, expect.SelectedBefore)
	}
	if got := rotation.SelectedOrdinal(records, input.At); got != expect.SelectedAt {
		t.Fatalf("selected(at=%d) = %d, want %d", input.At, got, expect.SelectedAt)
	}
	if got := rotation.SelectedOrdinal(records, input.After); got != expect.SelectedAfter {
		t.Fatalf("selected(after=%d) = %d, want %d", input.After, got, expect.SelectedAfter)
	}
}
