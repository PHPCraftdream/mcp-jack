//go:build linux

package rotationstore

// Candidate rotation-state-vector conformance driver for the clock event
// family. It loads spec/fixtures/candidate/rotation-state-vectors.json
// (format "mcp-jack-candidate-rotation-state-v1") and replays every clock
// event_case against the real bbolt-backed TrustStore through
// TrustStore.AdvanceAndCheck. The guard state (W=30, H=173800, revision=4) is
// seeded by driving the real path, not by direct bucket writes: the scripted
// clock feeds InitializeTrustUnused, OpenTrust (which performs its own
// mandatory advance), and explicit advances. Every event_case id must have a
// plan or an entry in clockVectorDeviations with a reason and spec quote;
// cases are driven with per-case t.Run and never skipped silently. The
// selection family is driven in rotation/ and the emission family in
// server/rotation/.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable/internal/testfixture"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

const clockVectorFixtureFormat = "mcp-jack-candidate-rotation-state-v1"
const clockVectorFixturePath = "../../../spec/fixtures/candidate/rotation-state-vectors.json"

type clockVectorFixture struct {
	Format      string             `json:"format"`
	ClientCases []json.RawMessage  `json:"client_cases"`
	EventCases  []clockVectorEvent `json:"event_cases"`
}

type clockVectorEvent struct {
	ID     string          `json:"id"`
	Input  json.RawMessage `json:"input"`
	Expect json.RawMessage `json:"expect"`
}

type clockVectorInput struct {
	Kind  string `json:"kind"`
	Guard struct {
		Binding   string `json:"binding"`
		Window    int64  `json:"window"`
		HighWater int64  `json:"highWater"`
		Revision  uint64 `json:"revision"`
	} `json:"guard"`
	RawNow int64  `json:"rawNow"`
	Latch  string `json:"latch"`
}

type clockVectorExpect struct {
	Error     *string `json:"error"`
	HighWater int64   `json:"highWater"`
	Revision  *uint64 `json:"revision"`
	Unsafe    bool    `json:"unsafe"`
	Writes    int     `json:"writes"`
	Callbacks int     `json:"callbacks"`
}

type clockVectorSnapshot struct {
	Endpoint string `json:"endpoint"`
	Audience string `json:"aud"`
}

type clockVectorClientCase struct {
	Input struct {
		Snapshot clockVectorSnapshot `json:"snapshot"`
	} `json:"input"`
}

var clockVectorDeviations = map[string][]string{
	"clock-rollback-latches": {
		"expect.callbacks=1 is the JS model's persistence-callback count; the Go TrustStore commits " +
			"the guard write itself (one transact call), so the driver counts one transact call instead " +
			"of a callback invocation.",
	},
	"clock-equal-is-noop": {
		"expect.writes=0 counts committed mutations; the Go advanceTrustClock always enters its " +
			"transaction (one transact call) but performs no Put on the equal branch, so exactly one " +
			"read-only transact call is observed and the guard bytes stay unchanged (revision 4).",
	},
	"clock-rollback-latch-unknown-is-unavailable": {
		"DEVIATION: Go has no uncertain-latch branch. The vector's unknown write outcome is modeled " +
			"by injecting a transact failure: the transaction rolls back, the revision stays 4, H stays " +
			"173800, unsafe stays false, and advanceTrustClock reports rotation_clock_unavailable. " +
			"Go ADDITIONALLY fences the store (store.failed()), so all later operations and Close fail " +
			"closed until recovery; the JS model persists nothing yet counts writes=1, and the driver " +
			"asserts zero committed writes and one transact call.",
		"Spec quote, spec/candidate/server-key-rotation.md L87 (clock guard): \"A definite failure or " +
			"unknown write outcome closes the binding and returns rotation_clock_unavailable; no " +
			"response success, key acceptance, or callback invocation is allowed.\"",
	},
	"clock-advance-persists-revision": {
		"expect.callbacks=1 is the JS model's persistence-callback count; the Go TrustStore commits " +
			"the guard write itself (one transact call).",
	},
}

// clockVectorCheckpoint is the deterministic anchor checkpoint of the vector guard.
func clockVectorCheckpoint() rotation.Checkpoint {
	sum := sha256.Sum256([]byte("mcp-jack test key: candidate-server-anchor"))
	public := ed25519.NewKeyFromSeed(sum[:]).Public().(ed25519.PublicKey)
	checkpoint := rotation.Checkpoint{Hash: "-", KID: jack.KeyID(public)}
	copy(checkpoint.PublicKey[:], public)
	return checkpoint
}

func loadClockVectorFixture(t *testing.T) clockVectorFixture {
	t.Helper()
	data, err := os.ReadFile(clockVectorFixturePath)
	if err != nil {
		t.Fatalf("candidate rotation-state vectors fixture: %v", err)
	}
	var fixture clockVectorFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("candidate rotation-state vectors fixture: %v", err)
	}
	if fixture.Format != clockVectorFixtureFormat {
		t.Fatalf("fixture format %q, want %q", fixture.Format, clockVectorFixtureFormat)
	}
	return fixture
}

func clockVectorBinding(t *testing.T, fixture clockVectorFixture) rotation.Binding {
	t.Helper()
	if len(fixture.ClientCases) == 0 {
		t.Fatal("fixture has no client_cases to derive the binding from")
	}
	var client clockVectorClientCase
	if err := json.Unmarshal(fixture.ClientCases[0], &client); err != nil {
		t.Fatalf("client_cases[0]: %v", err)
	}
	snapshot := client.Input.Snapshot
	if snapshot.Endpoint == "" || snapshot.Audience == "" {
		t.Fatal("client_cases[0].input.snapshot lacks binding endpoint/audience")
	}
	return rotation.Binding{Endpoint: snapshot.Endpoint, Audience: snapshot.Audience}
}

// newClockVectorStore seeds the exact vector guard (W=30, H=173800,
// revision=4) through the real path: init at 173797 (H=173797, revision=1),
// OpenTrust's mandatory advance at 173798 (revision=2), then explicit
// advances at 173799 and 173800 (revisions 3 and 4).
func newClockVectorStore(t *testing.T, binding rotation.Binding, clock *testfixture.ScriptedClock) *TrustStore {
	t.Helper()
	clock.Push(173797, 173798, 173799, 173800)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	options := TrustOptions{Binding: binding, Window: 30, Checkpoint: clockVectorCheckpoint(), Now: clock.Now}
	path := filepath.Join(directory, "trust.db")
	if err := InitializeTrustUnused(path, options); err != nil {
		t.Fatalf("InitializeTrustUnused: %v", err)
	}
	store, err := OpenTrust(path, options)
	if err != nil {
		t.Fatalf("OpenTrust: %v", err)
	}
	for _, sample := range []int64{173799, 173800} {
		tuple, err := store.AdvanceAndCheck()
		if err != nil || tuple.HighWater != sample || tuple.Revision != uint64(sample-173796) {
			t.Fatalf("seed advance to %d: tuple %+v err %v", sample, tuple, err)
		}
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func guardClockTuple(t *testing.T, store *TrustStore) rotation.ClockTuple {
	t.Helper()
	var guard trustGuard
	err := store.db.View(func(tx *bolt.Tx) error {
		raw, _, err := readTrustRows(tx)
		if err != nil {
			return err
		}
		guard, err = decodeTrustGuard(raw, store.options, store.identity.Profile)
		return err
	})
	if err != nil {
		t.Fatalf("read clock guard: %v", err)
	}
	return guard.Clock
}

type clockVectorCounters struct{ transactCalls int }

func countTrustTransact(store *TrustStore, counters *clockVectorCounters) {
	original := store.transact
	store.transact = func(apply func(*bolt.Tx) error) error {
		counters.transactCalls++
		return original(apply)
	}
}

func failTrustTransact(store *TrustStore, counters *clockVectorCounters) {
	store.transact = func(func(*bolt.Tx) error) error {
		counters.transactCalls++
		return errors.New("clock-vector injected unknown write outcome")
	}
}

func TestRotationStateClockVectors(t *testing.T) {
	fixture := loadClockVectorFixture(t)
	binding := clockVectorBinding(t, fixture)
	plans := map[string]bool{
		"clock-rollback-latches":                      true,
		"clock-equal-is-noop":                         true,
		"clock-rollback-latch-unknown-is-unavailable": true,
		"clock-advance-persists-revision":             true,
	}

	// Event families driven by other packages (see rotation/rotation_state_vectors_test.go).
	otherPackageEvents := map[string]string{
		"same-second-greatest-ordinal-wins":         "rotation",
		"server-final-eligible-single-signature":    "server/rotation",
		"server-final-cutoff-no-resign":             "server/rotation",
		"server-final-generation-fence-no-fallback": "server/rotation",
	}
	seen := make(map[string]int, len(fixture.EventCases))
	driven := 0
	summaryPass := 0
	deviation := 0
	for _, event := range fixture.EventCases {
		seen[event.ID]++
		switch {
		case plans[event.ID]:
			if t.Run(event.ID, func(t *testing.T) { driveClockVector(t, event, binding) }) {
				driven++
				switch event.ID {
				case "clock-equal-is-noop", "clock-rollback-latch-unknown-is-unavailable":
					deviation++
				default:
					summaryPass++
				}
			}
		case otherPackageEvents[event.ID] != "":
			// Driven and reverse-guarded by the named package runner.
			continue
		default:
			t.Fatalf("event_case %q has no clock plan and is not accounted by another package", event.ID)
		}
	}
	for id := range plans {
		if seen[id] != 1 {
			t.Fatalf("planned event_case %q appears %d times in the fixture", id, seen[id])
		}
	}
	if len(seen) != len(fixture.EventCases) {
		t.Fatal("duplicate event_case ids in fixture")
	}
	if driven != len(plans) {
		t.Fatalf("drove %d clock cases, planned %d", driven, len(plans))
	}
	t.Logf("VECTOR-SUMMARY corpus=rotation-state sdk=go component=clock pass=%d excluded=0 deviation=%d", driven-deviation, deviation)
}

func driveClockVector(t *testing.T, event clockVectorEvent, binding rotation.Binding) {
	t.Helper()
	deviations, documented := clockVectorDeviations[event.ID]
	if !documented {
		t.Fatalf("event_case %q has no plan or documented deviation", event.ID)
	}
	for index, note := range deviations {
		t.Logf("deviation %d: %s", index, note)
	}
	var input clockVectorInput
	if err := json.Unmarshal(event.Input, &input); err != nil {
		t.Fatalf("input: %v", err)
	}
	if input.Kind != "clock" {
		t.Fatalf("kind %q, want clock", input.Kind)
	}
	if input.Guard.Window != 30 || input.Guard.HighWater != 173800 || input.Guard.Revision != 4 {
		t.Fatalf("unexpected guard %+v", input.Guard)
	}
	if input.Guard.Binding != binding.Endpoint {
		t.Fatalf("guard binding %q, want %q", input.Guard.Binding, binding.Endpoint)
	}
	var expect clockVectorExpect
	if err := json.Unmarshal(event.Expect, &expect); err != nil {
		t.Fatalf("expect: %v", err)
	}

	clock := testfixture.NewScriptedClock()
	store := newClockVectorStore(t, binding, clock)
	seeded := guardClockTuple(t, store)
	if seeded.HighWater != input.Guard.HighWater || seeded.Revision != input.Guard.Revision ||
		seeded.Unsafe || seeded.Window != input.Guard.Window || seeded.Binding != binding {
		t.Fatalf("seeded guard %+v, want H=%d revision=%d window=%d unsafe=false binding=%+v",
			seeded, input.Guard.HighWater, input.Guard.Revision, input.Guard.Window, binding)
	}

	counters := &clockVectorCounters{}
	if input.Latch == "unknown" {
		failTrustTransact(store, counters)
	} else {
		countTrustTransact(store, counters)
	}
	clock.Push(input.RawNow)
	tuple, err := store.AdvanceAndCheck()

	var refusal *rotation.Error
	if expect.Error == nil {
		if err != nil {
			t.Fatalf("AdvanceAndCheck: %v", err)
		}
		if tuple.Binding != binding || tuple.Window != input.Guard.Window ||
			tuple.HighWater != expect.HighWater || tuple.Unsafe {
			t.Fatalf("clock tuple %+v, want H=%d unsafe=false", tuple, expect.HighWater)
		}
		if expect.Revision != nil && tuple.Revision != *expect.Revision {
			t.Fatalf("clock revision %d, want %d", tuple.Revision, *expect.Revision)
		}
	} else {
		if !errors.As(err, &refusal) || refusal.Code != *expect.Error {
			t.Fatalf("error %v, want %s", err, *expect.Error)
		}
		if tuple != (rotation.ClockTuple{}) {
			t.Fatalf("failed advance returned a tuple %+v, want zero", tuple)
		}
	}
	if counters.transactCalls != 1 {
		t.Fatalf("transact calls %d, want 1", counters.transactCalls)
	}

	guard := guardClockTuple(t, store)
	if guard.HighWater != expect.HighWater || guard.Unsafe != expect.Unsafe {
		t.Fatalf("guard H/unsafe %+v, want H=%d unsafe=%v", guard, expect.HighWater, expect.Unsafe)
	}
	if expect.Revision != nil && guard.Revision != *expect.Revision {
		t.Fatalf("guard revision %d, want %d", guard.Revision, *expect.Revision)
	}
	if guard.Binding != binding || guard.Window != input.Guard.Window {
		t.Fatalf("guard binding/window changed: %+v", guard)
	}
	if input.Latch == "unknown" {
		if !store.fenced.Load() {
			t.Fatal("unknown write outcome did not fence the store")
		}
		if err := store.Close(); err == nil {
			t.Fatal("fenced store closed cleanly")
		}
	} else if store.fenced.Load() {
		t.Fatal("definite advance outcome fenced the store")
	}
}
