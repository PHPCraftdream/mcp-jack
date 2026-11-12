package rotation_test

import (
	"errors"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/rotation"
)

func trustFixture(t *testing.T) (rotation.TrustSnapshot, rotation.Binding, rotation.Checkpoint) {
	t.Helper()
	vectors, binding, checkpoint, _ := fixture(t)
	recordWires := vectors.Chains["overlapping"]
	wires := make([][]byte, len(recordWires))
	for index, wire := range recordWires {
		wires[index] = []byte(wire)
	}
	records, err := rotation.VerifyChain(wires, binding, checkpoint, nil)
	if err != nil || len(records) != 2 {
		t.Fatal("independent chain fixture invalid")
	}
	snapshot := trustFromRecords(binding, checkpoint, records)
	return snapshot, binding, checkpoint
}

func trustFromRecords(binding rotation.Binding, checkpoint rotation.Checkpoint, records []rotation.Record) rotation.TrustSnapshot {
	snapshot := rotation.TrustSnapshot{
		FormatVersion: 1, Binding: binding, Window: 30, Checkpoint: checkpoint,
		Head: rotation.ResultCursor{Ordinal: checkpoint.Ordinal, Hash: checkpoint.Hash}, Revision: 1,
		Clock: rotation.ClockTuple{Binding: binding, Window: 30, Revision: 4},
		Keys:  []rotation.TrustKey{{Ordinal: checkpoint.Ordinal, KID: checkpoint.KID, PublicKey: checkpoint.PublicKey}},
	}
	if checkpoint.Ordinal != 0 {
		snapshot.Keys[0].NotBefore = checkpoint.PublishedAt + rotation.GraceSeconds
	}
	for index, record := range records {
		cutoff := record.ActivatesAt
		snapshot.Keys[index].KnownCutoff = &cutoff
		snapshot.Keys = append(snapshot.Keys, rotation.TrustKey{Ordinal: record.Ordinal, KID: record.NewKID, PublicKey: record.PublicKey, NotBefore: record.ActivatesAt})
		snapshot.Records = append(snapshot.Records, record.Wire)
		snapshot.Head = rotation.ResultCursor{Ordinal: record.Ordinal, Hash: record.Hash}
	}
	return snapshot
}

func TestTrustSnapshotIndependentChainAndOwnedMetadata(t *testing.T) {
	input, binding, checkpoint := trustFixture(t)
	output, err := rotation.ValidateTrustSnapshot(input, binding, 30, checkpoint)
	if err != nil || len(output.Keys) != 3 || output.Head.Ordinal != 2 || output.Clock != input.Clock {
		t.Fatalf("valid whole snapshot refused: %v", err)
	}
	wire := output.Records[0]
	cutoff := *output.Keys[0].KnownCutoff
	input.Records[0] = "changed"
	*input.Keys[0].KnownCutoff = 1
	input.Keys[1].PublicKey[0] ^= 1
	if output.Records[0] != wire || *output.Keys[0].KnownCutoff != cutoff || output.Keys[1].PublicKey == input.Keys[1].PublicKey {
		t.Fatal("validated snapshot aliases input metadata")
	}
	*output.Keys[1].KnownCutoff = 2
	if *output.Keys[0].KnownCutoff != cutoff {
		t.Fatal("different key cutoff cells alias")
	}
}

func TestTrustSnapshotRejectsEveryRedundantStateMismatch(t *testing.T) {
	mutations := map[string]func(*rotation.TrustSnapshot){
		"format":            func(s *rotation.TrustSnapshot) { s.FormatVersion = 2 },
		"endpoint":          func(s *rotation.TrustSnapshot) { s.Binding.Endpoint += "/other" },
		"window":            func(s *rotation.TrustSnapshot) { s.Window++ },
		"checkpoint":        func(s *rotation.TrustSnapshot) { s.Checkpoint.Hash = "changed" },
		"head":              func(s *rotation.TrustSnapshot) { s.Head.Ordinal++ },
		"revision-zero":     func(s *rotation.TrustSnapshot) { s.Revision = 0 },
		"revision-overflow": func(s *rotation.TrustSnapshot) { s.Revision = rotation.MaxOrdinal + 1 },
		"clock-binding":     func(s *rotation.TrustSnapshot) { s.Clock.Binding.Audience += "other" },
		"clock-window":      func(s *rotation.TrustSnapshot) { s.Clock.Window++ },
		"clock-negative":    func(s *rotation.TrustSnapshot) { s.Clock.HighWater = -1 },
		"clock-overflow":    func(s *rotation.TrustSnapshot) { s.Clock.Revision = rotation.MaxOrdinal + 1 },
		"missing-key":       func(s *rotation.TrustSnapshot) { s.Keys = s.Keys[:2] },
		"key-id":            func(s *rotation.TrustSnapshot) { s.Keys[1].KID = s.Keys[0].KID },
		"key-public":        func(s *rotation.TrustSnapshot) { s.Keys[1].PublicKey[0] ^= 1 },
		"key-ordinal":       func(s *rotation.TrustSnapshot) { s.Keys[1].Ordinal++ },
		"key-lower":         func(s *rotation.TrustSnapshot) { s.Keys[1].NotBefore-- },
		"key-cutoff":        func(s *rotation.TrustSnapshot) { *s.Keys[0].KnownCutoff += 1 },
		"missing-cutoff":    func(s *rotation.TrustSnapshot) { s.Keys[0].KnownCutoff = nil },
		"extra-cutoff":      func(s *rotation.TrustSnapshot) { cutoff := int64(1); s.Keys[2].KnownCutoff = &cutoff },
		"record-proof":      func(s *rotation.TrustSnapshot) { s.Records[0] += "\n" },
		"record-gap":        func(s *rotation.TrustSnapshot) { s.Records = s.Records[1:]; s.Keys = s.Keys[1:] },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			snapshot, binding, checkpoint := trustFixture(t)
			mutate(&snapshot)
			_, err := rotation.ValidateTrustSnapshot(snapshot, binding, 30, checkpoint)
			var rejection *rotation.Error
			if !errors.As(err, &rejection) || rejection.Code != "rotation_state_unknown" {
				t.Fatalf("invalid whole snapshot accepted: %v", err)
			}
		})
	}
}

func TestTrustSnapshotProvisionedCheckpointAndClockDependency(t *testing.T) {
	vectors, binding, anchor, _ := fixture(t)
	wires := make([][]byte, len(vectors.Chains["overlapping"]))
	for index, wire := range vectors.Chains["overlapping"] {
		wires[index] = []byte(wire)
	}
	records, err := rotation.VerifyChain(wires, binding, anchor, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := records[0]
	checkpoint := rotation.Checkpoint{Ordinal: first.Ordinal, Hash: first.Hash, KID: first.NewKID, PublicKey: first.PublicKey, PublishedAt: first.PublishedAt}
	snapshot := trustFromRecords(binding, checkpoint, records[1:])
	snapshot.Clock.HighWater = first.ActivatesAt
	validated, err := rotation.ValidateTrustSnapshot(snapshot, binding, 30, checkpoint)
	if err != nil || validated.Keys[0].NotBefore != first.ActivatesAt {
		t.Fatalf("exact OOB checkpoint refused: %v", err)
	}
	if _, err := rotation.ValidateTrustSnapshot(snapshot, binding, 30, anchor); err == nil {
		t.Fatal("remote snapshot replaced independently provisioned anchor")
	}
	clock := snapshot.Clock
	clock.HighWater++
	clock.Revision++
	if !rotation.TrustClockCompatible(validated, clock) {
		t.Fatal("later authoritative guard rejected")
	}
	for _, mutate := range []func(*rotation.ClockTuple){
		func(c *rotation.ClockTuple) { c.HighWater = snapshot.Clock.HighWater - 1 },
		func(c *rotation.ClockTuple) { c.Revision = snapshot.Clock.Revision - 1 },
		func(c *rotation.ClockTuple) { c.Unsafe = true },
		func(c *rotation.ClockTuple) { c.Window++ },
		func(c *rotation.ClockTuple) { c.Binding.Audience += "other" },
	} {
		wrong := clock
		mutate(&wrong)
		if rotation.TrustClockCompatible(validated, wrong) {
			t.Fatal("incompatible authoritative clock accepted")
		}
	}
	validated.Fenced = true
	if rotation.TrustClockCompatible(validated, clock) {
		t.Fatal("trust fence ignored")
	}
	validated.Fenced = false
	validated.Clock.Unsafe = true
	if rotation.TrustClockCompatible(validated, clock) {
		t.Fatal("copied unsafe dependency ignored")
	}
}
