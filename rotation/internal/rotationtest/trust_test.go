package rotation_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/rotation"
)

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

func TestTrustSnapshotCodecRoundTripAndCanonicalOutput(t *testing.T) {
	snapshot, binding, checkpoint := trustFixture(t)
	encoded, err := rotation.EncodeTrustSnapshot(snapshot, binding, 30, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := rotation.DecodeTrustSnapshot(encoded, binding, 30, checkpoint)
	if err != nil || !reflect.DeepEqual(decoded, snapshot) {
		t.Fatalf("whole-state round trip changed public values: %v", err)
	}
	var reordered map[string]any
	if json.Unmarshal(encoded, &reordered) != nil {
		t.Fatal("encoded document malformed")
	}
	alternative, err := json.MarshalIndent(reordered, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	other, err := rotation.DecodeTrustSnapshot(alternative, binding, 30, checkpoint)
	if err != nil || !reflect.DeepEqual(decoded, other) {
		t.Fatal("object member order or whitespace changed snapshot meaning")
	}
	again, err := rotation.EncodeTrustSnapshot(other, binding, 30, checkpoint)
	if err != nil || !bytes.Equal(encoded, again) {
		t.Fatal("canonical owned output is unstable")
	}
	for index := range encoded {
		encoded[index] = 0
	}
	if !reflect.DeepEqual(decoded, snapshot) {
		t.Fatal("decoded state borrows caller input bytes")
	}
}

func TestTrustSnapshotCodecRejectsSchemaAndScalarAmbiguity(t *testing.T) {
	snapshot, binding, checkpoint := trustFixture(t)
	encoded, err := rotation.EncodeTrustSnapshot(snapshot, binding, 30, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	deny := func(body []byte) {
		t.Helper()
		_, err := rotation.DecodeTrustSnapshot(body, binding, 30, checkpoint)
		var rejection *rotation.Error
		if !errors.As(err, &rejection) || rejection.Code != "rotation_state_unknown" {
			t.Fatalf("ambiguous state accepted: %v", err)
		}
	}
	for _, replacement := range []struct{ from, to string }{
		{`"format_version":1`, `"format_version":1,"format_version":1`},
		{`"fenced":false`, `"fenced":false,"fenced":false`},
		{`"unsafe":false`, `"unsafe":false,"unsafe":false`},
		{`"format_version":1`, `"format_version":1e0`},
		{`"window":30`, `"window":30.0`},
		{`"high_water":0`, `"high_water":-0`},
		{`"clock_revision":4`, `"clock_revision":4e0`},
		{`"fenced":false`, `"fenced":null`},
		{`"unsafe":false`, `"unsafe":"false"`},
		{`"high_water":0`, `"high_water":null`},
	} {
		if !bytes.Contains(encoded, []byte(replacement.from)) {
			t.Fatal("negative source token missing")
		}
		deny(bytes.Replace(encoded, []byte(replacement.from), []byte(replacement.to), 1))
	}
	for _, mutate := range []func(map[string]any){
		func(root map[string]any) { delete(root, "fenced") },
		func(root map[string]any) { root["private_key"] = "not allowed" },
		func(root map[string]any) { root["clock"].(map[string]any)["extra"] = true },
		func(root map[string]any) { delete(root["checkpoint"].(map[string]any), "published_at") },
		func(root map[string]any) { delete(root["keys"].([]any)[0].(map[string]any), "known_cutoff") },
		func(root map[string]any) { root["records"] = nil },
		func(root map[string]any) { root["keys"].([]any)[0].(map[string]any)["public_key"] = "wrong" },
		func(root map[string]any) { root["clock"].(map[string]any)["binding"].(map[string]any)["aud"] = "other" },
	} {
		var root map[string]any
		if json.Unmarshal(encoded, &root) != nil {
			t.Fatal("positive source malformed")
		}
		mutate(root)
		body, err := json.Marshal(root)
		if err != nil {
			t.Fatal(err)
		}
		deny(body)
	}
	deny(append(append([]byte{}, encoded...), []byte(`{}`)...))
	deny([]byte{0xff})
	deny(bytes.Replace(encoded, []byte(`"aud":`), []byte(`"aud":"\ud800","aud":`), 1))
}

func TestTrustSnapshotCodecEmptyAnchorFencesAndBodyLimit(t *testing.T) {
	_, binding, checkpoint, _ := fixture(t)
	snapshot := trustFromRecords(binding, checkpoint, nil)
	encoded, err := rotation.EncodeTrustSnapshot(snapshot, binding, 30, checkpoint)
	if err != nil || !bytes.Contains(encoded, []byte(`"records":[]`)) || !bytes.Contains(encoded, []byte(`"known_cutoff":null`)) {
		t.Fatalf("anchor-only canonical schema invalid: %v", err)
	}
	padding := make([]byte, rotation.MaxTrustSnapshotBytes)
	copy(padding, encoded)
	for index := len(encoded); index < len(padding); index++ {
		padding[index] = ' '
	}
	if _, err := rotation.DecodeTrustSnapshot(padding, binding, 30, checkpoint); err != nil {
		t.Fatal("inclusive full-body bound refused")
	}
	if _, err := rotation.DecodeTrustSnapshot(append(padding, ' '), binding, 30, checkpoint); err == nil {
		t.Fatal("oversized body accepted")
	}
	snapshot.Fenced = true
	snapshot.Clock.Unsafe = true
	encoded, err = rotation.EncodeTrustSnapshot(snapshot, binding, 30, checkpoint)
	if err != nil {
		t.Fatal("fenced recovery value cannot be encoded")
	}
	loaded, err := rotation.DecodeTrustSnapshot(encoded, binding, 30, checkpoint)
	if err != nil || !loaded.Fenced || !loaded.Clock.Unsafe || rotation.TrustClockCompatible(loaded, loaded.Clock) {
		t.Fatal("recovery decoding repaired a fence or implied readiness")
	}
	snapshot.Keys[0].KID = "changed"
	if _, err := rotation.EncodeTrustSnapshot(snapshot, binding, 30, checkpoint); err == nil {
		t.Fatal("encoder persisted invalid redundant state")
	}
}
