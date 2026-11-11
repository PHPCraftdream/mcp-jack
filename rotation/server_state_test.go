package rotation_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/rotation"
)

func serverFixture(t *testing.T) (rotation.ServerSnapshot, rotation.Binding, rotation.Checkpoint) {
	t.Helper()
	public, binding, checkpoint := trustFixture(t)
	references := make([]rotation.SignerReference, len(public.Keys))
	for index, key := range public.Keys { references[index] = rotation.SignerReference{KID: key.KID, Reference: "opaque-provider/"+key.KID} }
	return rotation.ServerSnapshot{FormatVersion: 1, Public: public, SignerReferences: references}, binding, checkpoint
}

func TestServerSnapshotProtectedReferencesRoundTripAndOwnedValues(t *testing.T) {
	snapshot, binding, checkpoint := serverFixture(t)
	encoded, err := rotation.EncodeServerSnapshot(snapshot, binding, 30, checkpoint)
	if err != nil { t.Fatal(err) }
	loaded, err := rotation.DecodeServerSnapshot(encoded, binding, 30, checkpoint)
	if err != nil || !reflect.DeepEqual(snapshot, loaded) { t.Fatalf("server state changed on roundtrip: %v", err) }
	ref := loaded.SignerReferences[0].Reference
	wire := loaded.Public.Records[0]
	snapshot.SignerReferences[0].Reference = "changed"
	snapshot.Public.Records[0] = "changed"
	if loaded.SignerReferences[0].Reference != ref || loaded.Public.Records[0] != wire { t.Fatal("server state aliases caller buffers") }
	publicBytes, err := rotation.EncodeTrustSnapshot(loaded.Public, binding, 30, checkpoint)
	if err != nil || bytes.Contains(publicBytes, []byte("opaque-provider")) || bytes.Contains(publicBytes, []byte("signer_refs")) {
		t.Fatal("protected references leaked into public trust representation")
	}
	loaded.SignerReferences[1].Reference = loaded.SignerReferences[0].Reference
	if _, err := rotation.ValidateServerSnapshot(loaded, binding, 30, checkpoint); err != nil { t.Fatal("opaque provider reference treated as public key authority") }
}

func TestServerPublicationFixedPOverlappingTransitionsAndPreservedReferences(t *testing.T) {
	vectors, binding, checkpoint, _ := fixture(t)
	wires := make([][]byte, len(vectors.Chains["overlapping"]))
	for index, wire := range vectors.Chains["overlapping"] { wires[index] = []byte(wire) }
	records, err := rotation.VerifyChain(wires, binding, checkpoint, nil)
	if err != nil { t.Fatal(err) }
	makeState := func(count int) rotation.ServerSnapshot {
		public := trustFromRecords(binding, checkpoint, records[:count])
		public.Revision = uint64(count)+1
		if count != 0 { public.Clock.HighWater = records[count-1].PublishedAt; public.Clock.Revision += uint64(count) }
		refs := make([]rotation.SignerReference, len(public.Keys))
		for index, key := range public.Keys { refs[index] = rotation.SignerReference{KID: key.KID, Reference: "opaque/"+key.KID} }
		return rotation.ServerSnapshot{FormatVersion: 1, Public: public, SignerReferences: refs}
	}
	anchor, first, second := makeState(0), makeState(1), makeState(2)
	if _, err := rotation.ValidateServerPublication(anchor, first, binding, 30, checkpoint); err != nil { t.Fatal("first fixed-P publication rejected") }
	if records[1].PublishedAt >= records[0].ActivatesAt { t.Fatal("independent fixture lacks overlapping pending announcements") }
	if _, err := rotation.ValidateServerPublication(first, second, binding, 30, checkpoint); err != nil { t.Fatal("pending-tail successor publication rejected") }
	if _, err := rotation.ValidateServerPublication(anchor, second, binding, 30, checkpoint); err == nil { t.Fatal("one publication silently batched two authorizations") }
	wrongTime := makeState(1)
	wrongTime.Public.Clock.HighWater++
	if _, err := rotation.ValidateServerPublication(anchor, wrongTime, binding, 30, checkpoint); err == nil { t.Fatal("fixed P resampled or moved") }
	wrongRef := makeState(1)
	wrongRef.SignerReferences[0].Reference = "replacement"
	if _, err := rotation.ValidateServerPublication(anchor, wrongRef, binding, 30, checkpoint); err == nil { t.Fatal("publication replaced existing signer reference") }
}

func TestServerSnapshotRejectsMissingMismatchedAndOversizedReferences(t *testing.T) {
	for _, mutate := range []func(*rotation.ServerSnapshot){
		func(s *rotation.ServerSnapshot) { s.FormatVersion = 2 },
		func(s *rotation.ServerSnapshot) { s.SignerReferences = s.SignerReferences[:2] },
		func(s *rotation.ServerSnapshot) { s.SignerReferences[0].KID = s.SignerReferences[1].KID },
		func(s *rotation.ServerSnapshot) { s.SignerReferences[0].Reference = "" },
		func(s *rotation.ServerSnapshot) { s.SignerReferences[0].Reference = strings.Repeat("x", rotation.MaxSignerReferenceBytes+1) },
		func(s *rotation.ServerSnapshot) { s.SignerReferences[0].Reference = string([]byte{0xff}) },
		func(s *rotation.ServerSnapshot) { s.Public.Keys[0].NotBefore++ },
	} {
		snapshot, binding, checkpoint := serverFixture(t)
		mutate(&snapshot)
		_, err := rotation.EncodeServerSnapshot(snapshot, binding, 30, checkpoint)
		var refusal *rotation.Error
		if !errors.As(err, &refusal) || refusal.Code != "rotation_state_unavailable" { t.Fatalf("bad protected snapshot accepted: %v", err) }
	}
}

func TestServerSnapshotStrictCodecNeverRepairsFencesOrAddsPrivateFields(t *testing.T) {
	snapshot, binding, checkpoint := serverFixture(t)
	encoded, err := rotation.EncodeServerSnapshot(snapshot, binding, 30, checkpoint)
	if err != nil { t.Fatal(err) }
	for _, replacement := range []struct{ from, to string }{
		{`"format_version":1`, `"format_version":1,"format_version":1`},
		{`"format_version":1`, `"format_version":1e0`},
		{`"reference":`, `"private_key":"forbidden","reference":`},
		{`"reference":`, `"reference":null,"reference":`},
	} {
		changed := bytes.Replace(encoded, []byte(replacement.from), []byte(replacement.to), 1)
		if bytes.Equal(changed, encoded) { t.Fatal("negative token missing") }
		if _, err := rotation.DecodeServerSnapshot(changed, binding, 30, checkpoint); err == nil { t.Fatal("ambiguous server schema accepted") }
	}
	var reordered map[string]any
	if json.Unmarshal(encoded, &reordered) != nil { t.Fatal("positive schema malformed") }
	alternative, err := json.MarshalIndent(reordered, "", "  ")
	if err != nil { t.Fatal(err) }
	if _, err := rotation.DecodeServerSnapshot(alternative, binding, 30, checkpoint); err != nil { t.Fatal("object ordering changed server state") }
	snapshot.Public.Fenced = true
	snapshot.Public.Clock.Unsafe = true
	encoded, err = rotation.EncodeServerSnapshot(snapshot, binding, 30, checkpoint)
	if err != nil { t.Fatal(err) }
	loaded, err := rotation.DecodeServerSnapshot(encoded, binding, 30, checkpoint)
	if err != nil || !loaded.Public.Fenced || !loaded.Public.Clock.Unsafe || rotation.TrustClockCompatible(loaded.Public, loaded.Public.Clock) { t.Fatal("server recovery parse repaired fence or implied readiness") }
}
