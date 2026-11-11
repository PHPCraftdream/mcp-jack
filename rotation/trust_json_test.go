package rotation_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/rotation"
)

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
	for _, replacement := range []struct { from, to string }{
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
