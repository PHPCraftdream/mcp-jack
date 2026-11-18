package rotation_test

import (
	"encoding/json"
	"os"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

type keyVector struct {
	Public string `json:"public_key"`
	KID    string `json:"kid"`
}

type vectors struct {
	Binding struct {
		Endpoint string `json:"endpoint"`
		Audience string `json:"aud"`
	} `json:"binding"`
	Keys     map[string]keyVector `json:"keys"`
	Chains   map[string][]string  `json:"valid_chains"`
	Controls struct {
		DecreasingPrefix string `json:"decreasing_prefix"`
	} `json:"source_controls"`
	Malformed []struct {
		ID       string `json:"id"`
		Expected string `json:"expected"`
		Wire     string `json:"wire_b64u"`
		Setup    string `json:"setup"`
		Binding  struct {
			Endpoint string `json:"endpoint"`
			Audience string `json:"aud"`
		} `json:"binding"`
	} `json:"malformed"`
}

func fixture(t *testing.T) (vectors, rotation.Binding, rotation.Checkpoint, map[string][]byte) {
	t.Helper()
	data, err := os.ReadFile("../../../spec/fixtures/candidate/rotation-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	binding := rotation.Binding{Endpoint: v.Binding.Endpoint, Audience: v.Binding.Audience}
	keys := make(map[string][]byte)
	for _, key := range v.Keys {
		public, err := jack.DecodeBase64URLFixed(key.Public, 32)
		if err != nil {
			t.Fatal(err)
		}
		keys[key.KID] = public
	}
	anchor := rotation.Checkpoint{Hash: "-", KID: v.Keys["anchor"].KID}
	copy(anchor.PublicKey[:], keys[anchor.KID])
	return v, binding, anchor, keys
}

func wires(chain []string) [][]byte {
	out := make([][]byte, len(chain))
	for i, record := range chain {
		out[i] = []byte(record)
	}
	return out
}

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
