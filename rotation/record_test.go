package rotation_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

type keyVector struct {
	Public string `json:"public_key"`
	KID string `json:"kid"`
}

type vectors struct {
	Binding struct {
		Endpoint string `json:"endpoint"`
		Audience string `json:"aud"`
	} `json:"binding"`
	Keys map[string]keyVector `json:"keys"`
	Chains map[string][]string `json:"valid_chains"`
	Controls struct { DecreasingPrefix string `json:"decreasing_prefix"` } `json:"source_controls"`
	Malformed []struct {
		ID string `json:"id"`
		Expected string `json:"expected"`
		Wire string `json:"wire_b64u"`
		Setup string `json:"setup"`
		Binding struct {
			Endpoint string `json:"endpoint"`
			Audience string `json:"aud"`
		} `json:"binding"`
	} `json:"malformed"`
}

func fixture(t *testing.T) (vectors, rotation.Binding, rotation.Checkpoint, map[string][]byte) {
	t.Helper()
	data, err := os.ReadFile("../spec/fixtures/candidate/rotation-vectors.json")
	if err != nil { t.Fatal(err) }
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil { t.Fatal(err) }
	binding := rotation.Binding{Endpoint: v.Binding.Endpoint, Audience: v.Binding.Audience}
	keys := make(map[string][]byte)
	for _, key := range v.Keys {
		public, err := jack.DecodeBase64URLFixed(key.Public, 32)
		if err != nil { t.Fatal(err) }
		keys[key.KID] = public
	}
	anchor := rotation.Checkpoint{Hash: "-", KID: v.Keys["anchor"].KID}
	copy(anchor.PublicKey[:], keys[anchor.KID])
	return v, binding, anchor, keys
}

func wires(chain []string) [][]byte {
	out := make([][]byte, len(chain))
	for i, record := range chain { out[i] = []byte(record) }
	return out
}

func TestIndependentNegativeVectors(t *testing.T) {
	v, binding, anchor, keys := fixture(t)
	if len(v.Malformed) != 19 { t.Fatalf("negative vectors: %d", len(v.Malformed)) }
	for _, row := range v.Malformed {
		t.Run(row.ID, func(t *testing.T) {
			wire, err := jack.DecodeBase64URL(row.Wire)
			if err != nil { t.Fatal(err) }
			switch row.Setup {
			case "chain":
				_, err = rotation.VerifyChain([][]byte{wire}, binding, anchor, nil)
			case "after-r1":
				_, err = rotation.VerifyChain([][]byte{[]byte(v.Chains["overlapping"][0]), wire}, binding, anchor, nil)
			case "decreasing":
				_, err = rotation.VerifyChain([][]byte{[]byte(v.Controls.DecreasingPrefix), wire}, binding, anchor, nil)
			default:
				_, err = rotation.Parse(wire, rotation.Binding{Endpoint: row.Binding.Endpoint, Audience: row.Binding.Audience}, keys)
			}
			var rejection *rotation.Error
			if !errors.As(err, &rejection) || rejection.Code != row.Expected { t.Fatalf("got %v, want %s", err, row.Expected) }
		})
	}
}

func TestIndependentPositiveBytesAndSignatures(t *testing.T) {
	v, binding, anchor, _ := fixture(t)
	for name, chain := range v.Chains {
		t.Run(name, func(t *testing.T) {
			records, err := rotation.VerifyChain(wires(chain), binding, anchor, nil)
			if err != nil { t.Fatal(err) }
			if len(records) != 2 { t.Fatalf("records: %d", len(records)) }
			for i, record := range records {
				if record.Wire != chain[i] || record.Hash != jack.BodyHash([]byte(chain[i])) { t.Fatal("exact record bytes/hash changed") }
				lines := strings.Split(record.Wire, "\n")
				body := strings.Join(lines[:10], "\n")
				seed := sha256.Sum256([]byte("mcp-jack test key: candidate-server-next" + string(rune('1'+i))))
				key := ed25519.NewKeyFromSeed(seed[:])
				proof := ed25519.Sign(key, []byte(rotation.Domain+"/next-proof\n"+body))
				if jack.EncodeBase64URL(proof) != lines[10] { t.Fatal("Go signature differs from independent fixture") }
			}
			if rotation.SelectedOrdinal(records, 173799) != 0 { t.Fatal("early activation") }
			if name == "tie" {
				if rotation.SelectedOrdinal(records, 173800) != 2 || rotation.AssignmentValid(records, 1, 173800, 173800) { t.Fatal("equal-time ordinal rule") }
			} else {
				if !rotation.AssignmentValid(records, 1, 173800, 173800) { t.Fatal("inclusive lower bound") }
				if rotation.AssignmentValid(records, 1, 177399, 177400) { t.Fatal("old signer survived strict cutoff") }
			}
		})
	}
}
