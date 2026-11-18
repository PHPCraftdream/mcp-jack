package rotation_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// fuzzFixture reads the committed candidate vectors the way the unit tests do,
// bound to testing.F so it can seed corpora without a testing.T.
func fuzzFixture(f *testing.F) (vectors, rotation.Binding, rotation.Checkpoint, map[string][]byte) {
	data, err := os.ReadFile("../../../spec/fixtures/candidate/rotation-vectors.json")
	if err != nil {
		f.Fatalf("read rotation vectors: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		f.Fatalf("decode rotation vectors: %v", err)
	}
	binding := rotation.Binding{Endpoint: v.Binding.Endpoint, Audience: v.Binding.Audience}
	keys := make(map[string][]byte)
	for _, key := range v.Keys {
		public, err := jack.DecodeBase64URLFixed(key.Public, 32)
		if err != nil {
			f.Fatalf("fixture key %s: %v", key.KID, err)
		}
		keys[key.KID] = public
	}
	anchor, known := v.Keys["anchor"]
	if !known {
		f.Fatalf("rotation vectors have no anchor key")
	}
	checkpoint := rotation.Checkpoint{Hash: "-", KID: anchor.KID}
	copy(checkpoint.PublicKey[:], keys[anchor.KID])
	return v, binding, checkpoint, keys
}

// fuzzChainRecords verifies one committed chain so snapshot seeds start from
// authenticated values only.
func fuzzChainRecords(f *testing.F, binding rotation.Binding, checkpoint rotation.Checkpoint, chain []string) []rotation.Record {
	records, err := rotation.VerifyChain(wires(chain), binding, checkpoint, nil)
	if err != nil {
		f.Fatalf("fixture chain invalid: %v", err)
	}
	return records
}

// FuzzParseRecord checks the intrinsic record codec: no panic, rejections are
// *rotation.Error values with no partial record, and accepted wires carry the
// exact bytes, the activation contract and a re-parse-stable value.
func FuzzParseRecord(f *testing.F) {
	v, binding, _, keys := fuzzFixture(f)
	validWires := make(map[string]bool)
	for _, chain := range v.Chains {
		for _, wire := range chain {
			validWires[wire] = true
			f.Add([]byte(wire))
		}
	}
	for _, row := range v.Malformed {
		wire, err := jack.DecodeBase64URL(row.Wire)
		if err != nil {
			f.Fatalf("malformed vector %s: %v", row.ID, err)
		}
		f.Add(wire)
	}
	f.Add([]byte{})
	f.Add([]byte(rotation.Domain + "\ntruncated"))

	f.Fuzz(func(t *testing.T, wire []byte) {
		record, err := rotation.Parse(wire, binding, keys)
		// Both directions must stay observable: an empty wire cannot parse
		// and every committed chain record must keep parsing.
		if len(wire) == 0 && err == nil {
			t.Fatalf("rejection witness: empty record accepted")
		}
		if validWires[string(wire)] && err != nil {
			t.Fatalf("acceptance witness: committed chain record rejected: %v", err)
		}
		if err != nil {
			var rejection *rotation.Error
			if !errors.As(err, &rejection) {
				t.Fatalf("error %v is not a *rotation.Error", err)
			}
			if record != (rotation.Record{}) {
				t.Fatalf("rejected wire returned a partial record")
			}
			return
		}
		if record.Wire != string(wire) || record.Hash != jack.BodyHash(wire) {
			t.Fatalf("accepted record changed the exact wire bytes or hash")
		}
		if jack.KeyID(record.PublicKey[:]) != record.NewKID {
			t.Fatalf("accepted record key does not hash to its key id")
		}
		if record.Ordinal == 0 || record.ActivatesAt != record.PublishedAt+rotation.GraceSeconds {
			t.Fatalf("accepted record violates the activation contract")
		}
		again, err := rotation.Parse([]byte(record.Wire), binding, keys)
		if err != nil || again != record {
			t.Fatalf("re-parse of the accepted record failed: %v", err)
		}
	})
}

// FuzzVerifyChain checks the contiguous-extension verifier over fuzzed wire
// pairs: no panic, only *rotation.Error rejections with no records, and
// accepted pairs replay to the same authenticated records.
func FuzzVerifyChain(f *testing.F) {
	v, binding, checkpoint, _ := fuzzFixture(f)
	over, tie := v.Chains["overlapping"], v.Chains["tie"]
	if len(over) != 2 || len(tie) != 2 {
		f.Fatalf("fixture chains invalid")
	}
	overSeed, tieSeed := [][]byte{[]byte(over[0]), []byte(over[1])}, [][]byte{[]byte(tie[0]), []byte(tie[1])}
	f.Add(overSeed[0], overSeed[1])
	f.Add(tieSeed[0], tieSeed[1])
	f.Add(overSeed[0], overSeed[0])
	f.Add([]byte{}, []byte{})
	f.Add([]byte("mcp-jack/server-key-rotation/min1\nx"), []byte{})

	f.Fuzz(func(t *testing.T, first, second []byte) {
		records, err := rotation.VerifyChain([][]byte{first, second}, binding, checkpoint, nil)
		// Witnesses: the committed overlapping chain must keep verifying and
		// a duplicated record must break the ordinal sequence.
		if bytes.Equal(first, overSeed[0]) && bytes.Equal(second, overSeed[1]) && err != nil {
			t.Fatalf("acceptance witness: committed overlapping chain rejected: %v", err)
		}
		if bytes.Equal(first, overSeed[0]) && bytes.Equal(second, overSeed[0]) && err == nil {
			t.Fatalf("rejection witness: duplicated record accepted")
		}
		if err != nil {
			var rejection *rotation.Error
			if !errors.As(err, &rejection) {
				t.Fatalf("error %v is not a *rotation.Error", err)
			}
			if records != nil {
				t.Fatalf("rejected chain returned records")
			}
			return
		}
		if len(records) != 2 {
			t.Fatalf("accepted chain returned %d records", len(records))
		}
		if records[0].Wire != string(first) || records[1].Wire != string(second) {
			t.Fatalf("verified chain changed the exact record bytes")
		}
		if records[1].Ordinal != records[0].Ordinal+1 || records[1].PreviousHash != records[0].Hash || records[1].OldKID != records[0].NewKID {
			t.Fatalf("accepted chain is not contiguous")
		}
		replay, err := rotation.VerifyChain(wires([]string{records[0].Wire, records[1].Wire}), binding, checkpoint, nil)
		if err != nil || !reflect.DeepEqual(replay, records) {
			t.Fatalf("re-verify of the accepted chain failed: %v", err)
		}
	})
}

// fuzzResultEnvelope builds the JSON-RPC result envelope the way the unit
// tests do; testing.F replaces the testing.T failure path.
func fuzzResultEnvelope(f *testing.F, payload, mirror []byte, id json.RawMessage) []byte {
	if mirror == nil {
		mirror = payload
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id,
		"result": map[string]any{
			"content":           []any{map[string]any{"type": "text", "text": string(mirror)}},
			"structuredContent": json.RawMessage(payload), "isError": false,
		},
	})
	if err != nil {
		f.Fatalf("marshal result envelope: %v", err)
	}
	return body
}

// FuzzDecodeResult checks the jack.server.key result decoder: no panic, only
// *rotation.Error refusals with no partial value, and accepted bodies decode
// idempotently into a key-consistent page. The decoder has no encoder, so the
// canonical-form invariant is the strict idempotent re-decode. Numeric id
// lexemes are deliberately not pinned: id canonicalization is changing in a
// sibling change, so every seed uses canonical ids only.
func FuzzDecodeResult(f *testing.F) {
	v, _, _, _ := fuzzFixture(f)
	anchor, known := v.Keys["anchor"]
	if !known {
		f.Fatalf("rotation vectors have no anchor key")
	}
	payload := []byte(`{"current":{"kid":"` + anchor.KID + `","public_key":"` + anchor.Public + `"},"records":[],"head":{"ordinal":0,"hash":"-"},"complete":true}`)
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		f.Fatalf("seed payload malformed: %v", err)
	}
	pretty, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		f.Fatalf("marshal seed mirror: %v", err)
	}
	other := bytes.Replace(payload, []byte(`"complete":true`), []byte(`"complete":false`), 1)
	if bytes.Equal(other, payload) {
		f.Fatalf("negative mirror token missing")
	}
	numericID, stringID, otherID := json.RawMessage(`7`), json.RawMessage(`"request-😀"`), json.RawMessage(`"other"`)
	env := fuzzResultEnvelope(f, payload, nil, numericID)
	envPretty := fuzzResultEnvelope(f, payload, pretty, numericID)
	envString := fuzzResultEnvelope(f, payload, nil, stringID)
	envMismatch := fuzzResultEnvelope(f, payload, other, numericID)
	f.Add(env, []byte(numericID))
	f.Add(envPretty, []byte(numericID))
	f.Add(envString, []byte(stringID))
	f.Add(envMismatch, []byte(numericID))
	f.Add(env, []byte(otherID))
	f.Add([]byte{0xff}, []byte(numericID))
	f.Add([]byte{}, []byte(numericID))

	f.Fuzz(func(t *testing.T, body, expectedID []byte) {
		decoded, err := rotation.DecodeResult(body, json.RawMessage(expectedID))
		// Witnesses: canonical numeric and string envelopes must decode; a
		// mirror that differs from structuredContent and an id mismatch must
		// fail. No witness pins non-canonical numeric id lexemes.
		if bytes.Equal(body, env) && bytes.Equal(expectedID, []byte(numericID)) && err != nil {
			t.Fatalf("acceptance witness: canonical result envelope rejected: %v", err)
		}
		if bytes.Equal(body, envString) && bytes.Equal(expectedID, []byte(stringID)) && err != nil {
			t.Fatalf("acceptance witness: string-id result envelope rejected: %v", err)
		}
		if bytes.Equal(body, envMismatch) && bytes.Equal(expectedID, []byte(numericID)) && err == nil {
			t.Fatalf("rejection witness: mirror that differs from structuredContent accepted")
		}
		if bytes.Equal(body, env) && bytes.Equal(expectedID, []byte(otherID)) && err == nil {
			t.Fatalf("rejection witness: result id mismatch accepted")
		}
		if bytes.Equal(body, []byte{0xff}) && err == nil {
			t.Fatalf("rejection witness: invalid UTF-8 body accepted")
		}
		if err != nil {
			var rejection *rotation.Error
			if !errors.As(err, &rejection) {
				t.Fatalf("error %v is not a *rotation.Error", err)
			}
			if !reflect.DeepEqual(decoded, rotation.DecodedResult{}) {
				t.Fatalf("rejected body returned a partial result")
			}
			return
		}
		if jack.KeyID(decoded.Current.PublicKey[:]) != decoded.Current.KID {
			t.Fatalf("accepted current key does not hash to its key id")
		}
		if decoded.Head.Ordinal > rotation.MaxOrdinal {
			t.Fatalf("accepted head ordinal beyond the 53-bit domain")
		}
		if decoded.Head.Ordinal == 0 && decoded.Head.Hash != "-" {
			t.Fatalf("accepted zero head with a non-sentinel hash")
		}
		if decoded.Head.Ordinal > 0 {
			if _, err := jack.DecodeBase64URLFixed(decoded.Head.Hash, 32); err != nil {
				t.Fatalf("accepted head hash does not decode to 32 bytes: %v", err)
			}
		}
		if len(decoded.Records) > rotation.MaxPageRecords {
			t.Fatalf("accepted page beyond the record cap")
		}
		again, err := rotation.DecodeResult(body, json.RawMessage(expectedID))
		if err != nil || !reflect.DeepEqual(again, decoded) {
			t.Fatalf("idempotent re-decode of the accepted body failed: %v", err)
		}
	})
}

// FuzzDecodeServerKeyArguments checks the exact-schema arguments decoder: no
// panic, only *rotation.Error refusals with a zero cursor, and accepted
// cursors are canonical: re-encoding the decoded value decodes identically.
func FuzzDecodeServerKeyArguments(f *testing.F) {
	hash := strings.Repeat("A", 43)
	valid := []byte(`{"after_ordinal":0,"after_hash":"-"}`)
	spaced := []byte(` { "after_hash":"-", "after_ordinal":0 } `)
	fractional := []byte(`{"after_ordinal":0.0,"after_hash":"-"}`)
	f.Add(valid)
	f.Add(spaced)
	f.Add([]byte(`{"after_ordinal":1,"after_hash":"` + hash + `"}`))
	f.Add([]byte(`{"after_ordinal":9007199254740991,"after_hash":"` + hash + `"}`))
	f.Add([]byte{})
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"after_ordinal":0,"after_ordinal":0,"after_hash":"-"}`))
	f.Add(fractional)
	f.Add([]byte(`{"after_ordinal":-1,"after_hash":"-"}`))
	f.Add([]byte(`{"after_ordinal":18446744073709551616,"after_hash":"` + hash + `"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		cursor, err := rotation.DecodeServerKeyArguments(data)
		// Witnesses: the canonical zero cursor must decode and a fractional
		// ordinal must fail, so a last-wins or float-accepting decoder fails
		// the campaign.
		if bytes.Equal(data, valid) && err != nil {
			t.Fatalf("acceptance witness: canonical zero cursor rejected: %v", err)
		}
		if bytes.Equal(data, fractional) && err == nil {
			t.Fatalf("rejection witness: fractional ordinal accepted")
		}
		if err != nil {
			var refusal *rotation.Error
			if !errors.As(err, &refusal) {
				t.Fatalf("error %v is not a *rotation.Error", err)
			}
			if cursor != (rotation.ResultCursor{}) {
				t.Fatalf("rejected arguments returned a partial cursor")
			}
			return
		}
		if cursor.Ordinal > rotation.MaxOrdinal {
			t.Fatalf("accepted ordinal beyond the 53-bit domain")
		}
		if cursor.Ordinal == 0 && cursor.Hash != "-" {
			t.Fatalf("accepted zero cursor with a non-sentinel hash")
		}
		if cursor.Ordinal > 0 {
			if _, err := jack.DecodeBase64URLFixed(cursor.Hash, 32); err != nil {
				t.Fatalf("accepted cursor hash does not decode to 32 bytes: %v", err)
			}
		}
		canonical := []byte(`{"after_ordinal":` + strconv.FormatUint(cursor.Ordinal, 10) + `,"after_hash":"` + cursor.Hash + `"}`)
		again, err := rotation.DecodeServerKeyArguments(canonical)
		if err != nil || again != cursor {
			t.Fatalf("canonical re-encode of the accepted cursor failed: %v", err)
		}
	})
}

// FuzzDecodeServerSnapshot checks the protected local-state decoder: no
// panic, only *rotation.Error refusals with no partial value, strict
// duplicate-key rejection, and accepted snapshots re-encode canonically and
// decode to the same value with intact signer references.
func FuzzDecodeServerSnapshot(f *testing.F) {
	v, binding, checkpoint, _ := fuzzFixture(f)
	records := fuzzChainRecords(f, binding, checkpoint, v.Chains["overlapping"])
	public := trustFromRecords(binding, checkpoint, records)
	references := make([]rotation.SignerReference, len(public.Keys))
	for index, key := range public.Keys {
		references[index] = rotation.SignerReference{KID: key.KID, Reference: "opaque-provider/" + key.KID}
	}
	snapshot := rotation.ServerSnapshot{FormatVersion: 1, Public: public, SignerReferences: references}
	encoded, err := rotation.EncodeServerSnapshot(snapshot, binding, 30, checkpoint)
	if err != nil {
		f.Fatalf("encode fixture server snapshot: %v", err)
	}
	fenced := snapshot
	fenced.Public.Fenced = true
	fenced.Public.Clock.Unsafe = true
	fencedEncoded, err := rotation.EncodeServerSnapshot(fenced, binding, 30, checkpoint)
	if err != nil {
		f.Fatalf("encode fenced server snapshot: %v", err)
	}
	duplicate := bytes.Replace(encoded, []byte(`"format_version":1`), []byte(`"format_version":1,"format_version":1`), 1)
	if bytes.Equal(duplicate, encoded) {
		f.Fatalf("duplicate-key negative token missing")
	}
	f.Add(encoded)
	f.Add(fencedEncoded)
	f.Add([]byte{})
	f.Add([]byte(`{}`))
	f.Add(encoded[:len(encoded)/2])
	f.Add(duplicate)
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		loaded, err := rotation.DecodeServerSnapshot(data, binding, 30, checkpoint)
		if bytes.Equal(data, encoded) && err != nil {
			t.Fatalf("acceptance witness: canonical server snapshot rejected: %v", err)
		}
		if bytes.Equal(data, duplicate) && err == nil {
			t.Fatalf("rejection witness: duplicate format_version accepted")
		}
		if err != nil {
			var refusal *rotation.Error
			if !errors.As(err, &refusal) {
				t.Fatalf("error %v is not a *rotation.Error", err)
			}
			if !reflect.DeepEqual(loaded, rotation.ServerSnapshot{}) {
				t.Fatalf("rejected server snapshot returned a partial value")
			}
			return
		}
		canonical, err := rotation.EncodeServerSnapshot(loaded, binding, 30, checkpoint)
		if err != nil {
			t.Fatalf("accepted server snapshot does not re-encode: %v", err)
		}
		again, err := rotation.DecodeServerSnapshot(canonical, binding, 30, checkpoint)
		if err != nil || !reflect.DeepEqual(again, loaded) {
			t.Fatalf("re-decode of the re-encoded server snapshot failed: %v", err)
		}
		for index, key := range loaded.Public.Keys {
			if loaded.SignerReferences[index].KID != key.KID || len(loaded.SignerReferences[index].Reference) == 0 {
				t.Fatalf("accepted server snapshot broke a signer reference")
			}
		}
	})
}

// FuzzDecodeTrustSnapshot checks the public local-state decoder the same way:
// no panic, only *rotation.Error refusals with no partial value, strict
// trailing-data rejection, and accepted snapshots re-encode canonically and
// decode to the same value with intact key history.
func FuzzDecodeTrustSnapshot(f *testing.F) {
	v, binding, checkpoint, _ := fuzzFixture(f)
	records := fuzzChainRecords(f, binding, checkpoint, v.Chains["overlapping"])
	snapshot := trustFromRecords(binding, checkpoint, records)
	encoded, err := rotation.EncodeTrustSnapshot(snapshot, binding, 30, checkpoint)
	if err != nil {
		f.Fatalf("encode fixture trust snapshot: %v", err)
	}
	anchorEncoded, err := rotation.EncodeTrustSnapshot(trustFromRecords(binding, checkpoint, nil), binding, 30, checkpoint)
	if err != nil {
		f.Fatalf("encode anchor-only snapshot: %v", err)
	}
	fenced := snapshot
	fenced.Fenced = true
	fenced.Clock.Unsafe = true
	fencedEncoded, err := rotation.EncodeTrustSnapshot(fenced, binding, 30, checkpoint)
	if err != nil {
		f.Fatalf("encode fenced trust snapshot: %v", err)
	}
	var reordered map[string]any
	if err := json.Unmarshal(encoded, &reordered); err != nil {
		f.Fatalf("fixture snapshot malformed: %v", err)
	}
	alternative, err := json.MarshalIndent(reordered, "", "  ")
	if err != nil {
		f.Fatalf("marshal alternative layout: %v", err)
	}
	trailing := append(append([]byte{}, encoded...), []byte(`{}`)...)
	f.Add(encoded)
	f.Add(anchorEncoded)
	f.Add(fencedEncoded)
	f.Add(alternative)
	f.Add([]byte{})
	f.Add([]byte(`{}`))
	f.Add(encoded[:len(encoded)/2])
	f.Add(trailing)
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		loaded, err := rotation.DecodeTrustSnapshot(data, binding, 30, checkpoint)
		// Witnesses: canonical and fenced snapshots must decode; trailing
		// documents must fail the strict parser.
		if bytes.Equal(data, encoded) && err != nil {
			t.Fatalf("acceptance witness: canonical trust snapshot rejected: %v", err)
		}
		if bytes.Equal(data, fencedEncoded) && err != nil {
			t.Fatalf("acceptance witness: fenced trust snapshot rejected: %v", err)
		}
		if bytes.Equal(data, trailing) && err == nil {
			t.Fatalf("rejection witness: trailing document accepted")
		}
		if err != nil {
			var refusal *rotation.Error
			if !errors.As(err, &refusal) {
				t.Fatalf("error %v is not a *rotation.Error", err)
			}
			if !reflect.DeepEqual(loaded, rotation.TrustSnapshot{}) {
				t.Fatalf("rejected snapshot returned a partial value")
			}
			return
		}
		if len(loaded.Keys) != len(loaded.Records)+1 {
			t.Fatalf("accepted snapshot key history inconsistent")
		}
		canonical, err := rotation.EncodeTrustSnapshot(loaded, binding, 30, checkpoint)
		if err != nil {
			t.Fatalf("accepted trust snapshot does not re-encode: %v", err)
		}
		again, err := rotation.DecodeTrustSnapshot(canonical, binding, 30, checkpoint)
		if err != nil || !reflect.DeepEqual(again, loaded) {
			t.Fatalf("re-decode of the re-encoded trust snapshot failed: %v", err)
		}
	})
}
