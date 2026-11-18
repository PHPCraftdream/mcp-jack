package rotation

import (
	"encoding/json"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// ClockTuple is a copied CAS dependency, not a standalone time authority.
type ClockTuple struct {
	Binding   Binding
	Window    int64
	HighWater int64
	Revision  uint64
	Unsafe    bool
}

// TrustKey holds only confirmed public metadata.
type TrustKey struct {
	Ordinal     uint64
	KID         string
	PublicKey   [32]byte
	NotBefore   int64
	KnownCutoff *int64
}

// TrustSnapshot is a whole value for a future transactional store, not an ACK.
// History starts from an independently provisioned checkpoint; there is no auto-compaction.
type TrustSnapshot struct {
	FormatVersion uint32
	Binding       Binding
	Window        int64
	Checkpoint    Checkpoint
	Head          ResultCursor
	Records       []string
	Keys          []TrustKey
	Revision      uint64
	Fenced        bool
	Clock         ClockTuple
}

func validClockTuple(clock ClockTuple, binding Binding, window int64) bool {
	return clock.Binding == binding && clock.Window == window &&
		clock.HighWater >= 0 && clock.HighWater <= MaxTimestamp && clock.Revision <= MaxOrdinal
}

// ValidateTrustSnapshot checks all redundant metadata and returns an owned copy.
// It does not open the store, read the clock, clear a fence or confirm persistence.
func ValidateTrustSnapshot(input TrustSnapshot, binding Binding, window int64, checkpoint Checkpoint) (TrustSnapshot, error) {
	refuse := func() (TrustSnapshot, error) { return TrustSnapshot{}, invalid("rotation_state_unknown") }
	if input.FormatVersion != 1 || !validBinding(binding) || input.Binding != binding ||
		window < 1 || window > 120 || input.Window != window || input.Checkpoint != checkpoint ||
		input.Revision == 0 || input.Revision > MaxOrdinal || !validClockTuple(input.Clock, binding, window) {
		return refuse()
	}
	if checkpoint.PublishedAt < 0 || checkpoint.PublishedAt > MaxTimestamp-GraceSeconds ||
		(checkpoint.Ordinal == 0 && checkpoint.PublishedAt != 0) ||
		len(input.Records) >= MaxRetainedKeys || len(input.Keys) != len(input.Records)+1 {
		return refuse()
	}
	wires := make([][]byte, len(input.Records))
	for index, wire := range input.Records {
		if len(wire) == 0 || len(wire) > MaxRecordBytes {
			return refuse()
		}
		wires[index] = []byte(wire)
	}
	records, err := VerifyChain(wires, binding, checkpoint, nil)
	if err != nil {
		return refuse()
	}
	head := ResultCursor{Ordinal: checkpoint.Ordinal, Hash: checkpoint.Hash}
	if len(records) != 0 {
		last := records[len(records)-1]
		head = ResultCursor{Ordinal: last.Ordinal, Hash: last.Hash}
	}
	if input.Head != head {
		return refuse()
	}
	keys := make([]TrustKey, len(records)+1)
	keys[0] = TrustKey{Ordinal: checkpoint.Ordinal, KID: checkpoint.KID, PublicKey: checkpoint.PublicKey}
	if checkpoint.Ordinal != 0 {
		keys[0].NotBefore = checkpoint.PublishedAt + GraceSeconds
	}
	for index, record := range records {
		cutoff := record.ActivatesAt
		keys[index].KnownCutoff = &cutoff
		keys[index+1] = TrustKey{Ordinal: record.Ordinal, KID: record.NewKID, PublicKey: record.PublicKey, NotBefore: record.ActivatesAt}
	}
	pending, retired := 0, 0
	for index, expected := range keys {
		actual := input.Keys[index]
		if actual.Ordinal != expected.Ordinal || actual.KID != expected.KID || actual.PublicKey != expected.PublicKey || actual.NotBefore != expected.NotBefore {
			return refuse()
		}
		if (actual.KnownCutoff == nil) != (expected.KnownCutoff == nil) ||
			(actual.KnownCutoff != nil && *actual.KnownCutoff != *expected.KnownCutoff) {
			return refuse()
		}
		if expected.NotBefore > input.Clock.HighWater {
			pending++
		} else if expected.KnownCutoff != nil && *expected.KnownCutoff <= input.Clock.HighWater {
			retired++
		}
	}
	if pending > 128 || retired > 1024 {
		return refuse()
	}
	output := input
	if input.Records != nil {
		output.Records = append([]string{}, input.Records...)
	}
	output.Keys = keys
	return output, nil
}

// TrustClockCompatible requires a validated snapshot; this is a tuple check, not readiness/ACK.
func TrustClockCompatible(snapshot TrustSnapshot, clock ClockTuple) bool {
	return snapshot.FormatVersion == 1 && !snapshot.Fenced && !snapshot.Clock.Unsafe && !clock.Unsafe &&
		validClockTuple(snapshot.Clock, snapshot.Binding, snapshot.Window) &&
		validClockTuple(clock, snapshot.Binding, snapshot.Window) &&
		validBinding(snapshot.Binding) && snapshot.Window >= 1 && snapshot.Window <= 120 &&
		snapshot.Clock.HighWater <= clock.HighWater && snapshot.Clock.Revision <= clock.Revision
}

const MaxTrustSnapshotBytes = 16 << 20

type trustBindingDocument struct {
	Endpoint string `json:"endpoint"`
	Audience string `json:"aud"`
}

type trustCheckpointDocument struct {
	Ordinal     uint64 `json:"ordinal"`
	Hash        string `json:"hash"`
	KID         string `json:"kid"`
	PublicKey   string `json:"public_key"`
	PublishedAt int64  `json:"published_at"`
}

type trustHeadDocument struct {
	Ordinal uint64 `json:"ordinal"`
	Hash    string `json:"hash"`
}

type trustKeyDocument struct {
	Ordinal     uint64 `json:"ordinal"`
	KID         string `json:"kid"`
	PublicKey   string `json:"public_key"`
	NotBefore   int64  `json:"not_before"`
	KnownCutoff *int64 `json:"known_cutoff"`
}

type trustClockDocument struct {
	Binding   trustBindingDocument `json:"binding"`
	Window    int64                `json:"window"`
	HighWater int64                `json:"high_water"`
	Revision  uint64               `json:"clock_revision"`
	Unsafe    bool                 `json:"unsafe"`
}

type trustDocument struct {
	FormatVersion uint32                  `json:"format_version"`
	Binding       trustBindingDocument    `json:"binding"`
	Window        int64                   `json:"window"`
	Checkpoint    trustCheckpointDocument `json:"checkpoint"`
	Head          trustHeadDocument       `json:"head"`
	Records       []string                `json:"records"`
	Keys          []trustKeyDocument      `json:"keys"`
	Revision      uint64                  `json:"trust_revision"`
	Fenced        bool                    `json:"fenced"`
	Clock         trustClockDocument      `json:"clock"`
}

func canonicalTrustScalars(value any, nullable bool) bool {
	switch node := value.(type) {
	case nil:
		return nullable
	case json.Number:
		_, ok := decimal(node.String(), MaxOrdinal)
		return ok
	case map[string]any:
		for key, child := range node {
			if !canonicalTrustScalars(child, key == "known_cutoff") {
				return false
			}
		}
	case []any:
		for _, child := range node {
			if !canonicalTrustScalars(child, false) {
				return false
			}
		}
	case string, bool:
	default:
		return false
	}
	return true
}

func trustDocumentShape(value any) bool {
	root, ok := fields(value, "format_version", "binding", "window", "checkpoint", "head", "records", "keys", "trust_revision", "fenced", "clock")
	if !ok || !canonicalTrustScalars(value, false) {
		return false
	}
	if _, ok := fields(root["binding"], "endpoint", "aud"); !ok {
		return false
	}
	if _, ok := fields(root["checkpoint"], "ordinal", "hash", "kid", "public_key", "published_at"); !ok {
		return false
	}
	if _, ok := fields(root["head"], "ordinal", "hash"); !ok {
		return false
	}
	clock, ok := fields(root["clock"], "binding", "window", "high_water", "clock_revision", "unsafe")
	if !ok {
		return false
	}
	if _, ok := fields(clock["binding"], "endpoint", "aud"); !ok {
		return false
	}
	keys, ok := root["keys"].([]any)
	if !ok || len(keys) > MaxRetainedKeys {
		return false
	}
	for _, key := range keys {
		if _, ok := fields(key, "ordinal", "kid", "public_key", "not_before", "known_cutoff"); !ok {
			return false
		}
	}
	records, ok := root["records"].([]any)
	return ok && len(records) < MaxRetainedKeys
}

// DecodeTrustSnapshot is a strict local state decoder, not startup readiness or ACK.
func DecodeTrustSnapshot(data []byte, binding Binding, window int64, checkpoint Checkpoint) (TrustSnapshot, error) {
	refuse := func() (TrustSnapshot, error) { return TrustSnapshot{}, invalid("rotation_state_unknown") }
	if len(data) == 0 || len(data) > MaxTrustSnapshotBytes {
		return refuse()
	}
	value, err := strictJSON(data)
	if err != nil || !trustDocumentShape(value) {
		return refuse()
	}
	var document trustDocument
	if json.Unmarshal(data, &document) != nil {
		return refuse()
	}
	public, err := jack.DecodeBase64URLFixed(document.Checkpoint.PublicKey, 32)
	if err != nil {
		return refuse()
	}
	loaded := TrustSnapshot{
		FormatVersion: document.FormatVersion, Binding: Binding{Endpoint: document.Binding.Endpoint, Audience: document.Binding.Audience}, Window: document.Window,
		Checkpoint: Checkpoint{Ordinal: document.Checkpoint.Ordinal, Hash: document.Checkpoint.Hash, KID: document.Checkpoint.KID, PublishedAt: document.Checkpoint.PublishedAt},
		Head:       ResultCursor{Ordinal: document.Head.Ordinal, Hash: document.Head.Hash}, Records: document.Records, Keys: make([]TrustKey, len(document.Keys)),
		Revision: document.Revision, Fenced: document.Fenced,
		Clock: ClockTuple{Binding: Binding{Endpoint: document.Clock.Binding.Endpoint, Audience: document.Clock.Binding.Audience}, Window: document.Clock.Window, HighWater: document.Clock.HighWater, Revision: document.Clock.Revision, Unsafe: document.Clock.Unsafe},
	}
	copy(loaded.Checkpoint.PublicKey[:], public)
	for index, key := range document.Keys {
		decoded, err := jack.DecodeBase64URLFixed(key.PublicKey, 32)
		if err != nil {
			return refuse()
		}
		loaded.Keys[index] = TrustKey{Ordinal: key.Ordinal, KID: key.KID, NotBefore: key.NotBefore, KnownCutoff: key.KnownCutoff}
		copy(loaded.Keys[index].PublicKey[:], decoded)
	}
	return ValidateTrustSnapshot(loaded, binding, window, checkpoint)
}

// EncodeTrustSnapshot writes only validated public state, without signer/private material.
func EncodeTrustSnapshot(input TrustSnapshot, binding Binding, window int64, checkpoint Checkpoint) ([]byte, error) {
	snapshot, err := ValidateTrustSnapshot(input, binding, window, checkpoint)
	if err != nil {
		return nil, err
	}
	document := trustDocument{
		FormatVersion: snapshot.FormatVersion, Binding: trustBindingDocument{Endpoint: snapshot.Binding.Endpoint, Audience: snapshot.Binding.Audience}, Window: snapshot.Window,
		Checkpoint: trustCheckpointDocument{Ordinal: snapshot.Checkpoint.Ordinal, Hash: snapshot.Checkpoint.Hash, KID: snapshot.Checkpoint.KID, PublicKey: jack.EncodeBase64URL(snapshot.Checkpoint.PublicKey[:]), PublishedAt: snapshot.Checkpoint.PublishedAt},
		Head:       trustHeadDocument{Ordinal: snapshot.Head.Ordinal, Hash: snapshot.Head.Hash}, Records: append([]string{}, snapshot.Records...), Keys: make([]trustKeyDocument, len(snapshot.Keys)),
		Revision: snapshot.Revision, Fenced: snapshot.Fenced,
		Clock: trustClockDocument{Binding: trustBindingDocument{Endpoint: snapshot.Clock.Binding.Endpoint, Audience: snapshot.Clock.Binding.Audience}, Window: snapshot.Clock.Window, HighWater: snapshot.Clock.HighWater, Revision: snapshot.Clock.Revision, Unsafe: snapshot.Clock.Unsafe},
	}
	for index, key := range snapshot.Keys {
		document.Keys[index] = trustKeyDocument{Ordinal: key.Ordinal, KID: key.KID, PublicKey: jack.EncodeBase64URL(key.PublicKey[:]), NotBefore: key.NotBefore, KnownCutoff: key.KnownCutoff}
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > MaxTrustSnapshotBytes {
		return nil, invalid("rotation_state_unknown")
	}
	return encoded, nil
}
