package rotation

import (
	"encoding/json"

	jack "github.com/PHPCraftdream/mcp-jack"
)

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

// DecodeTrustSnapshot — strict local state decoder, не startup readiness или ACK.
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

// EncodeTrustSnapshot пишет только validated public state, без signer/private material.
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
