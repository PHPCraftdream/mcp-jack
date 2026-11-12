package rotation

import (
	"encoding/json"
	"unicode/utf8"
)

const MaxSignerReferenceBytes = 1024

// SignerReference — opaque server-local handle, не private-key encoding.
type SignerReference struct {
	KID       string `json:"kid"`
	Reference string `json:"reference"`
}

// ServerSnapshot хранится только в protected server store, не в delivery payload.
type ServerSnapshot struct {
	FormatVersion    uint32
	Public           TrustSnapshot
	SignerReferences []SignerReference
}

func ValidateServerSnapshot(input ServerSnapshot, binding Binding, window int64, checkpoint Checkpoint) (ServerSnapshot, error) {
	refuse := func() (ServerSnapshot, error) { return ServerSnapshot{}, invalid("rotation_state_unavailable") }
	if input.FormatVersion != 1 {
		return refuse()
	}
	public, err := ValidateTrustSnapshot(input.Public, binding, window, checkpoint)
	if err != nil || len(input.SignerReferences) != len(public.Keys) {
		return refuse()
	}
	for index, entry := range input.SignerReferences {
		if entry.KID != public.Keys[index].KID || !utf8.ValidString(entry.Reference) || len(entry.Reference) == 0 || len(entry.Reference) > MaxSignerReferenceBytes {
			return refuse()
		}
	}
	return ServerSnapshot{FormatVersion: 1, Public: public, SignerReferences: append([]SignerReference{}, input.SignerReferences...)}, nil
}

// ValidateServerPublication проверяет один fixed-P переход, не durable authorization.
func ValidateServerPublication(expected, desired ServerSnapshot, binding Binding, window int64, checkpoint Checkpoint) (ServerSnapshot, error) {
	refuse := func() (ServerSnapshot, error) { return ServerSnapshot{}, invalid("rotation_state_unavailable") }
	previous, err := ValidateServerSnapshot(expected, binding, window, checkpoint)
	if err != nil {
		return refuse()
	}
	next, err := ValidateServerSnapshot(desired, binding, window, checkpoint)
	if err != nil {
		return refuse()
	}
	if previous.Public.Revision == MaxOrdinal || next.Public.Revision != previous.Public.Revision+1 ||
		len(next.Public.Records) != len(previous.Public.Records)+1 || previous.Public.Fenced || next.Public.Fenced ||
		!TrustClockCompatible(previous.Public, next.Public.Clock) {
		return refuse()
	}
	for index, wire := range previous.Public.Records {
		if next.Public.Records[index] != wire {
			return refuse()
		}
	}
	for index, reference := range previous.SignerReferences {
		if next.SignerReferences[index] != reference {
			return refuse()
		}
	}
	last := next.Public.Keys[len(next.Public.Keys)-1]
	if last.NotBefore-GraceSeconds != next.Public.Clock.HighWater {
		return refuse()
	}
	return next, nil
}

type serverSnapshotDocument struct {
	FormatVersion    uint32            `json:"format_version"`
	Public           json.RawMessage   `json:"public"`
	SignerReferences []SignerReference `json:"signer_refs"`
}

// EncodeServerSnapshot — private local format; caller не передаёт его клиентам.
func EncodeServerSnapshot(input ServerSnapshot, binding Binding, window int64, checkpoint Checkpoint) ([]byte, error) {
	snapshot, err := ValidateServerSnapshot(input, binding, window, checkpoint)
	if err != nil {
		return nil, err
	}
	public, err := EncodeTrustSnapshot(snapshot.Public, binding, window, checkpoint)
	if err != nil {
		return nil, invalid("rotation_state_unavailable")
	}
	encoded, err := json.Marshal(serverSnapshotDocument{FormatVersion: 1, Public: public, SignerReferences: snapshot.SignerReferences})
	if err != nil || len(encoded) > MaxTrustSnapshotBytes {
		return nil, invalid("rotation_state_unavailable")
	}
	return encoded, nil
}

// DecodeServerSnapshot сохраняет fences; strict parse не является serving readiness.
func DecodeServerSnapshot(data []byte, binding Binding, window int64, checkpoint Checkpoint) (ServerSnapshot, error) {
	refuse := func() (ServerSnapshot, error) { return ServerSnapshot{}, invalid("rotation_state_unavailable") }
	if len(data) == 0 || len(data) > MaxTrustSnapshotBytes {
		return refuse()
	}
	value, err := strictJSON(data)
	if err != nil {
		return refuse()
	}
	root, ok := fields(value, "format_version", "public", "signer_refs")
	if !ok || !canonicalTrustScalars(value, false) {
		return refuse()
	}
	refs, ok := root["signer_refs"].([]any)
	if !ok || len(refs) > MaxRetainedKeys {
		return refuse()
	}
	for _, entry := range refs {
		if _, ok := fields(entry, "kid", "reference"); !ok {
			return refuse()
		}
	}
	var document serverSnapshotDocument
	if json.Unmarshal(data, &document) != nil || document.FormatVersion != 1 {
		return refuse()
	}
	public, err := DecodeTrustSnapshot(document.Public, binding, window, checkpoint)
	if err != nil {
		return refuse()
	}
	return ValidateServerSnapshot(ServerSnapshot{FormatVersion: 1, Public: public, SignerReferences: document.SignerReferences}, binding, window, checkpoint)
}
