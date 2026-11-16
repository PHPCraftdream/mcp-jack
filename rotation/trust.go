package rotation

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
