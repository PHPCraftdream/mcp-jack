package rotation

import jack "github.com/PHPCraftdream/mcp-jack"

const MaxRetainedKeys = 1024 + 128 + 1

// Checkpoint должен быть получен независимо или из ранее подтверждённого snapshot.
type Checkpoint struct {
	Ordinal     uint64
	Hash        string
	KID         string
	PublicKey   [32]byte
	PublishedAt int64
}

// VerifyChain проверяет contiguous extension; retained включает публичную историю.
// Возвращаемые records не ссылаются на входные buffers.
func VerifyChain(wires [][]byte, binding Binding, checkpoint Checkpoint, retained map[string][]byte) ([]Record, error) {
	if len(wires) > MaxRetainedKeys || len(retained) > MaxRetainedKeys {
		return nil, invalid("capacity")
	}
	if checkpoint.Ordinal > MaxOrdinal || jack.ValidatePublicKey(checkpoint.PublicKey[:]) != nil || jack.KeyID(checkpoint.PublicKey[:]) != checkpoint.KID {
		return nil, invalid("anchor_key_id")
	}
	if checkpoint.Ordinal == 0 {
		if checkpoint.Hash != "-" {
			return nil, invalid("previous_hash")
		}
	} else if _, err := jack.DecodeBase64URLFixed(checkpoint.Hash, 32); err != nil {
		return nil, invalid("previous_hash")
	}
	if _, included := retained[checkpoint.KID]; !included && len(retained) == MaxRetainedKeys {
		return nil, invalid("capacity")
	}
	keys := make(map[string][]byte, len(retained)+1)
	for kid, public := range retained {
		if jack.ValidatePublicKey(public) != nil || jack.KeyID(public) != kid {
			return nil, invalid("anchor_key_id")
		}
		keys[kid] = append([]byte(nil), public...)
	}
	keys[checkpoint.KID] = append([]byte(nil), checkpoint.PublicKey[:]...)
	previous := checkpoint
	accepted := make([]Record, 0, len(wires))
	for _, wire := range wires {
		r, err := Parse(wire, binding, keys)
		if err != nil {
			return nil, err
		}
		if previous.Ordinal == MaxOrdinal || r.Ordinal != previous.Ordinal+1 {
			return nil, invalid("ordinal_sequence")
		}
		if r.PreviousHash != previous.Hash {
			return nil, invalid("previous_hash")
		}
		if r.OldKID != previous.KID {
			return nil, invalid("adjacency")
		}
		if r.PublishedAt < previous.PublishedAt {
			return nil, invalid("publication_order")
		}
		if _, exists := keys[r.NewKID]; exists {
			return nil, invalid("key_reuse")
		}
		if len(keys) >= MaxRetainedKeys {
			return nil, invalid("capacity")
		}
		keys[r.NewKID] = append([]byte(nil), r.PublicKey[:]...)
		accepted = append(accepted, r)
		previous = Checkpoint{Ordinal: r.Ordinal, Hash: r.Hash, KID: r.NewKID, PublicKey: r.PublicKey, PublishedAt: r.PublishedAt}
	}
	return accepted, nil
}

// SelectedOrdinal выбирает greatest ordinal; входная цепочка уже должна быть проверена.
func SelectedOrdinal(records []Record, now int64) uint64 {
	var selected uint64
	for _, r := range records {
		if r.ActivatesAt <= now && r.Ordinal > selected {
			selected = r.Ordinal
		}
	}
	return selected
}

// AssignmentValid проверяет ts и строгий final cutoff по известной цепочке.
func AssignmentValid(records []Record, ordinal uint64, ts, finalNow int64) bool {
	if ordinal > MaxOrdinal || ts < 0 || ts > MaxTimestamp || finalNow < 0 || finalNow > MaxTimestamp {
		return false
	}
	found := ordinal == 0
	for _, r := range records {
		if r.Ordinal == ordinal {
			found = true
			if ts < r.ActivatesAt {
				return false
			}
		}
		if ordinal < MaxOrdinal && r.Ordinal == ordinal+1 && (ts >= r.ActivatesAt || finalNow >= r.ActivatesAt) {
			return false
		}
	}
	return found
}
