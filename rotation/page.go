package rotation

import jack "github.com/PHPCraftdream/mcp-jack"

// PageFraming — metadata, не автоматическое продвижение ACKed cursor.
type PageFraming struct {
	ExtensionStart int
	Terminal ResultCursor
	Head ResultCursor
	Complete bool
}

func validCursor(cursor ResultCursor) bool {
	if cursor.Ordinal > MaxOrdinal {
		return false
	}
	if cursor.Ordinal == 0 {
		return cursor.Hash == "-"
	}
	_, err := jack.DecodeBase64URLFixed(cursor.Hash, 32)
	return err == nil
}

// Caller уже проверил outer/ClockGuard/schema и intrinsic record proofs.
// Здесь только page/cursor framing; authorizer/P/reuse/current/bridge и CAS —
// отдельные controller/chain gates. Нет ACK, persistence, retry или fetch.
func ValidatePageFraming(result DecodedResult, cursor ResultCursor, records []Record, acknowledgedHashes map[uint64]string) (PageFraming, error) {
	fail := func(code string) (PageFraming, error) { return PageFraming{}, invalid(code) }
	if !validCursor(cursor) || !validCursor(result.Head) {
		return fail("rotation_gap")
	}
	if len(records) != len(result.Records) || len(records) > MaxPageRecords {
		return fail("rotation_result_invalid")
	}
	if saved, exists := acknowledgedHashes[cursor.Ordinal]; exists && saved != cursor.Hash {
		return fail("rotation_conflict")
	}
	var previous ResultCursor
	present, extension := false, false
	start := len(records)
	for index, record := range records {
		if record.Wire != result.Records[index] || jack.BodyHash([]byte(record.Wire)) != record.Hash {
			return fail("rotation_record_invalid")
		}
		if record.Ordinal == 0 || record.Ordinal > MaxOrdinal {
			return fail("rotation_gap")
		}
		if present && (previous.Ordinal == MaxOrdinal || record.Ordinal != previous.Ordinal+1 || record.PreviousHash != previous.Hash) {
			return fail("rotation_gap")
		}
		if record.Ordinal <= cursor.Ordinal {
			if extension {
				return fail("rotation_gap")
			}
			saved, exists := acknowledgedHashes[record.Ordinal]
			if record.Ordinal == cursor.Ordinal {
				saved, exists = cursor.Hash, true
			}
			if !exists {
				return fail("rotation_gap")
			}
			if saved != record.Hash {
				return fail("rotation_conflict")
			}
		} else if !extension {
			if cursor.Ordinal == MaxOrdinal || record.Ordinal != cursor.Ordinal+1 || record.PreviousHash != cursor.Hash || (present && previous.Ordinal != cursor.Ordinal) {
				return fail("rotation_gap")
			}
			start, extension = index, true
		}
		previous, present = ResultCursor{Ordinal: record.Ordinal, Hash: record.Hash}, true
	}
	if !extension && present && previous.Ordinal != cursor.Ordinal {
		return fail("rotation_gap")
	}
	terminal := cursor
	if present {
		terminal = previous
	}
	if result.Complete {
		if result.Head != terminal {
			return fail("rotation_gap")
		}
	} else if len(records) == 0 || result.Head.Ordinal <= terminal.Ordinal {
		return fail("rotation_gap")
	}
	return PageFraming{ExtensionStart: start, Terminal: terminal, Head: result.Head, Complete: result.Complete}, nil
}
