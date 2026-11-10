package rotation_test

import (
	"errors"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/rotation"
)

func TestPageFramingRetainedPrefixExtensionNoopAndOwnedMetadata(t *testing.T) {
	vectors, binding, anchor, _ := fixture(t)
	records, err := rotation.VerifyChain(wires(vectors.Chains["overlapping"]), binding, anchor, nil)
	if err != nil || len(records) != 2 {
		t.Fatalf("valid independent records: %v", err)
	}
	zero := rotation.ResultCursor{Hash: "-"}
	one := rotation.ResultCursor{Ordinal: 1, Hash: records[0].Hash}
	two := rotation.ResultCursor{Ordinal: 2, Hash: records[1].Hash}
	known := map[uint64]string{1: one.Hash, 2: two.Hash}
	page := func(rows []rotation.Record, head rotation.ResultCursor, complete bool) rotation.DecodedResult {
		result := rotation.DecodedResult{Current: rotation.CurrentKey{KID: anchor.KID, PublicKey: anchor.PublicKey}, Head: head, Complete: complete}
		for _, row := range rows {
			result.Records = append(result.Records, row.Wire)
		}
		return result
	}
	for _, row := range []struct {
		cursor rotation.ResultCursor
		records []rotation.Record
		head rotation.ResultCursor
		complete bool
		start int
		terminal rotation.ResultCursor
	}{
		{zero, records, two, true, 0, two},
		{one, records, two, true, 1, two},
		{two, records[1:], two, true, 1, two},
		{zero, records[:1], two, false, 0, one},
		{one, records[:1], two, false, 1, one},
		{zero, nil, zero, true, 0, zero},
	} {
		framing, err := rotation.ValidatePageFraming(page(row.records, row.head, row.complete), row.cursor, row.records, known)
		if err != nil || framing.ExtensionStart != row.start || framing.Terminal != row.terminal || framing.Head != row.head || framing.Complete != row.complete {
			t.Fatalf("valid page framing: %+v %v", framing, err)
		}
		row.cursor.Hash = "caller mutation"
		if framing.Terminal != row.terminal {
			t.Fatal("returned framing aliased caller cursor")
		}
	}
}

func TestPageFramingRejectsGapsConflictsMixedSnapshotsAndOverflow(t *testing.T) {
	vectors, binding, anchor, keys := fixture(t)
	records, err := rotation.VerifyChain(wires(vectors.Chains["overlapping"]), binding, anchor, nil)
	if err != nil || len(records) != 2 {
		t.Fatalf("valid independent records: %v", err)
	}
	zero := rotation.ResultCursor{Hash: "-"}
	one := rotation.ResultCursor{Ordinal: 1, Hash: records[0].Hash}
	two := rotation.ResultCursor{Ordinal: 2, Hash: records[1].Hash}
	known := map[uint64]string{1: one.Hash, 2: two.Hash}
	page := func(rows []rotation.Record, head rotation.ResultCursor, complete bool) rotation.DecodedResult {
		result := rotation.DecodedResult{Current: rotation.CurrentKey{KID: anchor.KID, PublicKey: anchor.PublicKey}, Head: head, Complete: complete}
		for _, row := range rows {
			result.Records = append(result.Records, row.Wire)
		}
		return result
	}
	deny := func(result rotation.DecodedResult, cursor rotation.ResultCursor, parsed []rotation.Record, history map[uint64]string, code string) {
		t.Helper()
		_, err := rotation.ValidatePageFraming(result, cursor, parsed, history)
		var rejection *rotation.Error
		if !errors.As(err, &rejection) || rejection.Code != code {
			t.Fatalf("got %v want %s", err, code)
		}
	}
	deny(page(records[1:], two, true), zero, records[1:], known, "rotation_gap")
	deny(page(records[:1], one, true), two, records[:1], known, "rotation_gap")
	deny(page(records, one, true), zero, records, known, "rotation_gap")
	deny(page(records, two, false), zero, records, known, "rotation_gap")
	deny(page(nil, one, false), zero, nil, known, "rotation_gap")
	deny(page(nil, one, true), zero, nil, known, "rotation_gap")
	deny(page(records, two, true), two, records, map[uint64]string{2: two.Hash}, "rotation_gap")
	conflict, err := rotation.Parse([]byte(vectors.Controls.DecreasingPrefix), binding, keys)
	if err != nil || conflict.Hash == records[0].Hash {
		t.Fatalf("independently valid conflict fixture: %v", err)
	}
	deny(page([]rotation.Record{conflict}, rotation.ResultCursor{Ordinal: 1, Hash: conflict.Hash}, true), one, []rotation.Record{conflict}, known, "rotation_conflict")
	deny(page(records[:1], one, true), zero, records[1:], known, "rotation_record_invalid")
	forged := records[0]
	forged.Hash = records[1].Hash
	deny(page(records[:1], one, true), zero, []rotation.Record{forged}, known, "rotation_record_invalid")
	deny(page(nil, zero, true), zero, records[:1], known, "rotation_result_invalid")
	oversized := make([]rotation.Record, 17)
	for index := range oversized {
		oversized[index] = records[0]
	}
	deny(page(oversized, one, true), one, oversized, known, "rotation_result_invalid")
}
