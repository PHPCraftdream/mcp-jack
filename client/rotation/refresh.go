package rotationclient

import (
	"crypto/sha256"
	"encoding/json"
	"errors"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// RefreshResult отделяет declared page head от локального ACKed terminal.
type RefreshResult struct {
	Head      rotation.ResultCursor
	Terminal  rotation.ResultCursor
	Complete  bool
	Committed bool
	Revision  uint64
}

func recordError(err error) error {
	var parsed *rotation.Error
	if errors.As(err, &parsed) {
		switch parsed.Code {
		case "unknown_authorizer", "adjacency", "previous_hash", "ordinal_sequence", "publication_order":
			return localError("rotation_gap")
		}
	}
	return localError("rotation_record_invalid")
}

func pageRecords(snapshot rotation.TrustSnapshot, result rotation.DecodedResult) ([]rotation.Record, map[uint64]string, error) {
	authorizers := make(map[string][]byte, len(snapshot.Keys))
	for _, key := range snapshot.Keys {
		authorizers[key.KID] = append([]byte(nil), key.PublicKey[:]...)
	}
	hashes := map[uint64]string{snapshot.Checkpoint.Ordinal: snapshot.Checkpoint.Hash}
	for index, wire := range snapshot.Records {
		digest := sha256.Sum256([]byte(wire))
		hashes[snapshot.Checkpoint.Ordinal+uint64(index)+1] = jack.EncodeBase64URL(digest[:])
	}
	records := make([]rotation.Record, 0, len(result.Records))
	for _, wire := range result.Records {
		record, err := rotation.Parse([]byte(wire), snapshot.Binding, authorizers)
		if err != nil {
			return nil, nil, recordError(err)
		}
		records = append(records, record)
		authorizers[record.NewKID] = append([]byte(nil), record.PublicKey[:]...)
	}
	return records, hashes, nil
}

func extensionChain(snapshot rotation.TrustSnapshot, extension []rotation.Record) error {
	previous := snapshot.Checkpoint
	if len(snapshot.Records) != 0 {
		last := snapshot.Keys[len(snapshot.Keys)-1]
		previous = rotation.Checkpoint{Ordinal: snapshot.Head.Ordinal, Hash: snapshot.Head.Hash, KID: last.KID, PublicKey: last.PublicKey, PublishedAt: last.NotBefore - rotation.GraceSeconds}
	}
	retained := make(map[string][]byte, len(snapshot.Keys))
	for _, key := range snapshot.Keys {
		retained[key.KID] = append([]byte(nil), key.PublicKey[:]...)
	}
	wires := make([][]byte, len(extension))
	for index, record := range extension {
		wires[index] = []byte(record.Wire)
	}
	_, err := rotation.VerifyChain(wires, snapshot.Binding, previous, retained)
	if err != nil {
		return recordError(err)
	}
	return nil
}

func desiredSnapshot(snapshot rotation.TrustSnapshot, extension []rotation.Record, clock rotation.ClockTuple) rotation.TrustSnapshot {
	desired := snapshot
	desired.Records = append([]string{}, snapshot.Records...)
	desired.Keys = append([]rotation.TrustKey(nil), snapshot.Keys...)
	for _, record := range extension {
		cutoff := record.ActivatesAt
		desired.Keys[len(desired.Keys)-1].KnownCutoff = &cutoff
		desired.Keys = append(desired.Keys, rotation.TrustKey{Ordinal: record.Ordinal, KID: record.NewKID, PublicKey: record.PublicKey, NotBefore: record.ActivatesAt})
		desired.Records = append(desired.Records, record.Wire)
		desired.Head = rotation.ResultCursor{Ordinal: record.Ordinal, Hash: record.Hash}
	}
	desired.Clock = clock
	desired.Revision++
	return desired
}

// AcceptRefresh обрабатывает только явно запрошенный jack.server.key success page.
// Нет fetch/retry/pagination. Committed ACK не откатывается при late final failure.
func (controller *Controller) AcceptRefresh(response Response, expectedID json.RawMessage, cursor rotation.ResultCursor) (RefreshResult, error) {
	owned, snapshot, carrier, err := controller.outer(response)
	if err != nil {
		return RefreshResult{}, err
	}
	if owned.Status != 200 {
		return RefreshResult{}, localError("rotation_result_invalid")
	}
	page, err := rotation.DecodeResult(owned.Body, append(json.RawMessage(nil), expectedID...))
	if err != nil {
		return RefreshResult{}, mappedError(err, "rotation_result_invalid")
	}
	key := knownKeys(snapshot)[carrier.KID]
	if page.Current.KID != carrier.KID || page.Current.PublicKey != key.PublicKey {
		return RefreshResult{}, localError("rotation_result_invalid")
	}
	if cursor != snapshot.Head || page.Head.Ordinal < cursor.Ordinal {
		return RefreshResult{}, localError("rotation_gap")
	}
	records, hashes, err := pageRecords(snapshot, page)
	if err != nil {
		return RefreshResult{}, err
	}
	for _, record := range records {
		if record.PublishedAt > carrier.Timestamp {
			return RefreshResult{}, localError("rotation_record_invalid")
		}
	}
	framing, err := rotation.ValidatePageFraming(page, cursor, records, hashes)
	if err != nil {
		return RefreshResult{}, mappedError(err, "rotation_gap")
	}
	result := RefreshResult{Head: page.Head, Terminal: framing.Terminal, Complete: page.Complete, Revision: snapshot.Revision}
	extension := records[framing.ExtensionStart:]
	if len(extension) == 0 {
		return result, controller.final(carrier, snapshot)
	}
	if err := extensionChain(snapshot, extension); err != nil {
		return result, err
	}
	if !controller.writer.CompareAndSwap(false, true) {
		return result, localError("rotation_state_changed")
	}
	defer controller.writer.Store(false)
	current, err := controller.state()
	if err != nil {
		return result, err
	}
	if !controller.equal(current, snapshot) {
		return result, localError("rotation_state_changed")
	}
	clock, err := controller.store.CheckSnapshotClock(snapshot)
	if err != nil {
		return result, mappedError(err, "rotation_clock_unavailable")
	}
	if err := controller.timeValid(snapshot, carrier, clock.HighWater); err != nil {
		return result, err
	}
	if clock.HighWater >= extension[0].ActivatesAt {
		return result, localError("rotation_bridge_expired")
	}
	desired := desiredSnapshot(snapshot, extension, clock)
	if !capacityValid(desired, clock.HighWater) {
		return result, localError("rotation_state_changed")
	}
	if err := controller.store.CompareAndSwap(snapshot, desired, clock); err != nil {
		return result, mappedError(err, "rotation_state_unknown")
	}
	result.Committed, result.Revision = true, desired.Revision
	return result, controller.final(carrier, desired)
}
