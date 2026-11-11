package rotationserver

import (
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// Publication возвращается только после exact durable ACK; не является HTTP delivery.
type Publication struct {
	Record rotation.Record
	Revision uint64
}

func createPublication(binding rotation.Binding, previous rotation.Checkpoint, old, next pinnedSigner, publishedAt int64) (record rotation.Record, result error) {
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			record, result = rotation.Record{}, ErrUnavailable
		}
	}()
	record, result = rotation.CreateRecord(binding, previous, old, next, publishedAt)
	complete = true
	return record, result
}

// Announce — одна explicit authorization для заранее настроенного next handle.
// P фиксируется одним fresh sample; отказ/конфликт/unknown не повторяются автоматически.
func (provider *Provider) Announce(reference, kid string) (Publication, error) {
	if provider == nil || provider.store == nil || !provider.publication.CompareAndSwap(false, true) { return Publication{}, ErrUnavailable }
	defer provider.publication.Store(false)
	next, exists := provider.keys[keyIdentity{reference:reference,kid:kid}]
	if !exists { return Publication{}, ErrUnavailable }
	release, err := provider.store.AcquireServingLease()
	if err != nil { return Publication{}, ErrUnavailable }
	defer release()
	snapshot, _, err := provider.store.Snapshot()
	if err != nil { return Publication{}, err }
	if snapshot.Public.Head.Ordinal == rotation.MaxOrdinal || snapshot.Public.Revision == rotation.MaxOrdinal || len(snapshot.Public.Keys) >= rotation.MaxRetainedKeys { return Publication{}, ErrUnavailable }
	for _, retained := range snapshot.Public.Keys {
		if retained.KID == kid || retained.PublicKey == next.public { return Publication{}, ErrUnavailable }
	}
	last := snapshot.Public.Keys[len(snapshot.Public.Keys)-1]
	tailReference := snapshot.SignerReferences[len(snapshot.SignerReferences)-1]
	old, exists := provider.keys[keyIdentity{reference:tailReference.Reference,kid:last.KID}]
	if !exists || old.public != last.PublicKey { return Publication{}, ErrUnavailable }
	previous := snapshot.Public.Checkpoint
	if last.Ordinal != previous.Ordinal {
		previous = rotation.Checkpoint{Ordinal:last.Ordinal,Hash:snapshot.Public.Head.Hash,KID:last.KID,PublicKey:last.PublicKey,PublishedAt:last.NotBefore-rotation.GraceSeconds}
	}
	clock, err := provider.store.CheckSnapshotClock(snapshot)
	if err != nil { return Publication{}, err }
	if clock.HighWater > rotation.MaxTimestamp-rotation.GraceSeconds { return Publication{}, ErrUnavailable }
	if _, err := provider.selectSigner(snapshot,clock); err != nil { return Publication{}, err }
	pending := 0
	for _, key := range snapshot.Public.Keys { if key.NotBefore > clock.HighWater { pending++ } }
	if pending >= 128 { return Publication{}, ErrUnavailable }
	record, err := createPublication(snapshot.Public.Binding,previous,old,next,clock.HighWater)
	if err != nil { return Publication{}, ErrUnavailable }
	desired := snapshot
	desired.Public.Records = append(append([]string{},snapshot.Public.Records...),record.Wire)
	desired.Public.Keys = append([]rotation.TrustKey{},snapshot.Public.Keys...)
	cutoff := record.ActivatesAt
	desired.Public.Keys[len(desired.Public.Keys)-1].KnownCutoff = &cutoff
	desired.Public.Keys = append(desired.Public.Keys,rotation.TrustKey{Ordinal:record.Ordinal,KID:record.NewKID,PublicKey:record.PublicKey,NotBefore:record.ActivatesAt})
	desired.Public.Head = rotation.ResultCursor{Ordinal:record.Ordinal,Hash:record.Hash}
	desired.Public.Revision++
	desired.Public.Clock = clock
	desired.SignerReferences = append(append([]rotation.SignerReference{},snapshot.SignerReferences...),rotation.SignerReference{KID:kid,Reference:reference})
	if err := provider.store.CompareAndSwap(snapshot,desired,clock); err != nil { return Publication{}, err }
	return Publication{Record:record,Revision:desired.Public.Revision},nil
}
