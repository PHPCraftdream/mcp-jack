package durable

import (
	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	bolt "go.etcd.io/bbolt"
)

// ServerInspection — публичные diagnostics, не serving permission или rollback evidence.
// Protected references и complete private snapshot не выдаются.
type ServerInspection struct {
	StoreID string `json:"store_id"`
	OwnerGeneration uint64 `json:"owner_generation"`
	Window int64 `json:"window"`
	HighWater int64 `json:"high_water"`
	ClockRevision uint64 `json:"clock_revision"`
	Unsafe bool `json:"unsafe"`
	Dirty bool `json:"dirty"`
	Fenced bool `json:"fenced"`
	StateRevision uint64 `json:"state_revision"`
	HeadOrdinal uint64 `json:"head_ordinal"`
	HeadHash string `json:"head_hash"`
	RetainedKeys int `json:"retained_keys"`
	PublicationPresent bool `json:"publication_present"`
}

// InspectServer требует exclusive owner даже offline; не создаёт DB и не вызывает clock.
func InspectServer(path string, options ServerOptions) (report ServerInspection, result error) {
	options,_,profile,err := normalizedServerOptions(options)
	if err != nil { return report,err }
	db,_,err := openTrustDB(path,false)
	if err != nil { return report,err }
	defer func(){
		if db.Close()!=nil { report,result = ServerInspection{},ErrUnavailable }
	}()
	err = db.View(func(tx *bolt.Tx) error {
		raw,encoded,intent,err := readServerRows(tx)
		if err != nil { return err }
		guard,err := decodeServerGuard(raw,options.TrustOptions,profile)
		if err != nil { return err }
		snapshot,err := rotation.DecodeServerSnapshot(encoded,options.Binding,options.Window,options.Checkpoint)
		if err != nil { return ErrInvalidStore }
		// Flags сохраняются как diagnostics; несовместимую clock dependency не скрываем.
		if snapshot.Public.Clock.HighWater>guard.Clock.HighWater || snapshot.Public.Clock.Revision>guard.Clock.Revision { return ErrInvalidStore }
		if err := validateServerPublicationRows(encoded,intent,snapshot,options.TrustOptions); err != nil { return err }
		report = ServerInspection{
			StoreID:jack.EncodeBase64URL(guard.StoreID[:]),OwnerGeneration:guard.Owner,
			Window:guard.Clock.Window,HighWater:guard.Clock.HighWater,ClockRevision:guard.Clock.Revision,
			Unsafe:guard.Clock.Unsafe||snapshot.Public.Clock.Unsafe,Dirty:guard.Dirty,Fenced:guard.Fenced||snapshot.Public.Fenced,
			StateRevision:snapshot.Public.Revision,HeadOrdinal:snapshot.Public.Head.Ordinal,HeadHash:snapshot.Public.Head.Hash,
			RetainedKeys:len(snapshot.Public.Keys),PublicationPresent:len(intent)!=0,
		}
		return nil
	})
	if err != nil { return ServerInspection{},err }
	return report,nil
}
