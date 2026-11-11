package rotationserver

import (
	"crypto/sha256"
	"encoding/json"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	"github.com/PHPCraftdream/mcp-jack/server"
)

type nativeCurrent struct {
	KID string `json:"kid"`
	PublicKey string `json:"public_key"`
}
type nativeHead struct {
	Ordinal uint64 `json:"ordinal"`
	Hash string `json:"hash"`
}
type nativePage struct {
	Current nativeCurrent `json:"current"`
	Records []string `json:"records"`
	Head nativeHead `json:"head"`
	Complete bool `json:"complete"`
}

func nativeError(status int, code string) *jack.Error {
	return &jack.Error{HTTPStatus:status,Code:code,Message:"server key request unavailable"}
}

// Call обслуживает только explicit candidate route, никогда не forwarding.
func (provider *Provider) Call(call *server.NativeCall) (server.NativeResult, *jack.Error) {
	if provider == nil || provider.store == nil || call == nil || call.Tool != server.ToolServerKey || call.Caller == nil { return server.NativeResult{},nativeError(403,jack.CodeOperationDenied) }
	cursor,err := rotation.DecodeServerKeyArguments(call.Arguments)
	if err != nil { return server.NativeResult{},nativeError(400,jack.CodeInvalidParams) }
	release,err := provider.store.AcquireServingLease()
	if err != nil { return server.NativeResult{},nativeError(503,"rotation_state_unavailable") }
	defer release()
	snapshot,_,err := provider.store.Snapshot()
	if err != nil || call.Aud != snapshot.Public.Binding.Audience { return server.NativeResult{},nativeError(503,"rotation_state_unavailable") }
	checkpoint := snapshot.Public.Checkpoint
	if cursor.Ordinal < checkpoint.Ordinal || cursor.Ordinal > snapshot.Public.Head.Ordinal { return server.NativeResult{},nativeError(409,"rotation_checkpoint_unavailable") }
	offset := cursor.Ordinal-checkpoint.Ordinal
	if offset > uint64(len(snapshot.Public.Records)) { return server.NativeResult{},nativeError(409,"rotation_checkpoint_unavailable") }
	expectedHash := checkpoint.Hash
	if offset != 0 {
		hash := sha256.Sum256([]byte(snapshot.Public.Records[int(offset)-1]))
		expectedHash = jack.EncodeBase64URL(hash[:])
	}
	if cursor.Hash != expectedHash { return server.NativeResult{},nativeError(409,"rotation_checkpoint_unavailable") }
	// Все proof/hash операции завершены до authoritative sample.
	clock,err := provider.store.CheckSnapshotClock(snapshot)
	if err != nil { return server.NativeResult{},nativeError(503,"rotation_state_unavailable") }
	signer,err := provider.selectSigner(snapshot,clock)
	if err != nil { return server.NativeResult{},nativeError(503,"rotation_state_unavailable") }
	start := int(offset)
	end := start+rotation.MaxPageRecords
	if end > len(snapshot.Public.Records) { end = len(snapshot.Public.Records) }
	page := nativePage{
		Current:nativeCurrent{KID:snapshotSignerKID(snapshot,signer),PublicKey:jack.EncodeBase64URL(signer.public[:])},
		Records:append([]string{},snapshot.Public.Records[start:end]...),
		Head:nativeHead{Ordinal:snapshot.Public.Head.Ordinal,Hash:snapshot.Public.Head.Hash},
		Complete:end==len(snapshot.Public.Records),
	}
	return server.NativeResult{Structured:page},nil
}

// Полный envelope/parity parse до signing-time clock; payload не key authority.
func decodeNativeResponse(input server.ResponseKeyRequest) (*rotation.DecodedResult,error) {
	if input.Tool != server.ToolServerKey || input.Status != 200 { return nil,nil }
	if len(input.Body) > rotation.MaxResultBodyBytes { return nil,ErrUnavailable }
	var envelope struct { ID json.RawMessage `json:"id"` }
	if json.Unmarshal(input.Body,&envelope) != nil { return nil,ErrUnavailable }
	decoded,err := rotation.DecodeResult(input.Body,envelope.ID)
	if err != nil { return nil,ErrUnavailable }
	return &decoded,nil
}

func snapshotSignerKID(snapshot rotation.ServerSnapshot, signer pinnedSigner) string {
	for _, key := range snapshot.Public.Keys {
		if key.PublicKey == signer.public { return key.KID }
	}
	return ""
}

func matchesNativeResponse(page *rotation.DecodedResult,snapshot rotation.ServerSnapshot,signer pinnedSigner) bool {
	if page == nil { return true }
	if page.Current.PublicKey != signer.public || page.Current.KID != snapshotSignerKID(snapshot,signer) || page.Head != snapshot.Public.Head { return false }
	if len(page.Records) == 0 { return page.Complete }
	for start,wire := range snapshot.Public.Records {
		if wire != page.Records[0] { continue }
		end := start+len(page.Records)
		if end > len(snapshot.Public.Records) || page.Complete != (end==len(snapshot.Public.Records)) { return false }
		for index,record := range page.Records { if record != snapshot.Public.Records[start+index] { return false } }
		return true
	}
	return false
}

var _ server.NativeTools = (*Provider)(nil)
