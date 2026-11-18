// Package rotation implements the explicitly selected candidate profile of server rotation.
// Static pins and existing v1 signing bytes are unchanged.
package rotation

import (
	"bytes"
	"strconv"
	"strings"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const (
	Domain                = "mcp-jack/server-key-rotation/min1"
	GraceSeconds   int64  = 172800
	MaxTimestamp   int64  = 999999999999
	MaxOrdinal     uint64 = 1<<53 - 1
	MaxRecordBytes        = 8192
)

// Error carries a stable error code of the candidate codec.
type Error struct{ Code string }

func (e *Error) Error() string  { return "rotation: " + e.Code }
func invalid(code string) error { return &Error{Code: code} }

// Binding is set independently of the network response; strings are compared exactly.
type Binding struct {
	Endpoint string
	Audience string
}

// Record holds only public data and exact authenticated bytes.
type Record struct {
	Ordinal      uint64
	PreviousHash string
	OldKID       string
	NewKID       string
	PublicKey    [32]byte
	PublishedAt  int64
	ActivatesAt  int64
	Wire         string
	Hash         string
}

func validBinding(b Binding) bool {
	return utf8.ValidString(b.Endpoint) && utf8.ValidString(b.Audience) &&
		len(b.Endpoint) >= 1 && len(b.Endpoint) <= 2048 &&
		len(b.Audience) >= 1 && len(b.Audience) <= 1024
}

func decimal(text string, max uint64) (uint64, bool) {
	if text == "" || (len(text) > 1 && text[0] == '0') {
		return 0, false
	}
	for i := range text {
		if text[i] < '0' || text[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(text, 10, 64)
	return n, err == nil && n <= max
}

// Parse checks the intrinsic codec and both signatures; VerifyChain checks continuity.
func Parse(wire []byte, binding Binding, authorizers map[string][]byte) (Record, error) {
	fail := func(code string) (Record, error) { return Record{}, invalid(code) }
	if len(wire) == 0 || len(wire) > MaxRecordBytes {
		return fail("record_size")
	}
	for _, b := range wire {
		if b > 127 {
			return fail("non_ascii")
		}
	}
	if wire[len(wire)-1] == '\n' {
		return fail("trailing_lf")
	}
	lines := strings.Split(string(wire), "\n")
	if len(lines) != 12 {
		return fail("line_count")
	}
	if lines[0] != Domain {
		return fail("domain")
	}
	ordinal, ok := decimal(lines[3], MaxOrdinal)
	if !ok || ordinal == 0 {
		return fail("ordinal")
	}
	published, ok := decimal(lines[8], uint64(MaxTimestamp))
	if !ok {
		return fail("timestamp")
	}
	activation, ok := decimal(lines[9], uint64(MaxTimestamp))
	if !ok {
		return fail("timestamp")
	}
	if !validBinding(binding) {
		return fail("binding_size")
	}
	endpoint, err := jack.DecodeBase64URL(lines[1])
	if err != nil || len(endpoint) < 1 || len(endpoint) > 2048 {
		return fail("binding_encoding")
	}
	audience, err := jack.DecodeBase64URL(lines[2])
	if err != nil || len(audience) < 1 || len(audience) > 1024 {
		return fail("binding_encoding")
	}
	if !utf8.Valid(endpoint) || !utf8.Valid(audience) {
		return fail("utf8")
	}
	if string(endpoint) != binding.Endpoint || string(audience) != binding.Audience {
		return fail("binding")
	}
	if _, err := jack.DecodeBase64URLFixed(lines[5], 32); err != nil {
		return fail("key_id")
	}
	if _, err := jack.DecodeBase64URLFixed(lines[6], 32); err != nil {
		return fail("key_id")
	}
	if len(lines[7]) != 43 {
		return fail("base64url")
	}
	public, err := jack.DecodeBase64URLFixed(lines[7], 32)
	if err != nil || jack.ValidatePublicKey(public) != nil {
		return fail("new_key")
	}
	if jack.KeyID(public) != lines[6] {
		return fail("new_key_id")
	}
	nextProof, err := jack.DecodeBase64URLFixed(lines[10], 64)
	if err != nil {
		return fail("proof_encoding")
	}
	oldProof, err := jack.DecodeBase64URLFixed(lines[11], 64)
	if err != nil {
		return fail("proof_encoding")
	}
	if published > uint64(MaxTimestamp-GraceSeconds) || activation != published+uint64(GraceSeconds) {
		return fail("activation")
	}
	body := []byte(strings.Join(lines[:10], "\n"))
	oldPublic, known := authorizers[lines[5]]
	if !known || jack.KeyID(oldPublic) != lines[5] || jack.ValidatePublicKey(oldPublic) != nil {
		return fail("unknown_authorizer")
	}
	if !jack.Verify(public, bytes.Join([][]byte{[]byte(Domain + "/next-proof\n"), body}, nil), nextProof) {
		return fail("new_proof")
	}
	oldMessage := bytes.Join([][]byte{[]byte(Domain + "/authorize\n"), body, []byte("\n" + lines[10])}, nil)
	if !jack.Verify(oldPublic, oldMessage, oldProof) {
		return fail("old_authorization")
	}
	r := Record{Ordinal: ordinal, PreviousHash: lines[4], OldKID: lines[5], NewKID: lines[6], PublishedAt: int64(published), ActivatesAt: int64(activation), Wire: string(wire), Hash: jack.BodyHash(wire)}
	copy(r.PublicKey[:], public)
	return r, nil
}

// Signer provides an Ed25519 signature without exporting private material.
type Signer interface {
	PublicKey() []byte
	Sign([]byte) ([]byte, error)
}

// CreateRecord creates a statement but does not publish it or change trust.
// Previous must be an independently trusted checkpoint or an ACKed tail.
// The publication owner performs the full retained-key reuse check and durable ACK.
func CreateRecord(binding Binding, previous Checkpoint, oldSigner, nextSigner Signer, publishedAt int64) (Record, error) {
	if !validBinding(binding) {
		return Record{}, invalid("binding_size")
	}
	if previous.Ordinal >= MaxOrdinal {
		return Record{}, invalid("ordinal")
	}
	if previous.PublishedAt < 0 || previous.PublishedAt > MaxTimestamp || publishedAt < previous.PublishedAt {
		return Record{}, invalid("publication_order")
	}
	if publishedAt > MaxTimestamp-GraceSeconds {
		return Record{}, invalid("activation")
	}
	if previous.Ordinal == 0 {
		if previous.Hash != "-" {
			return Record{}, invalid("previous_hash")
		}
	} else if _, err := jack.DecodeBase64URLFixed(previous.Hash, 32); err != nil {
		return Record{}, invalid("previous_hash")
	}
	if oldSigner == nil || nextSigner == nil {
		return Record{}, invalid("signer_unavailable")
	}
	oldPublic := append([]byte(nil), oldSigner.PublicKey()...)
	nextPublic := append([]byte(nil), nextSigner.PublicKey()...)
	if jack.ValidatePublicKey(oldPublic) != nil || jack.KeyID(oldPublic) != previous.KID || !bytes.Equal(oldPublic, previous.PublicKey[:]) {
		return Record{}, invalid("unknown_authorizer")
	}
	if jack.ValidatePublicKey(nextPublic) != nil {
		return Record{}, invalid("new_key")
	}
	nextKID := jack.KeyID(nextPublic)
	if nextKID == previous.KID {
		return Record{}, invalid("key_reuse")
	}
	body := strings.Join([]string{
		Domain,
		jack.EncodeBase64URL([]byte(binding.Endpoint)),
		jack.EncodeBase64URL([]byte(binding.Audience)),
		strconv.FormatUint(previous.Ordinal+1, 10),
		previous.Hash,
		previous.KID,
		nextKID,
		jack.EncodeBase64URL(nextPublic),
		strconv.FormatInt(publishedAt, 10),
		strconv.FormatInt(publishedAt+GraceSeconds, 10),
	}, "\n")
	nextMessage := []byte(Domain + "/next-proof\n" + body)
	proof, err := nextSigner.Sign(append([]byte(nil), nextMessage...))
	if err != nil {
		return Record{}, invalid("signer_unavailable")
	}
	proof = append([]byte(nil), proof...)
	if !jack.Verify(nextPublic, nextMessage, proof) {
		return Record{}, invalid("new_proof")
	}
	proofText := jack.EncodeBase64URL(proof)
	oldMessage := []byte(Domain + "/authorize\n" + body + "\n" + proofText)
	authorization, err := oldSigner.Sign(append([]byte(nil), oldMessage...))
	if err != nil {
		return Record{}, invalid("signer_unavailable")
	}
	authorization = append([]byte(nil), authorization...)
	if !jack.Verify(oldPublic, oldMessage, authorization) {
		return Record{}, invalid("old_authorization")
	}
	wire := []byte(body + "\n" + proofText + "\n" + jack.EncodeBase64URL(authorization))
	return Parse(wire, binding, map[string][]byte{previous.KID: oldPublic})
}
