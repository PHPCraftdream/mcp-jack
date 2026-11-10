// Package rotation реализует явно выбранный candidate-профиль серверной ротации.
// Статические pins и существующие signing bytes v1 не изменяются.
package rotation

import (
	"bytes"
	"strconv"
	"strings"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const (
	Domain = "mcp-jack/server-key-rotation/min1"
	GraceSeconds int64 = 172800
	MaxTimestamp int64 = 999999999999
	MaxOrdinal uint64 = 1<<53 - 1
	MaxRecordBytes = 8192
)

// Error содержит стабильный код ошибки candidate codec.
type Error struct { Code string }

func (e *Error) Error() string { return "rotation: " + e.Code }
func invalid(code string) error { return &Error{Code: code} }

// Binding задаётся независимо от сетевого ответа; строки сравниваются точно.
type Binding struct {
	Endpoint string
	Audience string
}

// Record содержит только публичные данные и точные аутентифицированные bytes.
type Record struct {
	Ordinal uint64
	PreviousHash string
	OldKID string
	NewKID string
	PublicKey [32]byte
	PublishedAt int64
	ActivatesAt int64
	Wire string
	Hash string
}

func validBinding(b Binding) bool {
	return utf8.ValidString(b.Endpoint) && utf8.ValidString(b.Audience) &&
		len(b.Endpoint) >= 1 && len(b.Endpoint) <= 2048 &&
		len(b.Audience) >= 1 && len(b.Audience) <= 1024
}

func decimal(text string, max uint64) (uint64, bool) {
	if text == "" || (len(text) > 1 && text[0] == '0') { return 0, false }
	for i := range text { if text[i] < '0' || text[i] > '9' { return 0, false } }
	n, err := strconv.ParseUint(text, 10, 64)
	return n, err == nil && n <= max
}

// Parse проверяет intrinsic codec и обе подписи; continuity проверяет VerifyChain.
func Parse(wire []byte, binding Binding, authorizers map[string][]byte) (Record, error) {
	fail := func(code string) (Record, error) { return Record{}, invalid(code) }
	if len(wire) == 0 || len(wire) > MaxRecordBytes { return fail("record_size") }
	for _, b := range wire { if b > 127 { return fail("non_ascii") } }
	if wire[len(wire)-1] == '\n' { return fail("trailing_lf") }
	lines := strings.Split(string(wire), "\n")
	if len(lines) != 12 { return fail("line_count") }
	if lines[0] != Domain { return fail("domain") }
	ordinal, ok := decimal(lines[3], MaxOrdinal)
	if !ok || ordinal == 0 { return fail("ordinal") }
	published, ok := decimal(lines[8], uint64(MaxTimestamp))
	if !ok { return fail("timestamp") }
	activation, ok := decimal(lines[9], uint64(MaxTimestamp))
	if !ok { return fail("timestamp") }
	if !validBinding(binding) { return fail("binding_size") }
	endpoint, err := jack.DecodeBase64URL(lines[1])
	if err != nil || len(endpoint) < 1 || len(endpoint) > 2048 { return fail("binding_encoding") }
	audience, err := jack.DecodeBase64URL(lines[2])
	if err != nil || len(audience) < 1 || len(audience) > 1024 { return fail("binding_encoding") }
	if !utf8.Valid(endpoint) || !utf8.Valid(audience) { return fail("utf8") }
	if string(endpoint) != binding.Endpoint || string(audience) != binding.Audience { return fail("binding") }
	if _, err := jack.DecodeBase64URLFixed(lines[5], 32); err != nil { return fail("key_id") }
	if _, err := jack.DecodeBase64URLFixed(lines[6], 32); err != nil { return fail("key_id") }
	if len(lines[7]) != 43 { return fail("base64url") }
	public, err := jack.DecodeBase64URLFixed(lines[7], 32)
	if err != nil || jack.ValidatePublicKey(public) != nil { return fail("new_key") }
	if jack.KeyID(public) != lines[6] { return fail("new_key_id") }
	nextProof, err := jack.DecodeBase64URLFixed(lines[10], 64)
	if err != nil { return fail("proof_encoding") }
	oldProof, err := jack.DecodeBase64URLFixed(lines[11], 64)
	if err != nil { return fail("proof_encoding") }
	if published > uint64(MaxTimestamp-GraceSeconds) || activation != published+uint64(GraceSeconds) { return fail("activation") }
	body := []byte(strings.Join(lines[:10], "\n"))
	oldPublic, known := authorizers[lines[5]]
	if !known || jack.KeyID(oldPublic) != lines[5] || jack.ValidatePublicKey(oldPublic) != nil { return fail("unknown_authorizer") }
	if !jack.Verify(public, bytes.Join([][]byte{[]byte(Domain+"/next-proof\n"), body}, nil), nextProof) { return fail("new_proof") }
	oldMessage := bytes.Join([][]byte{[]byte(Domain+"/authorize\n"), body, []byte("\n"+lines[10])}, nil)
	if !jack.Verify(oldPublic, oldMessage, oldProof) { return fail("old_authorization") }
	r := Record{Ordinal: ordinal, PreviousHash: lines[4], OldKID: lines[5], NewKID: lines[6], PublishedAt: int64(published), ActivatesAt: int64(activation), Wire: string(wire), Hash: jack.BodyHash(wire)}
	copy(r.PublicKey[:], public)
	return r, nil
}
