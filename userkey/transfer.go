package userkey

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const maxTransferBytes = 4096

// TransferErrorClasses are the stable Code values returned by strict transfer operations.
const (
	ClassMalformedJSON           = "malformed_json"
	ClassWrongRootType           = "wrong_root_type"
	ClassOversizedEnvelope       = "oversized_envelope"
	ClassUnknownVersion          = "unknown_version"
	ClassUnknownType             = "unknown_type"
	ClassBadMemberSet            = "bad_member_set"
	ClassWrongFieldType          = "wrong_field_type"
	ClassBadEncoding             = "bad_encoding"
	ClassBadURL                  = "bad_url"
	ClassInvalidPublicKey        = "invalid_public_key"
	ClassSeedPubMismatch         = "seed_pub_mismatch"
	ClassKIDMismatch             = "kid_mismatch"
	ClassNonCanonicalBytes       = "non_canonical_bytes"
	ClassWrongEnvelopeType       = "wrong_envelope_type"
	ClassPrivateMaterialRejected = "private_material_rejected"
	ClassNotPrivate              = "not_private"
	ClassServerIdentityMismatch  = "server_identity_mismatch"
)

const (
	publicEnvelopeType     = "user-key/public"
	privateEnvelopeType    = "user-key/private"
	credentialEnvelopeType = "user-key/credential/client"
)

// ExpectedIdentity is the independently trusted endpoint, audience, and raw server identity required for credential operations.
type ExpectedIdentity struct {
	// URL is the exact client endpoint string.
	URL string
	// Aud is the exact non-empty audience string.
	Aud string
	// ServerPublicKey is the raw 32-byte trusted Ed25519 public key.
	ServerPublicKey []byte
	// ServerKID is the canonical base64url key identifier for ServerPublicKey.
	ServerKID string
}

// ConnectionConfig is a validated credential endpoint and server pin. ServerKey is an owned raw 32-byte key.
type ConnectionConfig struct {
	// BaseURL is the validated endpoint string.
	BaseURL string
	// Aud is the exact validated audience.
	Aud string
	// ServerKey is an owned copy of the pinned raw public key.
	ServerKey []byte
	// ServerKID is its canonical key identifier.
	ServerKID string
}

// ImportedCredential is the validated client signer and its connection identity.
type ImportedCredential struct {
	// Signer is the existing client-compatible software signer.
	Signer *ClientKey
	// Connection contains the validated endpoint and pinned server key.
	Connection ConnectionConfig
}

// PublicIdentity is a verify-only imported user identity containing no private material.
type PublicIdentity struct {
	pub []byte
	kid string
}

// PublicKey returns a fresh copy of the raw public key.
func (p *PublicIdentity) PublicKey() []byte {
	if p == nil {
		return nil
	}
	return copyPub(p.pub)
}

// KID returns the public key identifier.
func (p *PublicIdentity) KID() string {
	if p == nil {
		return ""
	}
	return p.kid
}

// Verify reports whether signature is valid for message under this public identity.
func (p *PublicIdentity) Verify(message, signature []byte) bool {
	return p != nil && jack.Verify(p.pub, message, signature)
}

// Sign refuses private operations on a public-only identity with not_private.
func (p *PublicIdentity) Sign([]byte) ([]byte, error) {
	return nil, transferError(ClassNotPrivate, "d", 0)
}

// ExportPublicEnvelope returns the canonical public envelope for this identity.
func (p *PublicIdentity) ExportPublicEnvelope() ([]byte, error) {
	return ExportPublicEnvelope(p)
}

func (p PublicIdentity) redacted() string {
	return fmt.Sprintf("userkey.PublicIdentity{kid:%s}", p.kid)
}

// String returns a redacted representation containing only the public KID.
func (p PublicIdentity) String() string { return p.redacted() }

// GoString returns a redacted %#v representation containing only the public KID.
func (p PublicIdentity) GoString() string { return p.redacted() }

// Format redacts the identity for every fmt verb.
func (p PublicIdentity) Format(f fmt.State, _ rune) { fmt.Fprint(f, p.redacted()) }

// MarshalJSON prevents the public identity representation from depending on private fields.
func (p PublicIdentity) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// ExportPublicEnvelope returns the canonical public envelope for any value exposing PublicKey; it requires no private-key extraction.
func ExportPublicEnvelope(key interface{ PublicKey() []byte }) ([]byte, error) {
	if key == nil || isNilInterface(key) {
		return nil, transferError(ClassBadEncoding, "x", 0)
	}
	pub := copyPub(key.PublicKey())
	if len(pub) != PublicKeySize {
		return nil, transferError(ClassBadEncoding, "x", len(pub))
	}
	if err := jack.ValidatePublicKey(pub); err != nil {
		return nil, transferError(ClassInvalidPublicKey, "x", len(pub))
	}
	return marshalPublicEnvelope(pub, jack.KeyID(pub)), nil
}

// ImportClientPublicEnvelope imports a public envelope as a verify-only identity.
func ImportClientPublicEnvelope(data []byte) (*PublicIdentity, error) {
	snapshot, err := boundedSnapshot(data)
	if err != nil {
		return nil, err
	}
	doc, err := parseEnvelope(snapshot, sinkClientPublic)
	if err != nil {
		return nil, err
	}
	return &PublicIdentity{pub: copyPub(doc.pub), kid: doc.kid}, nil
}

// ImportClientPrivateEnvelope imports a private envelope into the existing client-role software signer.
func ImportClientPrivateEnvelope(data []byte) (*ClientKey, error) {
	snapshot, err := boundedSnapshot(data)
	if err != nil {
		return nil, err
	}
	doc, err := parseEnvelope(snapshot, sinkClientPrivate)
	if err != nil {
		return nil, err
	}
	return newClientKey(doc.seed), nil
}

// ImportServerPublicEnvelope imports public identity data for server-side admission.
func ImportServerPublicEnvelope(data []byte) (*ServerKey, error) {
	snapshot, err := boundedSnapshot(data)
	if err != nil {
		return nil, err
	}
	doc, err := parseEnvelope(snapshot, sinkServerPublic)
	if err != nil {
		return nil, err
	}
	return &ServerKey{pub: copyPub(doc.pub), kid: doc.kid}, nil
}

// ImportCredential validates a credential before checking its independently trusted identity tuple.
func ImportCredential(data []byte, expected ExpectedIdentity) (*ImportedCredential, error) {
	snapshot, err := boundedSnapshot(data)
	if err != nil {
		return nil, err
	}
	doc, err := parseCredential(snapshot)
	if err != nil {
		return nil, err
	}
	trusted, err := validateExpected(expected)
	if err != nil || !credentialMatches(doc, trusted) {
		return nil, transferError(ClassServerIdentityMismatch, "expected", len(expected.ServerPublicKey))
	}
	signer := newClientKey(doc.client.seed)
	return &ImportedCredential{
		Signer: signer,
		Connection: ConnectionConfig{
			BaseURL: doc.url, Aud: doc.aud,
			ServerKey: copyPub(doc.serverPub), ServerKID: doc.serverKID,
		},
	}, nil
}

// ValidateCredential applies the credential pipeline before comparing with the server's configured identity.
func ValidateCredential(data []byte, expected ExpectedIdentity) error {
	snapshot, err := boundedSnapshot(data)
	if err != nil {
		return err
	}
	doc, err := parseCredential(snapshot)
	if err != nil {
		return err
	}
	trusted, err := validateExpected(expected)
	if err != nil || !credentialMatches(doc, trusted) {
		return transferError(ClassServerIdentityMismatch, "expected", len(expected.ServerPublicKey))
	}
	return nil
}

// UserKeyIssuance is the local server handoff handle. Credential bytes are unencrypted and remain in memory for its lifetime.
type UserKeyIssuance struct {
	credential func() []byte
	// PublicIdentity is the public-only identity to retain for server use.
	PublicIdentity *ServerKey
}

// CredentialBytes returns a fresh copy of the plaintext client credential.
func (i *UserKeyIssuance) CredentialBytes() []byte {
	if i == nil || i.credential == nil {
		return nil
	}
	return append([]byte(nil), i.credential()...)
}

func (i UserKeyIssuance) redacted() string {
	kid := ""
	if i.PublicIdentity != nil {
		kid = i.PublicIdentity.KID()
	}
	return fmt.Sprintf("userkey.UserKeyIssuance{kid:%s}", kid)
}

// String returns a redacted representation of the issuance handle.
func (i UserKeyIssuance) String() string { return i.redacted() }

// GoString returns a redacted %#v representation of the issuance handle.
func (i UserKeyIssuance) GoString() string { return i.redacted() }

// Format redacts the issuance handle for every fmt verb.
func (i UserKeyIssuance) Format(f fmt.State, _ rune) { fmt.Fprint(f, i.redacted()) }

// MarshalJSON redacts the issuance handle.
func (i UserKeyIssuance) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// IssueUserKey creates a key locally using 32 bytes from random and returns a credential handoff plus public identity.
func IssueUserKey(expected ExpectedIdentity, random io.Reader) (*UserKeyIssuance, error) {
	trusted, err := validateExpected(expected)
	if err != nil {
		return nil, err
	}
	if random == nil {
		return nil, fmt.Errorf("userkey: nil credential random source")
	}
	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, fmt.Errorf("userkey: credential random source failed")
	}
	private := ed25519.NewKeyFromSeed(seed)
	pub := copyPub(private.Public().(ed25519.PublicKey))
	kid := jack.KeyID(pub)
	inner := marshalPrivateEnvelope(seed, pub, kid)
	credential := marshalCredential(credentialDoc{
		aud: trusted.aud, clientKey: string(inner), serverKID: trusted.kid,
		serverPub: trusted.pub, url: trusted.url,
	})
	if len(credential) > maxTransferBytes {
		return nil, transferError(ClassOversizedEnvelope, "input", len(credential))
	}
	stored := append([]byte(nil), credential...)
	return &UserKeyIssuance{
		credential:     func() []byte { return stored },
		PublicIdentity: &ServerKey{pub: copyPub(pub), kid: kid},
	}, nil
}

type importSink uint8

const (
	sinkClientPublic importSink = iota
	sinkClientPrivate
	sinkServerPublic
)

type envelopeDoc struct {
	seed []byte
	pub  []byte
	kid  string
}

type credentialDoc struct {
	aud       string
	clientKey string
	serverKID string
	serverPub []byte
	url       string
	client    *envelopeDoc
}

type trustedIdentity struct {
	aud string
	kid string
	pub []byte
	url string
}

func parseEnvelope(data []byte, sink importSink) (*envelopeDoc, error) {
	members, err := parseObject(data)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(members); err != nil {
		return nil, err
	}
	typValue, exists := members["type"]
	if !exists {
		return nil, transferError(ClassUnknownType, "type", 0)
	}
	typ, ok := typValue.(string)
	if !ok {
		return nil, transferError(ClassWrongFieldType, "type", valueLength(typValue))
	}
	if !knownDocumentType(typ) {
		return nil, transferError(ClassUnknownType, "type", len(typ))
	}
	switch sink {
	case sinkClientPublic:
		if typ != publicEnvelopeType {
			return nil, transferError(ClassWrongEnvelopeType, "type", len(typ))
		}
	case sinkClientPrivate:
		if typ != privateEnvelopeType {
			return nil, transferError(ClassWrongEnvelopeType, "type", len(typ))
		}
	case sinkServerPublic:
		if typ == privateEnvelopeType || typ == credentialEnvelopeType {
			return nil, transferError(ClassPrivateMaterialRejected, "type", len(typ))
		}
		if typ != publicEnvelopeType {
			return nil, transferError(ClassWrongEnvelopeType, "type", len(typ))
		}
	}
	private := typ == privateEnvelopeType
	if !exactMembers(members, envelopeMembers(private)) {
		return nil, transferError(ClassBadMemberSet, "", len(data))
	}
	if err := checkEnvelopeLiterals(members); err != nil {
		return nil, err
	}
	for _, name := range []string{"d", "kid", "x"} {
		if name == "d" && !private {
			continue
		}
		if _, ok := members[name].(string); !ok {
			return nil, transferError(ClassWrongFieldType, name, valueLength(members[name]))
		}
	}
	var seed []byte
	if private {
		seed, ok = decodeTransferBytes(members["d"].(string))
		if !ok {
			return nil, transferError(ClassBadEncoding, "d", len(members["d"].(string)))
		}
	}
	pub, ok := decodeTransferBytes(members["x"].(string))
	if !ok {
		return nil, transferError(ClassBadEncoding, "x", len(members["x"].(string)))
	}
	kid := members["kid"].(string)
	if _, ok := decodeTransferBytes(kid); !ok {
		return nil, transferError(ClassBadEncoding, "kid", len(kid))
	}
	if err := jack.ValidatePublicKey(pub); err != nil {
		return nil, transferError(ClassInvalidPublicKey, "x", len(pub))
	}
	if private && !bytes.Equal(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), pub) {
		return nil, transferError(ClassSeedPubMismatch, "x", len(pub))
	}
	if kid != jack.KeyID(pub) {
		return nil, transferError(ClassKIDMismatch, "kid", len(kid))
	}
	canonical := marshalPublicEnvelope(pub, kid)
	if private {
		canonical = marshalPrivateEnvelope(seed, pub, kid)
	}
	if !bytes.Equal(data, canonical) {
		return nil, transferError(ClassNonCanonicalBytes, "", len(data))
	}
	return &envelopeDoc{seed: seed, pub: pub, kid: kid}, nil
}

func parseCredential(data []byte) (*credentialDoc, error) {
	members, err := parseObject(data)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(members); err != nil {
		return nil, err
	}
	typValue, exists := members["type"]
	if !exists {
		return nil, transferError(ClassUnknownType, "type", 0)
	}
	typ, ok := typValue.(string)
	if !ok {
		return nil, transferError(ClassWrongFieldType, "type", valueLength(typValue))
	}
	if !knownDocumentType(typ) {
		return nil, transferError(ClassUnknownType, "type", len(typ))
	}
	if typ != credentialEnvelopeType {
		return nil, transferError(ClassWrongEnvelopeType, "type", len(typ))
	}
	if !exactMembers(members, []string{"aud", "client_key", "server_kid", "server_public_key", "type", "url", "v"}) {
		return nil, transferError(ClassBadMemberSet, "", len(data))
	}
	for _, name := range []string{"aud", "client_key", "server_kid", "server_public_key", "url"} {
		if _, ok := members[name].(string); !ok {
			return nil, transferError(ClassWrongFieldType, name, valueLength(members[name]))
		}
	}
	aud := members["aud"].(string)
	if aud == "" {
		return nil, transferError(ClassWrongFieldType, "aud", 0)
	}
	url := members["url"].(string)
	if !checkURLPolicy(url) {
		return nil, transferError(ClassBadURL, "url", len(url))
	}
	serverKID := members["server_kid"].(string)
	serverKIDBytes, ok := decodeTransferBytes(serverKID)
	if !ok {
		return nil, transferError(ClassBadEncoding, "server_kid", len(serverKID))
	}
	serverPubString := members["server_public_key"].(string)
	serverPub, ok := decodeTransferBytes(serverPubString)
	if !ok {
		return nil, transferError(ClassBadEncoding, "server_public_key", len(serverPubString))
	}
	if err := jack.ValidatePublicKey(serverPub); err != nil {
		return nil, transferError(ClassInvalidPublicKey, "server_public_key", len(serverPub))
	}
	if serverKID != jack.KeyID(serverPub) || len(serverKIDBytes) != 32 {
		return nil, transferError(ClassKIDMismatch, "server_kid", len(serverKID))
	}
	clientKey := members["client_key"].(string)
	inner, err := parseEnvelope([]byte(clientKey), sinkClientPrivate)
	if err != nil {
		return nil, err
	}
	doc := &credentialDoc{aud: aud, clientKey: clientKey, serverKID: serverKID, serverPub: serverPub, url: url, client: inner}
	if !bytes.Equal(data, marshalCredential(*doc)) {
		return nil, transferError(ClassNonCanonicalBytes, "", len(data))
	}
	return doc, nil
}

func parseObject(data []byte) (map[string]any, error) {
	if len(data) > maxTransferBytes {
		return nil, transferError(ClassOversizedEnvelope, "input", len(data))
	}
	if !utf8.Valid(data) || !validRawStringScalars(data) {
		return nil, transferError(ClassMalformedJSON, "input", len(data))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return nil, transferError(ClassMalformedJSON, "input", len(data))
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, transferError(ClassMalformedJSON, "input", len(data))
	}
	members, ok := root.(map[string]any)
	if !ok {
		return nil, transferError(ClassWrongRootType, "", len(data))
	}
	return members, nil
}

func validRawStringScalars(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		i++
		for i < len(data) {
			switch data[i] {
			case '"':
				goto nextToken
			case '\\':
				if i+1 >= len(data) {
					return true
				}
				if data[i+1] != 'u' {
					i += 2
					continue
				}
				if i+5 >= len(data) {
					return true
				}
				unit, valid := hexUnit(data[i+2 : i+6])
				if !valid {
					i += 6
					continue
				}
				if unit >= 0xd800 && unit <= 0xdbff {
					if i+11 >= len(data) || data[i+6] != '\\' || data[i+7] != 'u' {
						return false
					}
					low, valid := hexUnit(data[i+8 : i+12])
					if !valid || low < 0xdc00 || low > 0xdfff {
						return false
					}
					i += 12
					continue
				}
				if unit >= 0xdc00 && unit <= 0xdfff {
					return false
				}
				i += 6
			default:
				i++
			}
		}
		return true
	nextToken:
	}
	return true
}

func hexUnit(b []byte) (uint16, bool) {
	if len(b) != 4 {
		return 0, false
	}
	var value uint16
	for _, c := range b {
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			value |= uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			value |= uint16(c-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func checkVersion(members map[string]any) error {
	value, ok := members["v"].(json.Number)
	if !ok || !numberEqualsOne(string(value)) {
		return transferError(ClassUnknownVersion, "v", valueLength(members["v"]))
	}
	return nil
}

func numberEqualsOne(value string) bool {
	if value == "" || value[0] == '-' {
		return false
	}
	exponent := 0
	mantissa := value
	if idx := strings.IndexAny(value, "eE"); idx >= 0 {
		mantissa = value[:idx]
		exponentText := value[idx+1:]
		negative := false
		if len(exponentText) > 0 && (exponentText[0] == '+' || exponentText[0] == '-') {
			negative = exponentText[0] == '-'
			exponentText = exponentText[1:]
		}
		for _, c := range exponentText {
			if exponent > maxTransferBytes {
				return false
			}
			exponent = exponent*10 + int(c-'0')
		}
		if exponent > maxTransferBytes {
			return false
		}
		if negative {
			exponent = -exponent
		}
	}
	fractionDigits := 0
	if idx := strings.IndexByte(mantissa, '.'); idx >= 0 {
		fractionDigits = len(mantissa) - idx - 1
		mantissa = mantissa[:idx] + mantissa[idx+1:]
	}
	first := 0
	for first < len(mantissa) && mantissa[first] == '0' {
		first++
	}
	if first == len(mantissa) {
		return false
	}
	digits := mantissa[first:]
	trailing := 0
	for trailing < len(digits) && digits[len(digits)-1-trailing] == '0' {
		trailing++
	}
	return digits[:len(digits)-trailing] == "1" && exponent-fractionDigits+trailing == 0
}

func checkEnvelopeLiterals(members map[string]any) error {
	for _, name := range []string{"kty", "crv"} {
		value, ok := members[name].(string)
		if !ok {
			return transferError(ClassWrongFieldType, name, valueLength(members[name]))
		}
		want := "OKP"
		if name == "crv" {
			want = "Ed25519"
		}
		if value != want {
			return transferError(ClassUnknownType, name, len(value))
		}
	}
	return nil
}

func exactMembers(members map[string]any, expected []string) bool {
	if len(members) != len(expected) {
		return false
	}
	for _, name := range expected {
		if _, ok := members[name]; !ok {
			return false
		}
	}
	return true
}

func envelopeMembers(private bool) []string {
	if private {
		return []string{"crv", "d", "kid", "kty", "type", "v", "x"}
	}
	return []string{"crv", "kid", "kty", "type", "v", "x"}
}

func knownDocumentType(typ string) bool {
	return typ == publicEnvelopeType || typ == privateEnvelopeType || typ == credentialEnvelopeType
}

func decodeTransferBytes(value string) ([]byte, bool) {
	decoded, err := jack.DecodeBase64URLFixed(value, 32)
	if err != nil || len(value) != 43 {
		return nil, false
	}
	return decoded, true
}

func marshalPublicEnvelope(pub []byte, kid string) []byte {
	return []byte(`{"crv":"Ed25519","kid":"` + kid + `","kty":"OKP","type":"user-key/public","v":1,"x":"` + jack.EncodeBase64URL(pub) + `"}`)
}

func marshalPrivateEnvelope(seed, pub []byte, kid string) []byte {
	return []byte(`{"crv":"Ed25519","d":"` + jack.EncodeBase64URL(seed) + `","kid":"` + kid + `","kty":"OKP","type":"user-key/private","v":1,"x":"` + jack.EncodeBase64URL(pub) + `"}`)
}

func marshalCredential(doc credentialDoc) []byte {
	return []byte(`{"aud":` + quoteJCS(doc.aud) + `,"client_key":` + quoteJCS(doc.clientKey) + `,"server_kid":` + quoteJCS(doc.serverKID) + `,"server_public_key":` + quoteJCS(jack.EncodeBase64URL(doc.serverPub)) + `,"type":"user-key/credential/client","url":` + quoteJCS(doc.url) + `,"v":1}`)
}

func quoteJCS(value string) string {
	out := make([]byte, 0, len(value)+2)
	out = append(out, '"')
	const hex = "0123456789abcdef"
	for _, r := range value {
		switch r {
		case '"', '\\':
			out = append(out, '\\', byte(r))
		case '\b':
			out = append(out, '\\', 'b')
		case '\t':
			out = append(out, '\\', 't')
		case '\n':
			out = append(out, '\\', 'n')
		case '\f':
			out = append(out, '\\', 'f')
		case '\r':
			out = append(out, '\\', 'r')
		default:
			if r < 0x20 {
				out = append(out, '\\', 'u', '0', '0', hex[byte(r)>>4], hex[byte(r)&15])
			} else {
				out = utf8.AppendRune(out, r)
			}
		}
	}
	return string(append(out, '"'))
}

func validateExpected(expected ExpectedIdentity) (*trustedIdentity, error) {
	if !checkURLPolicy(expected.URL) {
		return nil, transferError(ClassBadURL, "url", len(expected.URL))
	}
	if expected.Aud == "" || !utf8.ValidString(expected.Aud) {
		return nil, transferError(ClassWrongFieldType, "aud", len(expected.Aud))
	}
	if len(expected.ServerPublicKey) != PublicKeySize {
		return nil, transferError(ClassBadEncoding, "server_public_key", len(expected.ServerPublicKey))
	}
	pub := copyPub(expected.ServerPublicKey)
	if err := jack.ValidatePublicKey(pub); err != nil {
		return nil, transferError(ClassInvalidPublicKey, "server_public_key", len(pub))
	}
	if _, ok := decodeTransferBytes(expected.ServerKID); !ok {
		return nil, transferError(ClassBadEncoding, "server_kid", len(expected.ServerKID))
	}
	if expected.ServerKID != jack.KeyID(pub) {
		return nil, transferError(ClassKIDMismatch, "server_kid", len(expected.ServerKID))
	}
	return &trustedIdentity{aud: expected.Aud, kid: expected.ServerKID, pub: pub, url: expected.URL}, nil
}

func credentialMatches(doc *credentialDoc, trusted *trustedIdentity) bool {
	return trusted != nil && doc.url == trusted.url && doc.aud == trusted.aud && doc.serverKID == trusted.kid && bytes.Equal(doc.serverPub, trusted.pub)
}

// checkURLPolicy reports whether raw satisfies the client URL policy (docs/design/interop.md section 9): https is accepted for any syntactically plain host; http only for a literal canonical dotted-decimal 127.x.y.z or the bracketed literal [::1].
// The helpers below are a faithful local port of the client package's pure URL policy (client/urlpolicy.go checkDestination), kept internal because client edits are out of scope; behavior matches exactly.
func checkURLPolicy(raw string) bool {
	if raw == "" {
		return false
	}
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b <= 0x20 || b == 0x7f || b >= 0x80 || b == '\\' {
			return false
		}
	}
	var secure bool
	var rest string
	switch {
	case policyHasPrefixFold(raw, "https://"):
		secure, rest = true, raw[len("https://"):]
	case policyHasPrefixFold(raw, "http://"):
		secure, rest = false, raw[len("http://"):]
	default:
		return false
	}
	end := len(rest)
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; c == '/' || c == '?' || c == '#' {
			end = i
			break
		}
	}
	authority := rest[:end]
	if authority == "" {
		return false
	}
	for i := 0; i < len(authority); i++ {
		if authority[i] == '@' || authority[i] == '%' {
			return false
		}
	}
	host, bracketed, err := policySplitHostPort(authority)
	if err != nil {
		return false
	}
	if secure {
		return true
	}
	if bracketed {
		return host == "::1"
	}
	return policyIsLoopbackIPv4(host)
}

// policyHasPrefixFold reports whether s starts with the lowercase ASCII prefix, ignoring ASCII case in s.
func policyHasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}

// policySplitHostPort validates the authority (host and optional port) and returns the host (IPv6 literal without brackets, lowercased) and whether it was bracketed.
func policySplitHostPort(authority string) (host string, bracketed bool, err error) {
	var portPart string
	hasPort := false
	if authority[0] == '[' {
		closeIdx := -1
		for i := 1; i < len(authority); i++ {
			switch authority[i] {
			case '[':
				return "", false, errPolicyMalformedDestination
			case ']':
				if closeIdx >= 0 {
					return "", false, errPolicyMalformedDestination
				}
				closeIdx = i
			}
		}
		if closeIdx < 0 {
			return "", false, errPolicyMalformedDestination
		}
		lit := authority[1:closeIdx]
		if lit == "" {
			return "", false, errPolicyMalformedDestination
		}
		for i := 0; i < len(lit); i++ {
			c := lit[i]
			if !(policyIsHexDigit(c) || c == ':' || c == '.') {
				return "", false, errPolicyMalformedDestination
			}
		}
		host = policyAsciiLower(lit)
		bracketed = true
		tail := authority[closeIdx+1:]
		if tail != "" {
			if tail[0] != ':' {
				return "", false, errPolicyMalformedDestination
			}
			hasPort, portPart = true, tail[1:]
		}
	} else {
		colons := 0
		colonAt := -1
		for i := 0; i < len(authority); i++ {
			switch c := authority[i]; {
			case c == '[' || c == ']':
				return "", false, errPolicyMalformedDestination
			case c == ':':
				colons++
				colonAt = i
			}
		}
		if colons > 1 {
			return "", false, errPolicyMalformedDestination
		}
		host = authority
		if colons == 1 {
			host = authority[:colonAt]
			hasPort, portPart = true, authority[colonAt+1:]
		}
		if host == "" {
			return "", false, errPolicyMalformedDestination
		}
		for i := 0; i < len(host); i++ {
			c := host[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
			if !ok {
				return "", false, errPolicyMalformedDestination
			}
		}
	}
	if hasPort {
		if len(portPart) < 1 || len(portPart) > 5 {
			return "", false, errPolicyMalformedDestination
		}
		n := 0
		for i := 0; i < len(portPart); i++ {
			c := portPart[i]
			if c < '0' || c > '9' {
				return "", false, errPolicyMalformedDestination
			}
			n = n*10 + int(c-'0')
		}
		if n < 1 || n > 65535 {
			return "", false, errPolicyMalformedDestination
		}
	}
	return host, bracketed, nil
}

// errPolicyMalformedDestination is the port's internal refusal signal.
var errPolicyMalformedDestination = errors.New("userkey: url policy: malformed destination url")

// policyAsciiLower returns s with ASCII uppercase letters lowercased.
func policyAsciiLower(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	out := []byte(s)
	for i := 0; i < len(out); i++ {
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

func policyIsHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// policyIsLoopbackIPv4 reports whether host is canonical dotted-decimal IPv4 with exactly four octets 0..255, no leading zeros, and first octet exactly 127.
func policyIsLoopbackIPv4(host string) bool {
	octets := 0
	start := 0
	for i := 0; i <= len(host); i++ {
		if i < len(host) && host[i] != '.' {
			continue
		}
		part := host[start:i]
		if len(part) < 1 || len(part) > 3 || (len(part) > 1 && part[0] == '0') {
			return false
		}
		n := 0
		for j := 0; j < len(part); j++ {
			c := part[j]
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 || (octets == 0 && n != 127) {
			return false
		}
		octets++
		start = i + 1
	}
	return octets == 4
}

func valueLength(value any) int {
	switch v := value.(type) {
	case string:
		return len(v)
	case json.Number:
		return len(v)
	case nil:
		return 0
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return 0
		}
		return len(encoded)
	}
}

func transferError(class, member string, observed int) *jack.Error {
	message := class
	if member != "" {
		message += " member=" + member
	}
	message += " length=" + strconv.Itoa(observed)
	return &jack.Error{HTTPStatus: 0, Code: class, Message: message}
}

func isNilInterface(value any) bool {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// boundedSnapshot refuses oversized input BEFORE any proportional copy and
// returns an owned snapshot of bounded size for strict parsing. The limit
// check is O(1) on the caller's slice, so an arbitrarily large input is
// rejected without ever being duplicated.
func boundedSnapshot(data []byte) ([]byte, error) {
	if len(data) > maxTransferBytes {
		return nil, transferError(ClassOversizedEnvelope, "input", len(data))
	}
	return append([]byte(nil), data...), nil
}
