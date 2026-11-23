package dsig

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
)

// Signature schemes, content lengths and receiver codes of
// spec/06-webhooks.md sections 2 and 3.
const (
	schemeV1  = "v1"
	schemeV1a = "v1a"
	schemeV2a = "v2a"

	// sigLenHMAC is the decoded length of a v1 entry (R2.2).
	sigLenHMAC = 32
	// sigLenAsym is the decoded length of a v1a or v2a entry (R2.5, R2.6).
	sigLenAsym = ed25519.SignatureSize

	codeMalformedSignatureHeader = "malformed_signature_header"
	codeUnsupportedScheme        = "unsupported_signature_scheme"
	codeMalformedSignature       = "malformed_signature"
	codeBadServerSignature       = "bad_server_signature"

	separator = "."
)

// dotContent returns prefix, one '.' and body as one byte slice (R2.2, R2.3).
func dotContent(prefix string, body []byte) []byte {
	out := make([]byte, 0, len(prefix)+1+len(body))
	out = append(out, prefix...)
	out = append(out, '.')
	out = append(out, body...)
	return out
}

// hmacSHA256 returns HMAC-SHA256(key, message).
func hmacSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// checkPrivateKey reports an error unless key is a full 64-byte Ed25519
// private key, so that signing never panics on a zero or truncated key.
func checkPrivateKey(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("dsig: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
	}
	return nil
}

// V1Content returns the bytes v1 signs (R2.2): the UTF-8 bytes of
// webhook-id "." webhook-timestamp "." followed by the raw body bytes, which
// are never parsed, re-serialized or normalized (R2.3).
func V1Content(webhookID, timestamp string, body []byte) []byte {
	return dotContent(webhookID+separator+timestamp, body)
}

// V1Sign returns the v1 header entry, "v1," followed by canonical padded
// standard base64 of HMAC-SHA256(secret, V1Content(...)) (R2.2).
func V1Sign(secret []byte, webhookID, timestamp string, body []byte) string {
	return schemeV1 + "," + b64StdEncode(hmacSHA256(secret, V1Content(webhookID, timestamp, body)))
}

// V1aContent returns the bytes v1a signs (R2.5): the same raw content as V1,
// with no hash and no endpoint id.
func V1aContent(webhookID, timestamp string, body []byte) []byte {
	return V1Content(webhookID, timestamp, body)
}

// V1aSign returns the v1a header entry, "v1a," followed by canonical padded
// standard base64 of the Ed25519 signature over V1aContent (R2.5).
func V1aSign(key ed25519.PrivateKey, webhookID, timestamp string, body []byte) (string, error) {
	if err := checkPrivateKey(key); err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, V1aContent(webhookID, timestamp, body))
	return schemeV1a + "," + b64StdEncode(sig), nil
}

// V2aDigest returns the 32-byte SHA-256 digest v2a signs (R2.6) over the bytes
// endpoint-id "." webhook-id "." webhook-timestamp "." raw body.
func V2aDigest(endpointID, webhookID, timestamp string, body []byte) []byte {
	return sha256Sum(dotContent(endpointID+separator+webhookID+separator+timestamp, body))
}

// V2aSign returns the v2a header entry, "v2a," followed by canonical padded
// standard base64 of the Ed25519 signature over V2aDigest (R2.6).
func V2aSign(key ed25519.PrivateKey, endpointID, webhookID, timestamp string, body []byte) (string, error) {
	if err := checkPrivateKey(key); err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, V2aDigest(endpointID, webhookID, timestamp, body))
	return schemeV2a + "," + b64StdEncode(sig), nil
}

// Entry is one parsed <scheme>,<value> pair of a webhook-signature header
// (R2.4). Sig holds the decoded signature bytes after DecodeValues.
type Entry struct {
	Scheme string
	Value  string
	Sig    []byte
}

// ParseHeader splits a webhook-signature header value into its entries without
// decoding any value (R2.4). It returns "" on success, or
// "malformed_signature_header" for an empty value, leading or trailing
// whitespace, an empty entry, an entry without a scheme or without a value, a
// scheme outside [A-Za-z0-9]+, or a value containing a comma or whitespace.
// Unknown schemes are preserved for CheckSchemes.
func ParseHeader(value string) ([]Entry, string) {
	if value == "" {
		return nil, codeMalformedSignatureHeader
	}
	if hasLeadingJSSpace(value) || hasTrailingJSSpace(value) {
		return nil, codeMalformedSignatureHeader
	}
	parts := strings.Split(value, " ")
	entries := make([]Entry, 0, len(parts))
	for _, part := range parts {
		if part == "" || hasJSSpace(part) {
			return nil, codeMalformedSignatureHeader
		}
		comma := strings.IndexByte(part, ',')
		if comma <= 0 || comma == len(part)-1 {
			return nil, codeMalformedSignatureHeader
		}
		scheme := part[:comma]
		entryValue := part[comma+1:]
		if !isASCIIAlnum(scheme) || strings.IndexByte(entryValue, ',') >= 0 || hasJSSpace(entryValue) {
			return nil, codeMalformedSignatureHeader
		}
		entries = append(entries, Entry{Scheme: scheme, Value: entryValue})
	}
	return entries, ""
}

// CheckSchemes reports whether every scheme is v1, v1a or v2a (R3.11). It
// returns "" on success, "unsupported_signature_scheme" otherwise, and "" for
// an empty entry list.
func CheckSchemes(entries []Entry) string {
	for _, entry := range entries {
		switch entry.Scheme {
		case schemeV1, schemeV1a, schemeV2a:
		default:
			return codeUnsupportedScheme
		}
	}
	return ""
}

// DecodeValues strictly decodes every entry value (R3.12) and returns copies
// with Sig filled. It returns "" on success, or "malformed_signature" when a
// value is not canonical padded standard base64 or does not decode to exactly
// 32 bytes for v1 and 64 bytes for any other scheme. The input is not modified.
func DecodeValues(entries []Entry) ([]Entry, string) {
	out := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		sig, ok := b64StdDecodeStrict(entry.Value)
		if !ok {
			return nil, codeMalformedSignature
		}
		want := sigLenAsym
		if entry.Scheme == schemeV1 {
			want = sigLenHMAC
		}
		if len(sig) != want {
			return nil, codeMalformedSignature
		}
		out = append(out, Entry{Scheme: entry.Scheme, Value: entry.Value, Sig: sig})
	}
	return out, ""
}

// VerifyV1 returns the index of the first secret in secrets for which some v1
// entry equals HMAC-SHA256(secret, V1Content(...)), comparing the decoded
// 32 bytes in constant time (R2.7, R3.13). It returns (-1, false) when no
// secret matches; v1a and v2a entries are ignored.
func VerifyV1(entries []Entry, secrets [][]byte, webhookID, timestamp string, body []byte) (int, bool) {
	content := V1Content(webhookID, timestamp, body)
	for i, secret := range secrets {
		mac := hmacSHA256(secret, content)
		for _, entry := range entries {
			if entry.Scheme != schemeV1 || len(entry.Sig) != len(mac) {
				continue
			}
			if subtle.ConstantTimeCompare(entry.Sig, mac) == 1 {
				return i, true
			}
		}
	}
	return -1, false
}

// AsymKey is one accepted webhook signing key (R4.5): KID is the base64url
// SHA-256 of Raw, the raw 32-byte Ed25519 public key.
type AsymKey struct {
	KID string
	Raw []byte
}

// VerifyAsym accepts an asymmetric signature when some v1a or v2a entry
// verifies under some accepted key (R2.7, R3.14). Keys are tried in order and,
// for each key, entries in order; the matching key and "" are returned. It
// returns the zero AsymKey and "bad_server_signature" when no entry verifies,
// when every key is unusable, and also when no v1a or v2a entry is present.
func VerifyAsym(entries []Entry, keys []AsymKey, endpointID, webhookID, timestamp string, body []byte) (AsymKey, string) {
	asym := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.Scheme == schemeV1a || entry.Scheme == schemeV2a {
			asym = append(asym, entry)
		}
	}
	if len(asym) == 0 {
		return AsymKey{}, codeBadServerSignature
	}
	v1aMessage := V1aContent(webhookID, timestamp, body)
	v2aMessage := V2aDigest(endpointID, webhookID, timestamp, body)
	for _, key := range keys {
		if len(key.Raw) != ed25519.PublicKeySize {
			continue
		}
		public := ed25519.PublicKey(key.Raw)
		for _, entry := range asym {
			if len(entry.Sig) != ed25519.SignatureSize {
				continue
			}
			message := v1aMessage
			if entry.Scheme == schemeV2a {
				message = v2aMessage
			}
			if ed25519.Verify(public, message, entry.Sig) {
				return key, ""
			}
		}
	}
	return AsymKey{}, codeBadServerSignature
}

// EmissionSecret is one registered webhook secret for a subscription.
type EmissionSecret struct {
	Secret  []byte
	Current bool
}

// EmissionKey is one webhook signing key with its kid. Current selects the key
// group of the emission order.
type EmissionKey struct {
	Key     ed25519.PrivateKey
	KID     string
	Current bool
}

// Emission describes one delivery to sign (R2.8).
type Emission struct {
	WebhookID  string
	Timestamp  string
	EndpointID string
	Body       []byte
	Secrets    []EmissionSecret
	Keys       []EmissionKey
}

// EmissionHeader renders the emission set of R2.8 as one space-delimited
// header value: the current secret's v1 entry, the previous secret's v1 entry,
// then the current key's v1a and v2a entries, then the previous key's v1a and
// v2a entries. "Current" means the first entry with Current true and
// "previous" the first entry with Current false; a group with no such entry is
// omitted, and no empty entry is ever emitted. A key whose private key is not a
// 64-byte Ed25519 key is an error.
func EmissionHeader(opts Emission) (string, error) {
	for _, key := range opts.Keys {
		if err := checkPrivateKey(key.Key); err != nil {
			return "", err
		}
	}
	entries := make([]string, 0, 6)
	if secret, ok := selectSecret(opts.Secrets, true); ok {
		entries = append(entries, V1Sign(secret, opts.WebhookID, opts.Timestamp, opts.Body))
	}
	if secret, ok := selectSecret(opts.Secrets, false); ok {
		entries = append(entries, V1Sign(secret, opts.WebhookID, opts.Timestamp, opts.Body))
	}
	if key, ok := selectKey(opts.Keys, true); ok {
		pair, err := emissionPair(key, opts)
		if err != nil {
			return "", err
		}
		entries = append(entries, pair...)
	}
	if key, ok := selectKey(opts.Keys, false); ok {
		pair, err := emissionPair(key, opts)
		if err != nil {
			return "", err
		}
		entries = append(entries, pair...)
	}
	return strings.Join(entries, " "), nil
}

// selectSecret returns the first secret whose Current equals current.
func selectSecret(secrets []EmissionSecret, current bool) ([]byte, bool) {
	for _, secret := range secrets {
		if secret.Current == current {
			return secret.Secret, true
		}
	}
	return nil, false
}

// selectKey returns the first key whose Current equals current.
func selectKey(keys []EmissionKey, current bool) (EmissionKey, bool) {
	for _, key := range keys {
		if key.Current == current {
			return key, true
		}
	}
	return EmissionKey{}, false
}

// emissionPair returns the v1a then v2a entry of one signing key (R2.8).
func emissionPair(key EmissionKey, opts Emission) ([]string, error) {
	v1a, err := V1aSign(key.Key, opts.WebhookID, opts.Timestamp, opts.Body)
	if err != nil {
		return nil, err
	}
	v2a, err := V2aSign(key.Key, opts.EndpointID, opts.WebhookID, opts.Timestamp, opts.Body)
	if err != nil {
		return nil, err
	}
	return []string{v1a, v2a}, nil
}
