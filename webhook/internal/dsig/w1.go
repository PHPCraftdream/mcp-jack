package dsig

import (
	"crypto/ed25519"
	"strconv"
	"strings"
)

// Jack w1 signature constants and receiver codes of spec/06-webhooks.md
// section 4.
const (
	w1Scheme    = "w1"
	w1FirstLine = "mcp-jack/webhook1/delivery"

	// w1KidLen and w1SigLen are the fixed character counts of R4.1.
	w1KidLen = 43
	w1SigLen = 86

	codeMalformedJackAuth = "malformed_jack_auth"
	codeServerKeyKID      = "webhook_key_is_server_key"
	codeUnknownWebhookKey = "unknown_webhook_key"
	codeJackOutOfWindow   = "jack_timestamp_out_of_window"
	codeBadJackSignature  = "bad_jack_signature"
)

// W1Parts holds the seven signing-string inputs of R4.2 exactly as they go on
// the wire: Aud is the receiver-configured audience, SubscriptionID the
// X-MCP-Subscription-Id value, WebhookID and Timestamp the webhook headers as
// sent, CallbackURL the delivery url as stored, and Body the raw body bytes.
// Nothing is normalized (R4.3).
type W1Parts struct {
	Aud            string
	SubscriptionID string
	WebhookID      string
	Timestamp      string
	CallbackURL    string
	Body           []byte
}

// W1SigningString returns the seven LF-joined lines of the w1 signing string
// with no trailing LF (R4.2): the literal "mcp-jack/webhook1/delivery", then
// Aud, SubscriptionID, WebhookID, Timestamp, CallbackURL and
// base64url(SHA-256(body)).
func W1SigningString(p W1Parts) string {
	return strings.Join([]string{
		w1FirstLine,
		p.Aud,
		p.SubscriptionID,
		p.WebhookID,
		p.Timestamp,
		p.CallbackURL,
		b64URLEncode(sha256Sum(p.Body)),
	}, "\n")
}

// W1HeaderValue renders the Jack-Webhook-Auth header value "w1 kid=<kid>,sig=<sig>"
// (R4.1). It does not validate the parameters; ParseW1Header is the parser.
func W1HeaderValue(kid, sig string) string {
	return w1Scheme + " kid=" + kid + ",sig=" + sig
}

// W1Sign returns the Jack-Webhook-Auth header value of one delivery (R4.2):
// the unpadded base64url Ed25519 signature over W1SigningString, rendered by
// W1HeaderValue. A key whose private key is not a 64-byte Ed25519 key is an
// error.
func W1Sign(key ed25519.PrivateKey, kid string, p W1Parts) (string, error) {
	if err := checkPrivateKey(key); err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, []byte(W1SigningString(p)))
	return W1HeaderValue(kid, b64URLEncode(sig)), nil
}

// ParseW1Header parses the Jack-Webhook-Auth value (R4.1). It succeeds only for
// the literal "w1" followed by exactly one space and comma-separated
// parameters with no whitespace anywhere, holding exactly "kid" and "sig" once
// each in either order, with values of [A-Za-z0-9_-]+ where kid is 43 and sig
// 86 characters. Anything else reports ok false.
func ParseW1Header(value string) (kid, sig string, ok bool) {
	prefix := w1Scheme + " "
	if !strings.HasPrefix(value, prefix) {
		return "", "", false
	}
	rest := value[len(prefix):]
	if rest == "" || hasJSSpace(rest) {
		return "", "", false
	}
	params := make(map[string]string, 2)
	for _, part := range strings.Split(rest, ",") {
		if part == "" {
			return "", "", false
		}
		eq := strings.IndexByte(part, '=')
		if eq <= 0 || eq == len(part)-1 {
			return "", "", false
		}
		name := part[:eq]
		paramValue := part[eq+1:]
		if name != "kid" && name != "sig" {
			return "", "", false
		}
		if _, duplicate := params[name]; duplicate {
			return "", "", false
		}
		if !isURLAlnum(paramValue) {
			return "", "", false
		}
		params[name] = paramValue
	}
	kid, hasKid := params["kid"]
	sig, hasSig := params["sig"]
	if !hasKid || !hasSig || len(kid) != w1KidLen || len(sig) != w1SigLen {
		return "", "", false
	}
	return kid, sig, true
}

// W1Keys is the receiver configuration and clock W1Verify needs: the accepted
// webhook signing keys, the current time in Unix seconds, the Jack window in
// seconds and the configured MCP server key id, which the empty string leaves
// unset (R4.4, R4.5).
type W1Keys struct {
	Keys         []AsymKey
	Now          int64
	Window       int64
	MCPServerKID string
}

// W1Verify verifies a Jack-Webhook-Auth header in exactly the reference order
// (R3.15, R4.4, R4.5): a header outside the grammar is "malformed_jack_auth"; a
// kid equal to the configured MCPServerKID, when one is configured, is
// "webhook_key_is_server_key"; a kid outside Keys is "unknown_webhook_key"; a
// Timestamp that does not parse or whose distance from Now exceeds Window is
// "jack_timestamp_out_of_window"; a signature that is not canonical unpadded
// base64url of 64 bytes or does not verify is "bad_jack_signature". It returns
// the kid and "" on success.
func W1Verify(headerValue string, p W1Parts, opts W1Keys) (kid, code string) {
	kid, sig, ok := ParseW1Header(headerValue)
	if !ok {
		return "", codeMalformedJackAuth
	}
	if opts.MCPServerKID != "" && kid == opts.MCPServerKID {
		return "", codeServerKeyKID
	}
	var key AsymKey
	found := false
	for _, candidate := range opts.Keys {
		if candidate.KID == kid {
			key, found = candidate, true
			break
		}
	}
	if !found {
		return "", codeUnknownWebhookKey
	}
	timestamp, err := strconv.ParseInt(p.Timestamp, 10, 64)
	if err != nil || opts.Window < 0 || absDiffUint64(opts.Now, timestamp) > uint64(opts.Window) {
		return "", codeJackOutOfWindow
	}
	sigBytes, ok := b64URLDecodeStrict(sig)
	if !ok || len(key.Raw) != ed25519.PublicKeySize {
		return "", codeBadJackSignature
	}
	if !ed25519.Verify(ed25519.PublicKey(key.Raw), []byte(W1SigningString(p)), sigBytes) {
		return "", codeBadJackSignature
	}
	return kid, ""
}

// absDiffUint64 returns |a-b| without overflowing for any two int64 values.
func absDiffUint64(a, b int64) uint64 {
	if a >= b {
		return uint64(a) - uint64(b)
	}
	return uint64(b) - uint64(a)
}
