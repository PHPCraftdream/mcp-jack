package vectors_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/dsig"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/secret"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/vector"
)

func TestWebhookSignatureVectors(t *testing.T) {
	const name = "webhook-signature-vectors.json"
	const want = 45
	corpus := loadCorpus(t, name, want)
	keys := loadFixtureKeys(t)
	upstream := loadSignatureUpstream(t, name)
	checkCorpus(t, corpus, "webhook-signature", want, func(t *testing.T, c vector.Case) map[string]any {
		return runSignatureCase(t, c, keys, upstream[c.ID])
	})
}

type deliveryWire struct {
	WebhookID string          `json:"webhook_id"`
	Timestamp json.RawMessage `json:"webhook_timestamp"`
	BodyB64U  string          `json:"body_b64u"`
}

func (wire deliveryWire) timestamp(t *testing.T) int64 {
	t.Helper()
	ts, ok := vector.Int(wire.Timestamp)
	if !ok {
		t.Fatalf("webhook_timestamp must be an integer, got %s", wire.Timestamp)
	}
	return ts
}

type signatureWire struct {
	deliveryWire
	EndpointID string `json:"endpoint_id"`
}

func runSignatureCase(t *testing.T, c vector.Case, keys fixtureKeys, upstream signatureUpstream) map[string]any {
	t.Helper()
	switch c.Kind {
	case "secret":
		input := decodeJSON[struct {
			Value string `json:"value"`
		}](t, c.Input, "input")
		key, reason := secret.Parse(input.Value)
		if reason != "" {
			return map[string]any{"result": "reject", "code": "invalid_secret", "reason": reason}
		}
		return map[string]any{"result": "accept", "key_b64u": secret.EncodeURL(key)}
	case "kat-v1", "kat-v1a", "kat-v2a":
		return signatureKAT(t, c, keys)
	case "emission":
		return signatureEmission(t, c.Input, keys)
	case "verify":
		return decision(verifySignature(t, c.Input, keys))
	case "upstream-v2a", "upstream-combined":
		return checkSignatureUpstream(t, c, upstream)
	default:
		t.Fatalf("unknown case kind %q", c.Kind)
		return nil
	}
}

func signatureKAT(t *testing.T, c vector.Case, keys fixtureKeys) map[string]any {
	t.Helper()
	input := decodeJSON[struct {
		signatureWire
		Secret string `json:"secret"`
		Key    string `json:"key"`
	}](t, c.Input, "input")
	id, ts, body := input.WebhookID, strconv.FormatInt(input.timestamp(t), 10), decodeBody(t, input.BodyB64U)
	var signature string
	var content []byte
	var err error
	switch c.Kind {
	case "kat-v1":
		signature = dsig.V1Sign(parseFixtureSecret(t, input.Secret), id, ts, body)
		content = dsig.V1Content(id, ts, body)
	case "kat-v1a":
		signature, err = dsig.V1aSign(keys.named(t, input.Key).private, id, ts, body)
		content = dsig.V1aContent(id, ts, body)
	case "kat-v2a":
		signature, err = dsig.V2aSign(keys.named(t, input.Key).private, input.EndpointID, id, ts, body)
		content = dsig.V2aDigest(input.EndpointID, id, ts, body)
	}
	if err != nil {
		t.Fatalf("sign %s: %v", c.Kind, err)
	}
	return map[string]any{"result": "accept", "signature": signature, "content_b64u": secret.EncodeURL(content)}
}

func signatureEmission(t *testing.T, raw json.RawMessage, keys fixtureKeys) map[string]any {
	t.Helper()
	input := decodeJSON[struct {
		signatureWire
		Secrets []struct {
			Secret  string `json:"secret"`
			Current bool   `json:"current"`
		} `json:"secrets"`
		Keys []struct {
			Key     string `json:"key"`
			Current bool   `json:"current"`
		} `json:"keys"`
	}](t, raw, "input")
	options := dsig.Emission{
		WebhookID:  input.WebhookID,
		Timestamp:  strconv.FormatInt(input.timestamp(t), 10),
		EndpointID: input.EndpointID,
		Body:       decodeBody(t, input.BodyB64U),
	}
	for _, entry := range input.Secrets {
		options.Secrets = append(options.Secrets, dsig.EmissionSecret{
			Secret: parseFixtureSecret(t, entry.Secret), Current: entry.Current,
		})
	}
	for _, entry := range input.Keys {
		key := keys.named(t, entry.Key)
		options.Keys = append(options.Keys, dsig.EmissionKey{
			Key: key.private, KID: key.public.KID, Current: entry.Current,
		})
	}
	header, err := dsig.EmissionHeader(options)
	if err != nil {
		t.Fatalf("emit signature header: %v", err)
	}
	entries, code := dsig.ParseHeader(header)
	if code != "" {
		t.Fatalf("emitted header %q does not parse: %s", header, code)
	}
	schemes := make([]string, 0, len(entries))
	for _, entry := range entries {
		schemes = append(schemes, entry.Scheme)
	}
	return map[string]any{"result": "accept", "header": header, "schemes": schemes}
}

func verifySignature(t *testing.T, raw json.RawMessage, keys fixtureKeys) string {
	t.Helper()
	input := decodeJSON[struct {
		Envelope struct {
			signatureWire
			SignatureHeader string `json:"signature_header"`
		} `json:"envelope"`
		Secrets []string `json:"secrets"`
		Keys    []string `json:"keys"`
		Now     int64    `json:"now"`
		Window  int64    `json:"window"`
		Enforce string   `json:"enforce"`
	}](t, raw, "input")
	envelope := input.Envelope
	entries, code := dsig.ParseHeader(envelope.SignatureHeader)
	if code != "" {
		return code
	}
	if code := dsig.CheckSchemes(entries); code != "" {
		return code
	}
	entries, code = dsig.DecodeValues(entries)
	if code != "" {
		return code
	}

	timestamp := envelope.timestamp(t)
	id, ts, body := envelope.WebhookID, strconv.FormatInt(timestamp, 10), decodeBody(t, envelope.BodyB64U)
	var matched bool
	for _, value := range input.Secrets {
		key := parseFixtureSecret(t, value)
		if _, matched = dsig.VerifyV1(entries, [][]byte{key}, id, ts, body); matched {
			break
		}
	}
	if !matched {
		return "bad_signature"
	}
	if input.Now-timestamp > input.Window {
		return "stale_timestamp"
	}
	if timestamp-input.Now > input.Window {
		return "future_timestamp"
	}
	if input.Enforce == "server" {
		if len(input.Keys) == 0 {
			return "no_server_keys"
		}
		_, code := dsig.VerifyAsym(entries, keys.accepted(t, input.Keys), envelope.EndpointID, id, ts, body)
		return code
	}
	return ""
}

type signatureUpstream struct {
	PublicKey    string `json:"public_key"`
	SHA256Base64 string `json:"sha256_base64"`
	Signature    string `json:"signature"`
	Header       string `json:"header"`
}

// vector.Case does not retain upstream literals; read those fields by case ID.
func loadSignatureUpstream(t *testing.T, name string) map[string]signatureUpstream {
	t.Helper()
	fields := readFixtureJSON[struct {
		Cases []struct {
			ID       string             `json:"id"`
			Upstream *signatureUpstream `json:"upstream"`
		} `json:"cases"`
	}](t, vector.RepoPath("spec", "fixtures", "modern", name))
	byID := make(map[string]signatureUpstream)
	for _, c := range fields.Cases {
		if c.Upstream != nil {
			byID[c.ID] = *c.Upstream
		}
	}
	return byID
}

func checkSignatureUpstream(t *testing.T, c vector.Case, upstream signatureUpstream) map[string]any {
	t.Helper()
	input := decodeJSON[struct {
		signatureWire
		PrivateKey string `json:"private_key"`
	}](t, c.Input, "input")
	encoded, ok := strings.CutPrefix(input.PrivateKey, "whsk_")
	if !ok {
		t.Fatal("input.private_key is missing the whsk_ prefix")
	}
	seed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode input.private_key: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("input.private_key seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	key := ed25519.NewKeyFromSeed(seed)
	id, ts, body := input.WebhookID, strconv.FormatInt(input.timestamp(t), 10), decodeBody(t, input.BodyB64U)
	v2a, err := dsig.V2aSign(key, input.EndpointID, id, ts, body)
	if err != nil {
		t.Fatalf("sign upstream v2a: %v", err)
	}
	if c.Kind == "upstream-combined" {
		entries := strings.Split(upstream.Header, " ")
		if len(entries) < 2 {
			t.Fatalf("upstream.header is missing its v2a entry: %q", upstream.Header)
		}
		if v2a != entries[1] {
			t.Fatalf("upstream.header v2a entry: got %q, want %q", v2a, entries[1])
		}
		return map[string]any{"result": "accept", "v1_literal": entries[0], "v2a": v2a}
	}

	public := key.Public().(ed25519.PublicKey)
	digest := dsig.V2aDigest(input.EndpointID, id, ts, body)
	for _, check := range []struct{ field, got, want string }{
		{"public_key", "whpk_" + base64.StdEncoding.EncodeToString(public), upstream.PublicKey},
		{"sha256_base64", base64.StdEncoding.EncodeToString(digest), upstream.SHA256Base64},
		{"signature", v2a, upstream.Signature},
	} {
		if check.got != check.want {
			t.Fatalf("upstream.%s: got %q, want %q", check.field, check.got, check.want)
		}
	}
	return decision("")
}

func loadCorpus(t *testing.T, name string, want int) vector.Corpus {
	t.Helper()
	corpus, err := vector.Load(name)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	vector.Expect(t, corpus, want, name)
	return corpus
}

func checkCorpus(t *testing.T, corpus vector.Corpus, label string, want int, run func(*testing.T, vector.Case) map[string]any) {
	t.Helper()
	pass := 0
	for _, c := range corpus.Cases {
		if t.Run(c.ID, func(t *testing.T) {
			got := run(t, c)
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal result: %v", err)
			}
			actual := decodeJSON[any](t, gotJSON, "result")
			expected := decodeJSON[any](t, c.Expect, "expect")
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("%s: got %s, want %s", c.ID, gotJSON, c.Expect)
			}
		}) {
			pass++
		}
	}
	if pass != want {
		t.Errorf("%s: got %d passing cases, want %d", label, pass, want)
	}
	vector.Summary(t, label, pass, 0, 0)
}

func decision(code string) map[string]any {
	if code != "" {
		return map[string]any{"result": "reject", "code": code}
	}
	return map[string]any{"result": "accept"}
}

func decodeJSON[T any](t *testing.T, raw []byte, label string) T {
	t.Helper()
	var decoded T
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode %s: %v", label, err)
	}
	return decoded
}

func readFixtureJSON[T any](t *testing.T, path string) T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %q: %v", path, err)
	}
	return decodeJSON[T](t, data, path)
}

func decodeBody(t *testing.T, encoded string) []byte {
	t.Helper()
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode body_b64u: %v", err)
	}
	return body
}

func parseFixtureSecret(t *testing.T, value string) []byte {
	t.Helper()
	key, reason := secret.Parse(value)
	if reason != "" {
		t.Fatalf("invalid fixture secret: %s", reason)
	}
	return key
}

type fixtureKey struct {
	private ed25519.PrivateKey
	public  dsig.AsymKey
}

type fixtureKeys map[string]fixtureKey

func loadFixtureKeys(t *testing.T) fixtureKeys {
	t.Helper()
	fixture := readFixtureJSON[struct {
		Keys []struct {
			Name      string `json:"name"`
			SeedHex   string `json:"seed_hex"`
			PublicKey string `json:"public_key"`
			KID       string `json:"kid"`
		} `json:"keys"`
	}](t, vector.RepoPath("spec", "fixtures", "keys.json"))
	keys := make(fixtureKeys, len(fixture.Keys))
	for _, entry := range fixture.Keys {
		seed, err := hex.DecodeString(entry.SeedHex)
		if err != nil {
			t.Fatalf("decode %q seed_hex: %v", entry.Name, err)
		}
		if len(seed) != ed25519.SeedSize {
			t.Fatalf("%q seed is %d bytes, want %d", entry.Name, len(seed), ed25519.SeedSize)
		}
		private := ed25519.NewKeyFromSeed(seed)
		public := private.Public().(ed25519.PublicKey)
		if got := secret.EncodeURL(public); got != entry.PublicKey {
			t.Fatalf("%q public_key: got %q, want %q", entry.Name, got, entry.PublicKey)
		}
		keys[entry.Name] = fixtureKey{private: private, public: dsig.AsymKey{KID: entry.KID, Raw: public}}
	}
	return keys
}

func (keys fixtureKeys) named(t *testing.T, name string) fixtureKey {
	t.Helper()
	key, ok := keys[name]
	if !ok {
		t.Fatalf("unknown fixture key %q", name)
	}
	return key
}

func (keys fixtureKeys) accepted(t *testing.T, names []string) []dsig.AsymKey {
	t.Helper()
	accepted := make([]dsig.AsymKey, 0, len(names))
	for _, name := range names {
		accepted = append(accepted, keys.named(t, name).public)
	}
	return accepted
}
