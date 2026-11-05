// Package spec embeds the normative conformance fixtures and exposes typed,
// strict loaders for them. The JSON files under spec/fixtures are the source
// of truth for SDK conformance; their shapes are described in
// spec/tests/README.md.
package spec

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

//go:embed fixtures/*.json
var fixtures embed.FS

// decodeFixture decodes one embedded fixture strictly: unknown fields and
// trailing data are load errors, so a fixture field without a Go field fails
// loudly instead of being ignored.
func decodeFixture(name string, v any) error {
	f, err := fixtures.Open("fixtures/" + name)
	if err != nil {
		return fmt.Errorf("fixture %s: %w", name, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("fixture %s: %w", name, err)
	}
	var extra json.RawMessage
	switch err := dec.Decode(&extra); err {
	case io.EOF:
		return nil
	case nil:
		return fmt.Errorf("fixture %s: trailing data after the JSON document", name)
	default:
		return fmt.Errorf("fixture %s: trailing data: %w", name, err)
	}
}

// TestKey is one entry of keys.json. Test only: seeds are derived from public strings.
type TestKey struct {
	Name      string `json:"name"`
	SeedHex   string `json:"seed_hex"`
	PublicKey string `json:"public_key"`
	Kid       string `json:"kid"`
}

// KeyFile is keys.json.
type KeyFile struct {
	Note string    `json:"note"`
	Keys []TestKey `json:"keys"`
}

// RegistryEntry is one key of a registry document. Kind, NotBefore and
// NotAfter are pointers because documents may omit them (then they default)
// and the JSON uses null for unbounded validity.
type RegistryEntry struct {
	Kid       string   `json:"kid"`
	PublicKey string   `json:"public_key"`
	Name      string   `json:"name"`
	Kind      *string  `json:"kind,omitempty"`
	Scopes    []string `json:"scopes"`
	NotBefore *int64   `json:"not_before,omitempty"`
	NotAfter  *int64   `json:"not_after,omitempty"`
}

// RegistryDocument is registry.json.
type RegistryDocument struct {
	Version int             `json:"version"`
	Aud     string          `json:"aud"`
	Keys    []RegistryEntry `json:"keys"`
}

// PolicyMatch selects requests by JSON-RPC method and, for tools/call, tool name.
type PolicyMatch struct {
	Method string `json:"method"`
	Tool   string `json:"tool,omitempty"`
}

// PolicyRule is one first-match-wins rule. Scope is nil for JSON null ("any
// authenticated key") and for deny rules, which carry no scope; this typed form
// only holds valid documents, so load-time validation, which must tell a null
// scope from a missing one, works on raw JSON (see LoadCase).
type PolicyRule struct {
	Match  PolicyMatch `json:"match"`
	Scope  *string     `json:"scope,omitempty"`
	Effect string      `json:"effect,omitempty"`
}

// PolicyDocument is policy.json / policy-wildcard.json.
type PolicyDocument struct {
	Version int          `json:"version"`
	Rules   []PolicyRule `json:"rules"`
}

// HeaderPair is one [name, value] pair; the list form keeps repeated headers
// representable.
type HeaderPair struct {
	Name  string
	Value string
}

// UnmarshalJSON decodes a two-element array of strings and rejects anything
// else, including null elements (decoding null into a string would silently
// yield "").
func (h *HeaderPair) UnmarshalJSON(b []byte) error {
	var pair []*string
	if err := json.Unmarshal(b, &pair); err != nil {
		return fmt.Errorf("header pair must be [name, value]: %w", err)
	}
	if len(pair) != 2 {
		return fmt.Errorf("header pair must have exactly 2 elements, got %d", len(pair))
	}
	if pair[0] == nil || pair[1] == nil {
		return fmt.Errorf("header pair elements must be strings, got null")
	}
	h.Name, h.Value = *pair[0], *pair[1]
	return nil
}

// MarshalJSON re-emits the [name, value] array form.
func (h HeaderPair) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string{h.Name, h.Value})
}

// DecodeB64U decodes an unpadded base64url string (bodies, keys, signatures).
func DecodeB64U(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// NonceCacheEntry is a pre-seeded (kid, nonce) cache entry in a case state.
type NonceCacheEntry struct {
	Kid         string `json:"kid"`
	Nonce       string `json:"nonce"`
	RetainUntil int64  `json:"retain_until"`
}

// RequestState is the per-case state of request vectors.
type RequestState struct {
	Now           int64             `json:"now"`
	WindowSeconds int               `json:"window_seconds"`
	Aud           string            `json:"aud"`
	Policy        string            `json:"policy"`
	NonceCache    []NonceCacheEntry `json:"nonce_cache"`
}

// FixtureRequest is the HTTP request under test. BodyText is informative only;
// BodyB64U is the exact signed bytes.
type FixtureRequest struct {
	Method   string       `json:"method"`
	Target   string       `json:"target"`
	Headers  []HeaderPair `json:"headers"`
	BodyB64U string       `json:"body_b64u"`
	BodyText string       `json:"body_text,omitempty"`
}

// Body decodes the request body bytes.
func (r FixtureRequest) Body() ([]byte, error) { return DecodeB64U(r.BodyB64U) }

// AuditExpect is the expected audit record for protocol-native tool calls.
type AuditExpect struct {
	Tool     string  `json:"tool"`
	Outcome  string  `json:"outcome"`
	Code     *string `json:"code"`
	ActorKid string  `json:"actor_kid"`
}

// UserSummary is one entry of an after.users expectation.
type UserSummary struct {
	Name      string   `json:"name"`
	Kid       string   `json:"kid"`
	Kind      string   `json:"kind"`
	Scopes    []string `json:"scopes"`
	NotBefore *int64   `json:"not_before,omitempty"`
	NotAfter  *int64   `json:"not_after,omitempty"`
}

// AfterState summarizes the sequence state after a step ran.
type AfterState struct {
	Users   []UserSummary `json:"users"`
	Invites int           `json:"invites"`
}

// Expect is the shared outcome expectation. Structured stays raw JSON: its
// shape varies per protocol-native tool and expectations embed the
// "<b64u43>" placeholder, which is a runner-side wildcard.
type Expect struct {
	Result        string          `json:"result"`
	Kid           string          `json:"kid,omitempty"`
	Structured    json.RawMessage `json:"structured,omitempty"`
	HTTPStatus    int             `json:"http_status,omitempty"`
	Code          string          `json:"code,omitempty"`
	Audit         *AuditExpect    `json:"audit,omitempty"`
	NonceRecorded bool            `json:"nonce_recorded,omitempty"`
	After         *AfterState     `json:"after,omitempty"`
}

// Debug carries the signing string the generator signed, line by line. In
// tamper cases it differs from what a verifier recomputes; that is the point.
type Debug struct {
	SigningStringLines []string `json:"signing_string_lines"`
}

// RequestCase is one single-request vector.
type RequestCase struct {
	ID          string         `json:"id"`
	Description string         `json:"description,omitempty"`
	State       RequestState   `json:"state"`
	Request     FixtureRequest `json:"request"`
	Expect      Expect         `json:"expect"`
	Debug       Debug          `json:"debug"`
}

// RequestVectors is request-vectors.json; Policies maps a case's state.policy
// name to the file that holds it.
type RequestVectors struct {
	Registry string            `json:"registry"`
	Policies map[string]string `json:"policies"`
	Cases    []RequestCase     `json:"cases"`
}

// InviteRecord is a stored invite in a sequence state. KeyTTLSeconds is null
// when the enrolled key never expires.
type InviteRecord struct {
	InviteID      string   `json:"invite_id"`
	Scopes        []string `json:"scopes"`
	Kind          *string  `json:"kind,omitempty"`
	CreatedBy     string   `json:"created_by"`
	CreatedAt     int64    `json:"created_at"`
	ExpiresAt     int64    `json:"expires_at"`
	KeyTTLSeconds *int64   `json:"key_ttl_seconds,omitempty"`
}

// SequenceState is the initial state of an admin sequence case.
type SequenceState struct {
	RequestState
	Registry []RegistryEntry `json:"registry"`
	Invites  []InviteRecord  `json:"invites"`
}

// Step is one request of a sequence; steps share state in order.
type Step struct {
	Request FixtureRequest `json:"request"`
	Expect  Expect         `json:"expect"`
	Debug   Debug          `json:"debug"`
}

// AdminCase is one ordered sequence of state-changing requests.
type AdminCase struct {
	ID          string        `json:"id"`
	Description string        `json:"description,omitempty"`
	State       SequenceState `json:"state"`
	Steps       []Step        `json:"steps"`
}

// AdminVectors is admin-vectors.json.
type AdminVectors struct {
	Cases []AdminCase `json:"cases"`
}

// ResponseState is the per-case state of response vectors.
type ResponseState struct {
	Now                   int64  `json:"now"`
	WindowSeconds         int    `json:"window_seconds"`
	PinnedServerKid       string `json:"pinned_server_kid"`
	PinnedServerPublicKey string `json:"pinned_server_public_key"`
	RequestSig            string `json:"request_sig"`
}

// FixtureResponse is the signed response under test.
type FixtureResponse struct {
	Status   int          `json:"status"`
	Headers  []HeaderPair `json:"headers"`
	BodyB64U string       `json:"body_b64u"`
	BodyText string       `json:"body_text,omitempty"`
}

// Body decodes the response body bytes.
func (r FixtureResponse) Body() ([]byte, error) { return DecodeB64U(r.BodyB64U) }

// ResponseExpect is the outcome expectation of a response case.
type ResponseExpect struct {
	Result string `json:"result"`
	Code   string `json:"code,omitempty"`
}

// ResponseCase is one client-side response verification vector.
type ResponseCase struct {
	ID          string          `json:"id"`
	Description string          `json:"description,omitempty"`
	State       ResponseState   `json:"state"`
	Response    FixtureResponse `json:"response"`
	Expect      ResponseExpect  `json:"expect"`
}

// ResponseVectors is response-vectors.json.
type ResponseVectors struct {
	Cases []ResponseCase `json:"cases"`
}

// KeyCase is one strict-Ed25519 public-key validity vector.
type KeyCase struct {
	ID           string `json:"id"`
	PublicKeyHex string `json:"public_key_hex"`
	Expect       string `json:"expect"`
	Reason       string `json:"reason,omitempty"`
}

// KeyVectors is key-vectors.json.
type KeyVectors struct {
	Cases []KeyCase `json:"cases"`
}

// LoadCase is one load-time validation vector. Document stays raw JSON: the
// invalid cases intentionally contain fields the typed policy and registry
// forms reject, so typed strict decoding of the fixture itself would fail.
type LoadCase struct {
	ID       string          `json:"id"`
	Document json.RawMessage `json:"document"`
	Expect   string          `json:"expect"`
	Reason   string          `json:"reason,omitempty"`
}

// LoadVectors is load-vectors.json.
type LoadVectors struct {
	Policies   []LoadCase `json:"policies"`
	Registries []LoadCase `json:"registries"`
}

// PatternCase is one policy pattern matching vector; * is the only
// metacharacter and matches any run of characters including none and newlines.
type PatternCase struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Input   string `json:"input"`
	Match   bool   `json:"match"`
}

// PatternVectors is pattern-vectors.json.
type PatternVectors struct {
	Cases []PatternCase `json:"cases"`
}

// LoadKeys loads keys.json.
func LoadKeys() (KeyFile, error) {
	var v KeyFile
	err := decodeFixture("keys.json", &v)
	return v, err
}

// LoadRegistry loads registry.json.
func LoadRegistry() (RegistryDocument, error) {
	var v RegistryDocument
	err := decodeFixture("registry.json", &v)
	return v, err
}

// LoadDefaultPolicy loads policy.json.
func LoadDefaultPolicy() (PolicyDocument, error) {
	var v PolicyDocument
	err := decodeFixture("policy.json", &v)
	return v, err
}

// LoadWildcardPolicy loads policy-wildcard.json.
func LoadWildcardPolicy() (PolicyDocument, error) {
	var v PolicyDocument
	err := decodeFixture("policy-wildcard.json", &v)
	return v, err
}

// LoadRequestVectors loads request-vectors.json.
func LoadRequestVectors() (RequestVectors, error) {
	var v RequestVectors
	err := decodeFixture("request-vectors.json", &v)
	return v, err
}

// LoadAdminVectors loads admin-vectors.json.
func LoadAdminVectors() (AdminVectors, error) {
	var v AdminVectors
	err := decodeFixture("admin-vectors.json", &v)
	return v, err
}

// LoadResponseVectors loads response-vectors.json.
func LoadResponseVectors() (ResponseVectors, error) {
	var v ResponseVectors
	err := decodeFixture("response-vectors.json", &v)
	return v, err
}

// LoadKeyVectors loads key-vectors.json.
func LoadKeyVectors() (KeyVectors, error) {
	var v KeyVectors
	err := decodeFixture("key-vectors.json", &v)
	return v, err
}

// LoadLoadVectors loads load-vectors.json.
func LoadLoadVectors() (LoadVectors, error) {
	var v LoadVectors
	err := decodeFixture("load-vectors.json", &v)
	return v, err
}

// LoadPatternVectors loads pattern-vectors.json.
func LoadPatternVectors() (PatternVectors, error) {
	var v PatternVectors
	err := decodeFixture("pattern-vectors.json", &v)
	return v, err
}
