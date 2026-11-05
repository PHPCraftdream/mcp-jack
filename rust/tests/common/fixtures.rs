//! Strict typed loaders mirroring the Go spec package (spec/spec.go): the
//! JSON fixtures under ../spec/fixtures are the conformance source of truth.

// Typed loaders mirror every field of spec/spec.go; the load tests exercise
// only counts and ids, so unread fields are expected.
#![allow(dead_code)]
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// One `[name, value]` pair; the list form keeps repeated headers representable.
/// Manual impl mirrors Go's UnmarshalJSON: wrong arity and null elements are
/// rejected, so a null cannot silently decode into an empty string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

impl<'de> Deserialize<'de> for HeaderPair {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = HeaderPair;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "header pair must be [name, value]")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let name: String = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &"exactly 2 elements"))?;
                let value: String = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &"exactly 2 elements"))?;
                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(2, &"exactly 2 elements"));
                }
                Ok(HeaderPair { name, value })
            }
        }
        d.deserialize_seq(V)
    }
}

/// TestKey is one entry of keys.json. Test only: seeds are derived from public strings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestKey {
    pub name: String,
    pub seed_hex: String,
    pub public_key: String,
    pub kid: String,
}

/// KeyFile is keys.json.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyFile {
    pub note: String,
    pub keys: Vec<TestKey>,
}

/// RegistryEntry is one key of a registry document. Kind, not_before and
/// not_after are Option because documents may omit them (then they default)
/// and the JSON uses null for unbounded validity.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    pub kid: String,
    pub public_key: String,
    pub name: String,
    pub kind: Option<String>,
    pub scopes: Vec<String>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
}

/// RegistryDocument is registry.json.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryDocument {
    pub version: i64,
    pub aud: String,
    pub keys: Vec<RegistryEntry>,
}

/// NonceCacheEntry is a pre-seeded (kid, nonce) cache entry in a case state.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceCacheEntry {
    pub kid: String,
    pub nonce: String,
    pub retain_until: i64,
}

/// RequestState is the per-case state of request vectors.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestState {
    pub now: i64,
    pub window_seconds: i64,
    pub aud: String,
    pub policy: String,
    pub nonce_cache: Vec<NonceCacheEntry>,
}

/// FixtureRequest is the HTTP request under test. body_text is informative
/// only; body_b64u is the exact signed bytes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRequest {
    pub method: String,
    pub target: String,
    pub headers: Vec<HeaderPair>,
    pub body_b64u: String,
    #[serde(default)]
    pub body_text: String,
}

/// AuditExpect is the expected audit record for protocol-native tool calls.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditExpect {
    pub tool: String,
    pub outcome: String,
    pub code: Option<String>,
    pub actor_kid: String,
}

/// UserSummary is one entry of an after.users expectation.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserSummary {
    pub name: String,
    pub kid: String,
    pub kind: String,
    pub scopes: Vec<String>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
}

/// AfterState summarizes the sequence state after a step ran.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AfterState {
    pub users: Vec<UserSummary>,
    pub invites: i64,
}

/// Expect is the shared outcome expectation. structured stays raw JSON: its
/// shape varies per protocol-native tool and expectations embed the
/// "<b64u43>" placeholder, which is a runner-side wildcard.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub result: String,
    #[serde(default)]
    pub kid: String,
    #[serde(default)]
    pub structured: Option<serde_json::Value>,
    #[serde(default)]
    pub http_status: i64,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub audit: Option<AuditExpect>,
    #[serde(default)]
    pub nonce_recorded: bool,
    #[serde(default)]
    pub after: Option<AfterState>,
}

/// Debug carries the signing string the generator signed, line by line. In
/// tamper cases it differs from what a verifier recomputes; that is the point.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Debug {
    pub signing_string_lines: Vec<String>,
}

/// RequestCase is one single-request vector.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestCase {
    pub id: String,
    #[serde(default)]
    pub description: String,
    pub state: RequestState,
    pub request: FixtureRequest,
    pub expect: Expect,
    pub debug: Debug,
}

/// RequestVectors is request-vectors.json; policies maps a case's
/// state.policy name to the file that holds it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestVectors {
    pub registry: String,
    pub policies: HashMap<String, String>,
    pub cases: Vec<RequestCase>,
}

/// InviteRecord is a stored invite in a sequence state. key_ttl_seconds is
/// null when the enrolled key never expires.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRecord {
    pub invite_id: String,
    pub scopes: Vec<String>,
    pub kind: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub key_ttl_seconds: Option<i64>,
}

/// SequenceState is the initial state of an admin sequence case. The five
/// RequestState fields are repeated explicitly instead of using
/// #[serde(flatten)] because flatten cannot be combined with
/// deny_unknown_fields, which the strict fixture contract requires.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceState {
    pub now: i64,
    pub window_seconds: i64,
    pub aud: String,
    pub policy: String,
    pub nonce_cache: Vec<NonceCacheEntry>,
    pub registry: Vec<RegistryEntry>,
    pub invites: Vec<InviteRecord>,
}

/// Step is one request of a sequence; steps share state in order.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub request: FixtureRequest,
    pub expect: Expect,
    pub debug: Debug,
}

/// AdminCase is one ordered sequence of state-changing requests.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminCase {
    pub id: String,
    #[serde(default)]
    pub description: String,
    pub state: SequenceState,
    pub steps: Vec<Step>,
}

/// AdminVectors is admin-vectors.json.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminVectors {
    pub cases: Vec<AdminCase>,
}

/// ResponseState is the per-case state of response vectors.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseState {
    pub now: i64,
    pub window_seconds: i64,
    pub pinned_server_kid: String,
    pub pinned_server_public_key: String,
    pub request_sig: String,
}

/// FixtureResponse is the signed response under test.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureResponse {
    pub status: i64,
    pub headers: Vec<HeaderPair>,
    pub body_b64u: String,
    #[serde(default)]
    pub body_text: String,
}

/// ResponseExpect is the outcome expectation of a response case.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseExpect {
    pub result: String,
    #[serde(default)]
    pub code: String,
}

/// ResponseCase is one client-side response verification vector.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseCase {
    pub id: String,
    #[serde(default)]
    pub description: String,
    pub state: ResponseState,
    pub response: FixtureResponse,
    pub expect: ResponseExpect,
}

/// ResponseVectors is response-vectors.json.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseVectors {
    pub cases: Vec<ResponseCase>,
}

/// KeyCase is one strict-Ed25519 public-key validity vector.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCase {
    pub id: String,
    pub public_key_hex: String,
    pub expect: String,
    #[serde(default)]
    pub reason: String,
}

/// KeyVectors is key-vectors.json.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyVectors {
    pub cases: Vec<KeyCase>,
}

/// LoadCase is one load-time validation vector. document stays raw JSON: the
/// invalid cases intentionally contain fields the typed policy and registry
/// forms reject, so typed strict decoding of the fixture itself would fail.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadCase {
    pub id: String,
    pub document: serde_json::Value,
    pub expect: String,
    #[serde(default)]
    pub reason: String,
}

/// LoadVectors is load-vectors.json.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadVectors {
    pub policies: Vec<LoadCase>,
    pub registries: Vec<LoadCase>,
}

/// PatternCase is one policy pattern matching vector; * is the only
/// metacharacter and matches any run of characters including none and newlines.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternCase {
    pub id: String,
    pub pattern: String,
    pub input: String,
    #[serde(rename = "match")]
    pub matched: bool,
}

/// PatternVectors is pattern-vectors.json.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternVectors {
    pub cases: Vec<PatternCase>,
}

/// Load error: a fixture failed to read or strictly decode.
#[derive(Debug)]
pub struct FixtureError {
    file: &'static str,
    source: String,
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fixture {}: {}", self.file, self.source)
    }
}

impl std::error::Error for FixtureError {}

fn read_strict<T: DeserializeOwned>(name: &'static str) -> Result<T, FixtureError> {
    let text = fs::read_to_string(fixture_path(name)).map_err(|e| FixtureError {
        file: name,
        source: e.to_string(),
    })?;
    // from_str rejects trailing data, matching Go's decoder check.
    serde_json::from_str(&text).map_err(|e| FixtureError {
        file: name,
        source: e.to_string(),
    })
}

/// Fixtures are read in place from the shared spec directory, never copied.
pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/fixtures")
}

pub fn fixture_path(name: &str) -> PathBuf {
    fixture_dir().join(name)
}

pub fn load_keys() -> Result<KeyFile, FixtureError> {
    read_strict("keys.json")
}

pub fn load_registry() -> Result<RegistryDocument, FixtureError> {
    read_strict("registry.json")
}

/// Loads the policy document as raw JSON; the typed loader is mcp_jack::server::policy::Policy::parse.
pub fn load_default_policy() -> Result<serde_json::Value, FixtureError> {
    read_strict("policy.json")
}

/// Loads the policy document as raw JSON; the typed loader is mcp_jack::server::policy::Policy::parse.
pub fn load_wildcard_policy() -> Result<serde_json::Value, FixtureError> {
    read_strict("policy-wildcard.json")
}

pub fn load_request_vectors() -> Result<RequestVectors, FixtureError> {
    read_strict("request-vectors.json")
}

pub fn load_admin_vectors() -> Result<AdminVectors, FixtureError> {
    read_strict("admin-vectors.json")
}

pub fn load_response_vectors() -> Result<ResponseVectors, FixtureError> {
    read_strict("response-vectors.json")
}

pub fn load_key_vectors() -> Result<KeyVectors, FixtureError> {
    read_strict("key-vectors.json")
}

pub fn load_load_vectors() -> Result<LoadVectors, FixtureError> {
    read_strict("load-vectors.json")
}

pub fn load_pattern_vectors() -> Result<PatternVectors, FixtureError> {
    read_strict("pattern-vectors.json")
}
