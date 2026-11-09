//! Strict typed loaders mirroring the Go spec package: the JSON fixtures
//! under ../spec/fixtures are the conformance source of truth. Every loader
//! mirrors the admin-only contract shapes (registry entries `{kid,
//! public_key, name, admin?, not_before?, not_after?}`, invite records
//! `{invite_id, admin?, created_by, created_at, expires_at, key_ttl_seconds?}`).

// Typed loaders mirror every field of the spec generator; the load tests
// exercise only counts and ids, so unread fields are expected.
#![allow(dead_code)]
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

/// RegistryEntry is one key of a registry document. `admin` is a strict JSON
/// boolean when present (serde's plain bool rejects null/string/number) and
/// defaults to false when absent; not_before/not_after are Option because
/// documents may omit them.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    pub kid: String,
    pub public_key: String,
    pub name: String,
    #[serde(default)]
    pub admin: bool,
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

/// IdentityExpect is the verified caller identity the server must hand to the
/// wrapped handler on a forwarded accept (02 section 3). Present only on
/// forwarded accepts: never on native `jack.*` accepts or rejections.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityExpect {
    pub kid: String,
    pub name: String,
    pub admin: bool,
}

/// UserSummary is one entry of an after.users expectation: a full registry
/// entry, admin always present (false included).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserSummary {
    pub kid: String,
    pub public_key: String,
    pub name: String,
    pub admin: bool,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
}

/// AfterState summarizes the sequence state after a step ran. invites is the
/// full raw stored-record expectation list; keeping JSON values preserves
/// literal member presence (notably absent versus explicit null).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AfterState {
    pub users: Vec<UserSummary>,
    pub invites: Vec<serde_json::Value>,
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
    /// Present exactly on forwarded accepts: the verified caller identity.
    #[serde(default)]
    pub identity: Option<IdentityExpect>,
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

/// RequestVectors is request-vectors.json; the registry is the named file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestVectors {
    pub registry: String,
    pub cases: Vec<RequestCase>,
}

/// InviteRecord is a seeded stored invite in a sequence state.
/// key_ttl_seconds is absent when the enrolled key never expires.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRecord {
    pub invite_id: String,
    #[serde(default)]
    pub admin: bool,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
    #[serde(default)]
    pub key_ttl_seconds: Option<i64>,
}

/// SequenceState is the initial state of an admin sequence case.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceState {
    pub now: i64,
    pub window_seconds: i64,
    pub aud: String,
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
/// invalid cases intentionally contain fields the typed forms reject, so
/// typed strict decoding of the fixture itself would fail.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadCase {
    pub id: String,
    pub document: serde_json::Value,
    pub expect: String,
    #[serde(default)]
    pub reason: String,
}

/// LoadVectors is load-vectors.json (registry documents only).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadVectors {
    pub registries: Vec<LoadCase>,
}

/// StateFileCase is one state-file validation vector; document stays raw JSON
/// because invalid cases carry members the typed forms reject.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFileCase {
    pub id: String,
    pub document: serde_json::Value,
    pub expect: String,
    #[serde(default)]
    pub reason: String,
}

/// StateFileVectors is state-file-vectors.json.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFileVectors {
    pub cases: Vec<StateFileCase>,
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

pub fn load_state_file_vectors() -> Result<StateFileVectors, FixtureError> {
    read_strict("state-file-vectors.json")
}

/// One case of client-url-policy.json: the raw URL and whether the client
/// must accept it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlPolicyCase {
    pub name: String,
    pub url: String,
    pub allow: bool,
    /// Parsers that reject an allow=true row (e.g. `["go"]`). Informational
    /// only: Rust has no parser and must accept every allow=true row.
    #[serde(default)]
    pub parse_reject: Vec<String>,
}

/// client-url-policy.json: the normative table of the client URL policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlPolicyFile {
    pub description: String,
    pub policy: String,
    pub cases: Vec<UrlPolicyCase>,
}

pub fn load_client_url_policy() -> Result<UrlPolicyFile, FixtureError> {
    read_strict("client-url-policy.json")
}
