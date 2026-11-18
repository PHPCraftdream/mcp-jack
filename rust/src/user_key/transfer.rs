use super::*;

const MAX_TRANSFER_BYTES: usize = 4096;
const PUBLIC_KIND: &str = "user-key/public";
const PRIVATE_KIND: &str = "user-key/private";
const CREDENTIAL_KIND: &str = "user-key/credential/client";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ImportSink {
    ClientPublic,
    ClientPrivate,
    ServerPublic,
    Credential,
}

struct ParsedPrivate {
    seed: Option<[u8; SEED_LEN]>,
    public_identity: UserKeyPublic,
}

/// Independently trusted server identity required when importing a transfer
/// credential. `server_public_key` is canonical unpadded base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedIdentity {
    pub url: String,
    pub aud: String,
    pub server_public_key: String,
    pub server_kid: String,
}

/// Validated public connection data carried by a server-issued credential.
/// It can be passed to the existing client after trust comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionData {
    url: String,
    aud: String,
    server_public_key: String,
    server_kid: String,
}

impl ConnectionData {
    /// Constructs validated connection data from a configured identity.
    pub fn new(
        url: impl Into<String>,
        aud: impl Into<String>,
        server_public_key: impl Into<String>,
        server_kid: impl Into<String>,
    ) -> Result<Self, UserKeyError> {
        let connection = Self {
            url: url.into(),
            aud: aud.into(),
            server_public_key: server_public_key.into(),
            server_kid: server_kid.into(),
        };
        validate_connection_config(&connection)?;
        Ok(connection)
    }

    /// Returns the configured URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the configured audience.
    pub fn aud(&self) -> &str {
        &self.aud
    }

    /// Returns the canonical unpadded base64url server public key.
    pub fn server_public_key(&self) -> &str {
        &self.server_public_key
    }

    /// Returns the canonical key identifier.
    pub fn server_kid(&self) -> &str {
        &self.server_kid
    }

    /// Returns the decoded 32-byte server public key.
    pub fn server_key_bytes(&self) -> [u8; 32] {
        let bytes = crate::encoding::decode_b64url_fixed(&self.server_public_key, 32)
            .expect("validated connection data has a canonical 32-byte key");
        bytes
            .try_into()
            .expect("fixed-size decoding returns exactly 32 bytes")
    }

    /// Builds the existing client configuration without performing I/O or
    /// mutating a profile or pin.
    pub fn client_config(
        &self,
        signer: std::sync::Arc<dyn crate::client::signer::Signer>,
        transport: std::sync::Arc<dyn crate::client::transport::Transport>,
    ) -> crate::client::rpc::Config {
        crate::client::rpc::Config {
            base_url: self.url.clone(),
            aud: self.aud.clone(),
            signer,
            server_key: self.server_key_bytes(),
            transport,
            now: None,
            nonce: None,
            window_seconds: 0,
        }
    }
}

/// Client-side verify-only identity imported from a public envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicClientIdentity {
    public_key: [u8; 32],
    kid: String,
}

impl PublicClientIdentity {
    /// Returns the raw public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Returns the key identifier.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Returns the public-only portable identity.
    pub fn public_part(&self) -> UserKeyPublic {
        UserKeyPublic {
            public_key: encode_b64url(&self.public_key),
            kid: self.kid.clone(),
        }
    }

    /// Serializes this public-only identity as its canonical public envelope.
    pub fn export_public_envelope(&self) -> Vec<u8> {
        serialize_public(&self.public_part())
    }

    /// Secret operations on a public-only identity fail closed.
    pub fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, UserKeyError> {
        Err(UserKeyError::transfer("not_private", None))
    }

    /// Verifies an Ed25519 signature with this identity.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        crate::ed25519::verify(&self.public_key, message, signature)
    }
}

/// Server-local key issuance handoff. It retains an unencrypted credential
/// and exposes only a fresh copy through [`IssuedUserKey::credential_bytes`].
///
/// # Role guards
///
/// The issued handle is not a signer and carries no seed accessor; the
/// following are compile-time capability proofs (they run as doc tests).
/// Each must not compile:
///
/// ```compile_fail
/// use mcp_jack::user_key::IssuedUserKey;
/// // Must not compile: the issued handle cannot sign.
/// fn sign_as_issued(issued: &IssuedUserKey, message: &[u8]) -> [u8; 64] {
///     issued.sign(message)
/// }
/// ```
///
/// The SDK signer trait (`client::signer::Signer`) must also be absent
/// here — this guards the REAL public trait route: introducing a trait
/// implementation would make a trait-bound guard compile, even when the
/// inherent-shaped guard above stays broken. The positive companion below
/// shows the trait route working for the client key it belongs to.
/// This must not compile:
///
/// ```compile_fail
/// use mcp_jack::client::signer::Signer;
/// use mcp_jack::user_key::IssuedUserKey;
/// // Must not compile: the issued handle must never implement the signer trait.
/// fn assert_signer<T: Signer>(_signer: &T) {}
/// pub fn deny(issued: &IssuedUserKey) {
///     assert_signer(issued);
/// }
/// ```
///
/// The matched positive companion: a consumer CAN go through the same
/// trait with the client key the credential carries (imported via
/// [`crate::user_key::client::import_credential`]), so the trait route
/// bound above is real, not an accidental absence:
///
/// ```
/// use mcp_jack::client::signer::Signer;
/// use mcp_jack::user_key::ClientSigningKey;
/// let key = ClientSigningKey::from_seed(&[7u8; 32]).expect("32 bytes");
/// fn assert_signer<T: Signer>(_signer: &T) {}
/// assert_signer(&key); // compiles: the client signer IS a Signer
/// ```
///
/// The issued handle must not be deserializable either — a serde round
/// trip would resurrect retained credential bytes inside a process. The
/// positive companion is the doc example further below (`credential_bytes`
/// / `public_identity`), which shows what CAN leave the handle. This must
/// not compile:
///
/// ```compile_fail
/// use mcp_jack::user_key::IssuedUserKey;
/// // Must not compile: the issued handle must not be deserializable.
/// fn resurrect(text: &str) -> IssuedUserKey {
///     serde_json::from_str(text).expect("deserialize")
/// }
/// ```
///
/// ```compile_fail
/// use mcp_jack::user_key::IssuedUserKey;
/// // Must not compile: the issued handle has no seed accessor.
/// fn steal_seed(issued: &IssuedUserKey) -> [u8; 32] { issued.export_seed() }
/// ```
///
/// ```compile_fail
/// use mcp_jack::user_key::IssuedUserKey;
/// // Must not compile: the issued handle must not be serializable (its
/// // bytes embed the client's private envelope).
/// fn leak_json(issued: &IssuedUserKey) -> String {
///     serde_json::to_string(issued).expect("serialize")
/// }
/// ```
///
/// What the issuer CAN do, as a downstream consumer would — explicit byte
/// handoff and public identity:
///
/// ```
/// use mcp_jack::user_key::{ConnectionData, IssuedUserKey, server};
/// let connection = ConnectionData::new(
///     "https://svc.example.test",
///     "https://svc.example.test",
///     "wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw",
///     "wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88",
/// )
/// .expect("valid server identity");
/// let issued: IssuedUserKey = server::issue_user_key_os(&connection)
///     .expect("os randomness");
/// let credential: Vec<u8> = issued.credential_bytes();
/// let public_identity = issued.public_identity();
/// assert_eq!(public_identity.kid.len(), 43);
/// assert!(credential.starts_with(b"{"));
/// ```
pub struct IssuedUserKey {
    credential: Vec<u8>,
    public_identity: UserKeyPublic,
}

impl IssuedUserKey {
    /// Returns an independently owned copy of the full transfer credential.
    pub fn credential_bytes(&self) -> Vec<u8> {
        self.credential.clone()
    }

    /// Public identity for the server's ordinary public-only registration path.
    pub fn public_identity(&self) -> UserKeyPublic {
        self.public_identity.clone()
    }
}

impl fmt::Debug for IssuedUserKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IssuedUserKey {{ kid: {} }}", self.public_identity.kid)
    }
}

impl fmt::Display for IssuedUserKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IssuedUserKey(kid={})", self.public_identity.kid)
    }
}

/// Successful credential import: a software signer and validated server
/// connection data. No profile or pin is modified.
pub struct ImportedCredential {
    pub signer: ClientSigningKey,
    pub connection: ConnectionData,
}

impl fmt::Debug for ImportedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportedCredential")
            .field("signer", &self.signer)
            .field("connection", &self.connection)
            .finish()
    }
}

impl fmt::Display for ImportedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImportedCredential(kid={})", self.signer.kid())
    }
}

fn transfer_error(class: &'static str, member: Option<&'static str>) -> UserKeyError {
    UserKeyError::transfer(class, member)
}

fn malformed() -> UserKeyError {
    transfer_error("malformed_json", None)
}

fn validate_raw_json_scalars(bytes: &[u8]) -> bool {
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                in_string = !in_string;
                i += 1;
            }
            b'\\' if in_string => {
                let Some(&escape) = bytes.get(i + 1) else {
                    return false;
                };
                if escape == b'u' {
                    let Some(unit) = read_hex_unit(bytes, i + 2) else {
                        return false;
                    };
                    if (0xd800..=0xdbff).contains(&unit) {
                        if bytes.get(i + 6..i + 8) != Some(&b"\\u"[..]) {
                            return false;
                        }
                        let Some(low) = read_hex_unit(bytes, i + 8) else {
                            return false;
                        };
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return false;
                        }
                        i += 12;
                    } else if (0xdc00..=0xdfff).contains(&unit) {
                        return false;
                    } else {
                        i += 6;
                    }
                } else {
                    i += 2;
                }
            }
            _ => i += 1,
        }
    }
    !in_string
}

fn read_hex_unit(bytes: &[u8], start: usize) -> Option<u16> {
    let digits = bytes.get(start..start.checked_add(4)?)?;
    let mut value = 0u16;
    for &byte in digits {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        value = (value << 4) | u16::from(nibble);
    }
    Some(value)
}

fn parse_json(input: &[u8]) -> Result<serde_json::Value, UserKeyError> {
    if input.len() > MAX_TRANSFER_BYTES {
        return Err(UserKeyError::transfer_length(
            "oversized_envelope",
            "input",
            input.len(),
            MAX_TRANSFER_BYTES,
        ));
    }
    let text = std::str::from_utf8(input).map_err(|_| malformed())?;
    if !validate_raw_json_scalars(text.as_bytes()) {
        return Err(malformed());
    }
    serde_json::from_str(text).map_err(|_| malformed())
}

fn value_object(
    value: &serde_json::Value,
) -> Result<&serde_json::Map<String, serde_json::Value>, UserKeyError> {
    value
        .as_object()
        .ok_or_else(|| transfer_error("wrong_root_type", None))
}

fn check_version(object: &serde_json::Map<String, serde_json::Value>) -> Result<(), UserKeyError> {
    match object.get("v").and_then(serde_json::Value::as_f64) {
        Some(1.0) => Ok(()),
        _ => Err(transfer_error("unknown_version", Some("v"))),
    }
}

fn discriminator(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<&str, UserKeyError> {
    object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| transfer_error("unknown_type", Some("type")))
}

fn exact_members(
    object: &serde_json::Map<String, serde_json::Value>,
    expected: &'static [&'static str],
) -> Result<(), UserKeyError> {
    if object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)) {
        return Ok(());
    }
    let member = expected
        .iter()
        .find(|key| !object.contains_key(**key))
        .copied();
    Err(transfer_error("bad_member_set", member))
}

fn string_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    member: &'static str,
) -> Result<&'a str, UserKeyError> {
    object
        .get(member)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| transfer_error("wrong_field_type", Some(member)))
}

fn check_envelope_sink(kind: &str, sink: ImportSink) -> Result<bool, UserKeyError> {
    match (kind, sink) {
        (PUBLIC_KIND, ImportSink::ClientPublic | ImportSink::ServerPublic) => Ok(false),
        (PUBLIC_KIND, ImportSink::Credential | ImportSink::ClientPrivate) => {
            Err(transfer_error("wrong_envelope_type", Some("type")))
        }
        (PRIVATE_KIND, ImportSink::ClientPrivate | ImportSink::Credential) => Ok(true),
        (PRIVATE_KIND, ImportSink::ClientPublic) => {
            Err(transfer_error("wrong_envelope_type", Some("type")))
        }
        (PRIVATE_KIND, ImportSink::ServerPublic) | (CREDENTIAL_KIND, ImportSink::ServerPublic) => {
            Err(transfer_error("private_material_rejected", Some("type")))
        }
        (CREDENTIAL_KIND, _) => Err(transfer_error("wrong_envelope_type", Some("type"))),
        (_, _) => Err(transfer_error("unknown_type", Some("type"))),
    }
}

fn canonical_b64_32(value: &str, member: &'static str) -> Result<[u8; 32], UserKeyError> {
    let decoded = crate::encoding::decode_b64url_fixed(value, 32)
        .map_err(|_| UserKeyError::transfer_length("bad_encoding", member, value.len(), 43))?;
    decoded
        .try_into()
        .map_err(|_| transfer_error("bad_encoding", Some(member)))
}

fn validate_public_key(public_key: &[u8; 32], member: &'static str) -> Result<(), UserKeyError> {
    crate::ed25519::validate_public_key(public_key)
        .map_err(|_| transfer_error("invalid_public_key", Some(member)))
}

fn serialize_public(public_identity: &UserKeyPublic) -> Vec<u8> {
    format!(
        "{{\"crv\":\"Ed25519\",\"kid\":{},\"kty\":\"OKP\",\"type\":\"user-key/public\",\"v\":1,\"x\":{}}}",
        quote_json_string(&public_identity.kid),
        quote_json_string(&public_identity.public_key),
    )
    .into_bytes()
}

fn serialize_private(seed: &[u8; 32], public_identity: &UserKeyPublic) -> String {
    format!(
        "{{\"crv\":\"Ed25519\",\"d\":{},\"kid\":{},\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":{}}}",
        quote_json_string(&encode_b64url(seed)),
        quote_json_string(&public_identity.kid),
        quote_json_string(&public_identity.public_key),
    )
}

fn serialize_credential(connection: &ConnectionData, client_key: &str) -> Vec<u8> {
    format!(
        "{{\"aud\":{},\"client_key\":{},\"server_kid\":{},\"server_public_key\":{},\"type\":\"user-key/credential/client\",\"url\":{},\"v\":1}}",
        quote_json_string(&connection.aud),
        quote_json_string(client_key),
        quote_json_string(&connection.server_kid),
        quote_json_string(&connection.server_public_key),
        quote_json_string(&connection.url),
    )
    .into_bytes()
}

fn quote_json_string(value: &str) -> String {
    // serde_json emits JCS-compatible scalar strings: short control escapes,
    // lowercase \u00xx for other controls, and literal UTF-8 otherwise.
    serde_json::to_string(value).expect("serializing a Rust string is infallible")
}

fn import_envelope(input: &[u8], sink: ImportSink) -> Result<(bool, ParsedPrivate), UserKeyError> {
    let value = parse_json(input)?;
    let object = value_object(&value)?;
    check_version(object)?;
    let kind = discriminator(object)?;
    let is_private = check_envelope_sink(kind, sink)?;
    let expected_members: &[&str] = if is_private {
        &["crv", "d", "kid", "kty", "type", "v", "x"]
    } else {
        &["crv", "kid", "kty", "type", "v", "x"]
    };
    exact_members(object, expected_members)?;

    for (member, expected) in [("kty", "OKP"), ("crv", "Ed25519")] {
        match object.get(member).and_then(serde_json::Value::as_str) {
            Some(value) if value == expected => {}
            Some(_) => return Err(transfer_error("unknown_type", Some(member))),
            None => return Err(transfer_error("wrong_field_type", Some(member))),
        }
    }
    let seed_text = if is_private {
        Some(string_field(object, "d")?)
    } else {
        None
    };
    let public_text = string_field(object, "x")?;
    let kid_text = string_field(object, "kid")?;
    let seed = seed_text
        .map(|value| canonical_b64_32(value, "d"))
        .transpose()?;
    let public_key = canonical_b64_32(public_text, "x")?;
    let kid_bytes = canonical_b64_32(kid_text, "kid")?;
    validate_public_key(&public_key, "x")?;

    if let Some(seed) = seed {
        let signing_key = SigningKey::from_bytes(&seed);
        if signing_key.verifying_key().as_bytes() != &public_key {
            return Err(transfer_error("seed_pub_mismatch", Some("d")));
        }
    }
    if encode_b64url(&kid_bytes) != key_id(&public_key) {
        return Err(transfer_error("kid_mismatch", Some("kid")));
    }

    let identity = UserKeyPublic {
        public_key: encode_b64url(&public_key),
        kid: kid_text.to_owned(),
    };
    let canonical = if let Some(seed) = seed {
        serialize_private(&seed, &identity).into_bytes()
    } else {
        serialize_public(&identity)
    };
    if input != canonical {
        return Err(transfer_error("non_canonical_bytes", None));
    }
    Ok((
        is_private,
        ParsedPrivate {
            seed,
            public_identity: identity,
        },
    ))
}

fn validate_expected_identity(expected: &ExpectedIdentity) -> Result<[u8; 32], UserKeyError> {
    if crate::client::url::validate_base_url(&expected.url).is_err() || expected.aud.is_empty() {
        return Err(transfer_error("server_identity_mismatch", None));
    }
    let public_key = canonical_b64_32(&expected.server_public_key, "server_public_key")
        .map_err(|_| transfer_error("server_identity_mismatch", None))?;
    validate_public_key(&public_key, "server_public_key")
        .map_err(|_| transfer_error("server_identity_mismatch", None))?;
    let expected_kid = canonical_b64_32(&expected.server_kid, "server_kid")
        .map_err(|_| transfer_error("server_identity_mismatch", None))?;
    if encode_b64url(&expected_kid) != key_id(&public_key) {
        return Err(transfer_error("server_identity_mismatch", None));
    }
    Ok(public_key)
}

fn validate_connection_config(connection: &ConnectionData) -> Result<(), UserKeyError> {
    let expected = ExpectedIdentity {
        url: connection.url.clone(),
        aud: connection.aud.clone(),
        server_public_key: connection.server_public_key.clone(),
        server_kid: connection.server_kid.clone(),
    };
    validate_expected_identity(&expected).map(|_| ())
}

fn import_credential_document(
    input: &[u8],
) -> Result<(ConnectionData, ParsedPrivate), UserKeyError> {
    let value = parse_json(input)?;
    let object = value_object(&value)?;
    check_version(object)?;
    let kind = discriminator(object)?;
    if kind != CREDENTIAL_KIND {
        return match kind {
            PUBLIC_KIND | PRIVATE_KIND => Err(transfer_error("wrong_envelope_type", Some("type"))),
            _ => Err(transfer_error("unknown_type", Some("type"))),
        };
    }
    exact_members(
        object,
        &[
            "aud",
            "client_key",
            "server_kid",
            "server_public_key",
            "type",
            "url",
            "v",
        ],
    )?;
    let aud = string_field(object, "aud")?;
    let client_key = string_field(object, "client_key")?;
    let server_kid = string_field(object, "server_kid")?;
    let server_public_key = string_field(object, "server_public_key")?;
    let url = string_field(object, "url")?;
    if aud.is_empty() {
        return Err(transfer_error("wrong_field_type", Some("aud")));
    }
    if crate::client::url::validate_base_url(url).is_err() {
        return Err(transfer_error("bad_url", Some("url")));
    }
    let supplied_server_kid = canonical_b64_32(server_kid, "server_kid")?;
    let server_key = canonical_b64_32(server_public_key, "server_public_key")?;
    validate_public_key(&server_key, "server_public_key")?;
    if encode_b64url(&supplied_server_kid) != key_id(&server_key) {
        return Err(transfer_error("kid_mismatch", Some("server_kid")));
    }
    let (is_private, parsed) = import_envelope(client_key.as_bytes(), ImportSink::Credential)?;
    if !is_private {
        return Err(transfer_error("wrong_envelope_type", Some("client_key")));
    }
    let connection = ConnectionData {
        url: url.to_owned(),
        aud: aud.to_owned(),
        server_public_key: server_public_key.to_owned(),
        server_kid: server_kid.to_owned(),
    };
    let canonical = serialize_credential(&connection, client_key);
    if input != canonical {
        return Err(transfer_error("non_canonical_bytes", None));
    }
    Ok((connection, parsed))
}

fn identity_matches(connection: &ConnectionData, expected: &ExpectedIdentity) -> bool {
    connection.url.as_bytes() == expected.url.as_bytes()
        && connection.aud.as_bytes() == expected.aud.as_bytes()
        && connection.server_public_key.as_bytes() == expected.server_public_key.as_bytes()
        && connection.server_kid.as_bytes() == expected.server_kid.as_bytes()
}

/// Role-specific client API.
pub mod client {
    use super::*;

    /// Exports only a signer's public identity; works with extractable and
    /// non-extractable implementations of the existing signer trait.
    pub fn export_public_envelope(
        signer: &dyn crate::client::signer::Signer,
    ) -> Result<Vec<u8>, UserKeyError> {
        let public_key = signer.public_key();
        validate_public_key(&public_key, "x")?;
        let kid = key_id(&public_key);
        if signer.kid() != kid {
            return Err(transfer_error("kid_mismatch", Some("kid")));
        }
        Ok(serialize_public(&UserKeyPublic {
            public_key: encode_b64url(&public_key),
            kid,
        }))
    }

    /// Strictly imports a public envelope as a verify-only identity.
    pub fn import_public_envelope(input: &[u8]) -> Result<PublicClientIdentity, UserKeyError> {
        let (_, parsed) = import_envelope(input, ImportSink::ClientPublic)?;
        let public_key = canonical_b64_32(&parsed.public_identity.public_key, "x")?;
        Ok(PublicClientIdentity {
            public_key,
            kid: parsed.public_identity.kid,
        })
    }

    /// Strictly imports a private envelope as a software signing key.
    pub fn import_private_envelope(input: &[u8]) -> Result<ClientSigningKey, UserKeyError> {
        let (is_private, parsed) = import_envelope(input, ImportSink::ClientPrivate)?;
        if !is_private {
            return Err(transfer_error("wrong_envelope_type", Some("type")));
        }
        let seed = parsed
            .seed
            .ok_or_else(|| transfer_error("wrong_envelope_type", Some("type")))?;
        ClientSigningKey::from_seed(&seed)
    }

    /// Imports a server-issued credential only after independently validating
    /// and exactly matching the required trusted identity tuple.
    pub fn import_credential(
        input: &[u8],
        expected: &ExpectedIdentity,
    ) -> Result<ImportedCredential, UserKeyError> {
        let (connection, parsed) = import_credential_document(input)?;
        validate_expected_identity(expected)?;
        if !identity_matches(&connection, expected) {
            return Err(transfer_error("server_identity_mismatch", None));
        }
        let seed = parsed
            .seed
            .ok_or_else(|| transfer_error("wrong_envelope_type", Some("client_key")))?;
        let signer = ClientSigningKey::from_seed(&seed)?;
        Ok(ImportedCredential { signer, connection })
    }
}

/// Role-specific server API.
pub mod server {
    use super::*;

    /// Strictly imports public identity data for server admission paths.
    /// Private envelopes and credentials receive `private_material_rejected`.
    pub fn import_public_envelope(input: &[u8]) -> Result<ServerPublicKey, UserKeyError> {
        let (is_private, parsed) = import_envelope(input, ImportSink::ServerPublic)?;
        if parsed.seed.is_some() || is_private {
            return Err(transfer_error("private_material_rejected", Some("type")));
        }
        let public_key = canonical_b64_32(&parsed.public_identity.public_key, "x")?;
        ServerPublicKey::from_public_key(&public_key)
    }

    /// Issues a client key locally using the caller's injected byte source.
    /// The source must return exactly the requested number of CSPRNG bytes in
    /// production; deterministic sources are intended for conformance use.
    pub fn issue_user_key(
        connection: &ConnectionData,
        random_bytes: &mut dyn FnMut(usize) -> Result<Vec<u8>, UserKeyError>,
    ) -> Result<IssuedUserKey, UserKeyError> {
        validate_connection_config(connection)?;
        let random = random_bytes(SEED_LEN).map_err(|_| UserKeyError::random_source_failure())?;
        let seed: [u8; SEED_LEN] = random.try_into().map_err(|bytes: Vec<u8>| {
            UserKeyError::new(format!(
                "random source returned {} bytes, expected {SEED_LEN}",
                bytes.len()
            ))
        })?;
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = *signing_key.verifying_key().as_bytes();
        let public_identity = UserKeyPublic {
            public_key: encode_b64url(&public_key),
            kid: key_id(&public_key),
        };
        let private_envelope = serialize_private(&seed, &public_identity);
        let credential = serialize_credential(connection, &private_envelope);
        if credential.len() > MAX_TRANSFER_BYTES {
            return Err(UserKeyError::transfer_length(
                "oversized_envelope",
                "credential",
                credential.len(),
                MAX_TRANSFER_BYTES,
            ));
        }
        Ok(IssuedUserKey {
            credential,
            public_identity,
        })
    }

    /// Issues a client key using OS randomness.
    pub fn issue_user_key_os(connection: &ConnectionData) -> Result<IssuedUserKey, UserKeyError> {
        issue_user_key(connection, &mut |length| {
            let mut bytes = vec![0u8; length];
            getrandom::fill(&mut bytes).map_err(|_| UserKeyError::random_source_failure())?;
            Ok(bytes)
        })
    }

    /// Structurally validates an issued credential, then checks it against the
    /// server's independently configured identity.
    pub fn validate_issued_credential(
        input: &[u8],
        configured: &ExpectedIdentity,
    ) -> Result<(), UserKeyError> {
        let (connection, _) = import_credential_document(input)?;
        validate_expected_identity(configured)?;
        if !identity_matches(&connection, configured) {
            return Err(transfer_error("server_identity_mismatch", None));
        }
        Ok(())
    }
}
