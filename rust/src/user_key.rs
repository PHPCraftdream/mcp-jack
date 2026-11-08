//! Role-specific Ed25519 user-key material for the mcp-jack Rust SDK.
//!
//! The types here are asymmetric by role:
//!
//! - [`ClientSigningKey`] is the CLIENT-side type. Client consumers hold
//!   private material: they can generate a fresh key or import an exact
//!   server-issued credential, imported into the client through the
//!   strict transfer API. The client type has no private export or
//!   serialization method.
//! - [`IssuedClientKey`] is the SERVER-LOCAL raw issuance foundation. The
//!   separate transfer API issues a credential for delivery to the client;
//!   this legacy raw handoff remains available and independent.
//! - [`ServerPublicKey`] is the SERVER-side type. Server consumers import
//!   PUBLIC keys only and never obtain private material from them: no
//!   method on this type recovers a seed from a public key — such
//!   recovery is impossible by construction, not merely by convention.
//!
//! ## Server-context-free
//!
//! Transfer credentials bind locally issued client keys to a validated server
//! identity. Import never changes client profiles, pins, registry state, or
//! network state. Issuance is a local handoff; the caller owns safe delivery.
//!
//! Server private keys never belong in registry/profile/RPC surfaces;
//! those surfaces carry public data only.
//!
//! ## Memory hygiene (exact limits)
//!
//! No new DIRECT dependency was added. zeroize 1.9.1 is resolved
//! transitively via ed25519-dalek 2.2.0 default features, and
//! `ed25519_dalek::SigningKey` best-effort zeroizes its internally stored
//! seed on drop. There is NO comprehensive erasure guarantee: imported
//! seed copies, stack temporaries, handoff/export bytes returned by
//! value, and optimizer-introduced duplicates all persist uncontrolled,
//! and drop is not an erasure boundary. No secure-erase claim is made
//! anywhere in this module.
//!
//! ## Deliberate non-features
//!
//! - [`ClientSigningKey`] and [`IssuedClientKey`] deliberately do **not**
//!   implement `Clone`: duplicating signing capability happens only
//!   through the explicit issuance handoff, so accidental copies of
//!   secret material cannot arise from a casual `.clone()`.
//! - Neither secret-bearing type derives `serde::Serialize` or
//!   `serde::Deserialize`: a secret-bearing type must never be
//!   serializable. Transfer formats use explicit role APIs and byte accessors.

use std::fmt;

use ed25519_dalek::SigningKey;
// Aliased to avoid the name clash with this module's inherent `sign`.
use ed25519_dalek::Signer as DalekSigner;

use crate::encoding::{encode_b64url, key_id};

/// Length of an Ed25519 seed in bytes (RFC 8032).
const SEED_LEN: usize = 32;

/// A software Ed25519 signing key held in process memory (client role).
/// Constructed with [`ClientSigningKey::generate`] (OS entropy) or
/// [`ClientSigningKey::from_seed`]; signing is deterministic RFC 8032
/// Ed25519.
///
/// The 32-byte seed is the whole signing capability: it is held in
/// plaintext for the life of the key. The client type exposes NO seed
/// accessor or private serializer.
///
/// # Role guard
///
/// An external consumer cannot export a client key's seed; this must not
/// compile (doc tests build it the way a downstream crate would):
///
/// ```compile_fail
/// use mcp_jack::user_key::ClientSigningKey;
/// // Must not compile: the client role has no seed export.
/// fn leak(key: &ClientSigningKey) -> [u8; 32] { key.export_seed() }
/// ```
///
/// The following are compile-time capability proofs (they run as doc tests):
/// a `ClientSigningKey` must not be serializable or `Clone`, so neither the
/// serde path nor a casual copy can carry the seed out of process memory.
/// This must not compile:
///
/// ```compile_fail
/// use mcp_jack::user_key::ClientSigningKey;
/// // Must not compile: the client signer must not be serializable.
/// fn leak_json(key: &ClientSigningKey) -> String {
///     serde_json::to_string(key).expect("serialize")
/// }
/// ```
///
/// ```compile_fail
/// use mcp_jack::user_key::ClientSigningKey;
/// // Must not compile: the client signer is deliberately not Clone.
/// fn clone_it(key: &ClientSigningKey) -> ClientSigningKey { key.clone() }
/// ```
///
/// A serde DESERIALIZE path would resurrect a seed from persisted text, so
/// it is guarded too (the positive companion is the doc example below:
/// `from_seed` + the public surface are the only ways a client key exists).
/// This must not compile:
///
/// ```compile_fail
/// use mcp_jack::user_key::ClientSigningKey;
/// // Must not compile: the client signer must not be deserializable.
/// fn resurrect(text: &str) -> ClientSigningKey {
///     serde_json::from_str(text).expect("deserialize")
/// }
/// ```
///
/// The public surface works as a downstream consumer would use it:
///
/// ```
/// use mcp_jack::user_key::ClientSigningKey;
/// let key = ClientSigningKey::from_seed(&[7u8; 32]).expect("32 bytes");
/// assert_eq!(key.public_part().public_key.len(), 43);
/// ```
///
/// The SDK signer trait (`client::signer::Signer`) is usable downstream
/// through the client type — the exact import the trait guards on the
/// other two types rely on:
///
/// ```
/// use mcp_jack::client::signer::Signer;
/// use mcp_jack::user_key::ClientSigningKey;
/// let key = ClientSigningKey::from_seed(&[7u8; 32]).expect("32 bytes");
/// let signer: &dyn Signer = &key;
/// let sig = signer
///     .sign(b"guarded capability")
///     .expect("software signing is infallible");
/// assert_eq!(sig.len(), 64);
/// assert_eq!(signer.public_key(), key.public_key());
/// ```
pub struct ClientSigningKey {
    signing_key: SigningKey,
    public_key: [u8; 32],
    kid: String,
}

/// An error from constructing, generating or importing a user key: a
/// wrong seed length, an OS entropy failure, or a public-key rejection on
/// strict server-side import. The single message never contains secret
/// material — it only ever carries lengths, RNG or validation text — so
/// the derived [`fmt::Debug`] is safe to print.
#[derive(Debug)]
pub struct UserKeyError {
    message: String,
    class: Option<&'static str>,
    member: Option<&'static str>,
    observed_length: Option<usize>,
    expected_length: Option<usize>,
}

impl UserKeyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            class: None,
            member: None,
            observed_length: None,
            expected_length: None,
        }
    }

    fn random_source_failure() -> Self {
        Self::new("random source failed")
    }

    pub(crate) fn transfer(class: &'static str, member: Option<&'static str>) -> Self {
        Self {
            message: String::new(),
            class: Some(class),
            member,
            observed_length: None,
            expected_length: None,
        }
    }

    pub(crate) fn transfer_length(
        class: &'static str,
        member: &'static str,
        observed_length: usize,
        expected_length: usize,
    ) -> Self {
        Self {
            message: String::new(),
            class: Some(class),
            member: Some(member),
            observed_length: Some(observed_length),
            expected_length: Some(expected_length),
        }
    }

    /// The shared transfer error class, when this error came from transfer
    /// document validation.
    pub fn class(&self) -> Option<&'static str> {
        self.class
    }

    /// Returns the structured length details, if this was a length error.
    pub fn lengths(&self) -> Option<(usize, usize)> {
        Some((self.observed_length?, self.expected_length?))
    }

    /// The transfer document member associated with this error, if any.
    pub fn member(&self) -> Option<&'static str> {
        self.member
    }
}

impl fmt::Display for UserKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(class) = self.class {
            write!(f, "jack: user key: {class}")?;
            if let Some(member) = self.member {
                write!(f, " member={member}")?;
            }
            if let Some(length) = self.observed_length {
                write!(f, " length={length}")?;
            }
            if let Some(length) = self.expected_length {
                write!(f, " expected_length={length}")?;
            }
            return Ok(());
        }
        write!(f, "jack: user key: {}", self.message)
    }
}

impl std::error::Error for UserKeyError {}

impl ClientSigningKey {
    /// Creates a key from 32 OS-random bytes.
    pub fn generate() -> Result<Self, UserKeyError> {
        let mut seed = [0u8; SEED_LEN];
        getrandom::fill(&mut seed)
            .map_err(|e| UserKeyError::new(format!("generating seed: {e}")))?;
        Ok(Self::from_seed_bytes(seed))
    }

    /// Creates a key from an exactly 32-byte Ed25519 seed. This is the
    /// client role's only private-material entry point; no seed accessor
    /// exists on this type.
    pub fn from_seed(seed: &[u8]) -> Result<Self, UserKeyError> {
        let seed_array = <[u8; SEED_LEN]>::try_from(seed).map_err(|_| {
            UserKeyError::new(format!(
                "seed must be exactly {SEED_LEN} bytes, got {}",
                seed.len()
            ))
        })?;
        Ok(Self::from_seed_bytes(seed_array))
    }

    fn from_seed_bytes(seed: [u8; SEED_LEN]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = *signing_key.verifying_key().as_bytes();
        let kid = key_id(&public_key);
        Self {
            signing_key,
            public_key,
            kid,
        }
    }

    /// The 32-byte raw Ed25519 public key (public data; returned by
    /// value).
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// `key_id(public_key())` — base64url(SHA-256(public key)).
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Deterministic RFC 8032 Ed25519 signature of the exact message
    /// bytes.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// The portable public part (public key and kid, canonical unpadded
    /// base64url). This is the client role's public export.
    pub fn public_part(&self) -> UserKeyPublic {
        UserKeyPublic {
            public_key: encode_b64url(&self.public_key),
            kid: self.kid.clone(),
        }
    }
}

// Manual impl: Debug must never expose seed or any secret material.
impl fmt::Debug for ClientSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ClientSigningKey {{ kid: {}, public_key: {} }}",
            self.kid,
            encode_b64url(&self.public_key)
        )
    }
}

impl fmt::Display for ClientSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientSigningKey(kid={})", self.kid)
    }
}

// Bridge to the client SDK signer trait. The trait itself is unchanged and
// stays non-extractable (no seed accessor); this impl lives in the same
// crate, which is the only way to add it.
impl crate::client::signer::Signer for ClientSigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, crate::client::error::ClientError> {
        // Dalek signing is infallible; the Result keeps the trait open to
        // fallible implementations (OS key stores, ssh-agent).
        Ok(self.sign(message).to_vec())
    }

    fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    fn kid(&self) -> &str {
        &self.kid
    }
}

/// Server-local raw issuance foundation. The role-specific transfer API
/// below provides credential-based delivery; this pre-existing seed handoff
/// remains separate and is not the client import or credential API.
///
/// The handoff seed is a fresh plaintext copy of the whole signing
/// capability on every call; no comprehensive erasure of those bytes or
/// their copies is guaranteed (see the module docs). No `Clone`, no serde.
///
/// # Role guard
///
/// The issuance handle is not a signer; an issuer cannot sign as the
/// client key it issued. This must not compile:
///
/// ```compile_fail
/// use mcp_jack::user_key::IssuedClientKey;
/// // Must not compile: the issuance handle cannot sign.
/// fn sign_as_issuer(issued: &IssuedClientKey, message: &[u8]) -> [u8; 64] {
///     issued.sign(message)
/// }
/// ```
///
/// The SDK signer trait (`client::signer::Signer`) must also be absent
/// here, regardless of inherent method shape; [`ClientSigningKey`] shows
/// the trait's real downstream use. This must not compile:
///
/// ```compile_fail
/// use mcp_jack::client::signer::Signer;
/// use mcp_jack::user_key::IssuedClientKey;
/// // Must not compile: IssuedClientKey must not implement the signer trait.
/// fn assert_signer<T: Signer>(_signer: &T) {}
/// pub fn deny(issued: &IssuedClientKey) {
///     assert_signer(issued);
/// }
/// ```
///
/// The following are compile-time capability proofs (they run as doc tests):
/// the issuance handle must not be serializable or `Clone`, so neither serde
/// nor a casual `.clone()` can duplicate the retained signing capability.
/// Each must not compile:
///
/// ```compile_fail
/// use mcp_jack::user_key::IssuedClientKey;
/// // Must not compile: the issuance handle must not be serializable.
/// fn leak_json(issued: &IssuedClientKey) -> String {
///     serde_json::to_string(issued).expect("serialize")
/// }
/// ```
///
/// ```compile_fail
/// use mcp_jack::user_key::IssuedClientKey;
/// // Must not compile: the issuance handle is deliberately not Clone.
/// fn clone_it(issued: &IssuedClientKey) -> IssuedClientKey { issued.clone() }
/// ```
///
/// A serde DESERIALIZE path would resurrect the retained signing capability
/// from persisted text; the positive companion is the doc example below
/// (`generate` / `export_seed` are the only ways the key moves). This must
/// not compile:
///
/// ```compile_fail
/// use mcp_jack::user_key::IssuedClientKey;
/// // Must not compile: the issuance handle must not be deserializable.
/// fn resurrect(text: &str) -> IssuedClientKey {
///     serde_json::from_str(text).expect("deserialize")
/// }
/// ```
///
/// What the issuer CAN do, as a downstream consumer would:
///
/// ```
/// use mcp_jack::user_key::{ClientSigningKey, IssuedClientKey};
/// let issued = IssuedClientKey::generate().expect("os randomness");
/// let retained = issued.public_part();
/// let client = ClientSigningKey::from_seed(&issued.export_seed())
///     .expect("32-byte seed");
/// assert_eq!(client.public_part(), retained);
/// ```
pub struct IssuedClientKey {
    key: ClientSigningKey,
}

impl IssuedClientKey {
    /// Generates a fresh client keypair from 32 OS-random bytes
    /// (issuer-local new-pair generation).
    pub fn generate() -> Result<Self, UserKeyError> {
        Ok(Self {
            key: ClientSigningKey::generate()?,
        })
    }

    /// The 32-byte raw Ed25519 public key of the issued key (public
    /// data).
    pub fn public_key(&self) -> [u8; 32] {
        self.key.public_key()
    }

    /// `key_id(public_key())` of the issued key.
    pub fn kid(&self) -> &str {
        self.key.kid()
    }

    /// The retained portable public part of the issued key.
    pub fn public_part(&self) -> UserKeyPublic {
        self.key.public_part()
    }

    /// Explicit private handoff: a FRESH plaintext copy of the 32-byte
    /// seed of the issued key. The seed IS the whole signing capability:
    /// anyone holding it can sign as this key. The handoff must travel
    /// over an already-authenticated channel; every returned copy — and
    /// any log, serialization or persistence surface it reaches — is
    /// sensitive, and no comprehensive erasure of copies is guaranteed
    /// (module docs). This method exists ONLY on the issuance result: the
    /// client-facing [`ClientSigningKey`] has no seed accessor.
    pub fn export_seed(&self) -> [u8; 32] {
        self.key.signing_key.to_bytes()
    }
}

// Manual impl: Debug must never expose the handoff seed.
impl fmt::Debug for IssuedClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IssuedClientKey {{ kid: {}, public_key: {} }}",
            self.key.kid,
            encode_b64url(&self.key.public_key)
        )
    }
}

impl fmt::Display for IssuedClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IssuedClientKey(kid={})", self.key.kid)
    }
}

/// A strictly validated Ed25519 public key held by SERVER-side consumers.
/// This type holds public data only: no method recovers or ever stores a
/// seed, and no seed or private-key accessor exists by construction. It
/// also cannot sign — a server public record is a verifying identity, not
/// a signer.
///
/// # Role guards
///
/// A downstream consumer must not be able to export private material from
/// a server record, or to sign with one; neither must compile:
///
/// ```compile_fail
/// use mcp_jack::user_key::ServerPublicKey;
/// // Must not compile: a public-only server record has no private export.
/// fn steal_seed(server: &ServerPublicKey) -> [u8; 32] { server.export_seed() }
/// ```
///
/// ```compile_fail
/// use mcp_jack::user_key::ServerPublicKey;
/// // Must not compile: ServerPublicKey cannot sign.
/// fn forge(server: &ServerPublicKey, message: &[u8]) -> [u8; 64] {
///     server.sign(message)
/// }
/// ```
///
/// The SDK signer trait (`client::signer::Signer`) must also be absent
/// here, regardless of inherent method shape; [`ClientSigningKey`] shows
/// the trait's real downstream use. This must not compile:
///
/// ```compile_fail
/// use mcp_jack::client::signer::Signer;
/// use mcp_jack::user_key::ServerPublicKey;
/// // Must not compile: ServerPublicKey must not implement the signer trait.
/// fn assert_signer<T: Signer>(_signer: &T) {}
/// pub fn deny(server: &ServerPublicKey) {
///     assert_signer(server);
/// }
/// ```
///
/// A server record must not be serializable either — this is a compile-time
/// capability proof that runs as a doc test. It must not compile:
///
/// ```compile_fail
/// use mcp_jack::user_key::ServerPublicKey;
/// // Must not compile: ServerPublicKey must not be serializable.
/// fn leak_json(server: &ServerPublicKey) -> String {
///     serde_json::to_string(server).expect("serialize")
/// }
/// ```
///
/// The Deserialize direction is guarded with the same strictness (the
/// positive companion is the doc example below: `from_public_key` /
/// `from_public_part` validate strictly, a blanket serde path would not).
/// This must not compile:
///
/// ```compile_fail
/// use mcp_jack::user_key::ServerPublicKey;
/// // Must not compile: ServerPublicKey must not be deserializable.
/// fn resurrect(text: &str) -> ServerPublicKey {
///     serde_json::from_str(text).expect("deserialize")
/// }
/// ```
///
/// What a server consumer CAN do, as a downstream consumer would (the
/// RFC 8032 test 1 public key: a canonical prime-order point):
///
/// ```
/// use mcp_jack::user_key::ServerPublicKey;
/// let bytes: [u8; 32] = [
///     0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
///     0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
///     0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
///     0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
/// ];
/// let server = ServerPublicKey::from_public_key(&bytes).expect("valid point");
/// assert_eq!(server.public_key(), bytes);
/// assert_eq!(server.kid().len(), 43);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerPublicKey {
    public_key: [u8; 32],
    kid: String,
}

impl ServerPublicKey {
    /// Imports a public key with STRICT validation:
    /// [`crate::ed25519::validate_public_key`] runs first (32 bytes,
    /// canonical, on curve, non-identity, prime-order subgroup) and its
    /// rejection reason is embedded in the error; only then is the kid
    /// computed.
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, UserKeyError> {
        crate::ed25519::validate_public_key(public_key)
            .map_err(|e| UserKeyError::new(format!("invalid public key: {}", e.message)))?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .expect("validated as exactly 32 bytes");
        let kid = key_id(&public_key);
        Ok(Self { public_key, kid })
    }

    /// Imports from a portable [`UserKeyPublic`]. The base64url public
    /// key is decoded to exactly 32 bytes and the supplied kid must equal
    /// `key_id` of that key — an inconsistent or malformed kid is
    /// rejected instead of silently normalized — then the strict
    /// [`ServerPublicKey::from_public_key`] validation applies.
    pub fn from_public_part(part: &UserKeyPublic) -> Result<Self, UserKeyError> {
        let raw = crate::encoding::decode_b64url_fixed(&part.public_key, 32)
            .map_err(|e| UserKeyError::new(format!("public key is not valid base64url: {e}")))?;
        let kid = key_id(&raw);
        if part.kid != kid {
            return Err(UserKeyError::new(
                "public part kid does not match its public key",
            ));
        }
        Self::from_public_key(&raw)
    }

    /// The 32-byte raw Ed25519 public key (public data; returned by
    /// value).
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// `key_id(public_key())` — base64url(SHA-256(public key)).
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The portable public part (public key and kid, canonical unpadded
    /// base64url).
    pub fn public_part(&self) -> UserKeyPublic {
        UserKeyPublic {
            public_key: encode_b64url(&self.public_key),
            kid: self.kid.clone(),
        }
    }

    /// Verifies an Ed25519 signature over `message` with this public key.
    /// Wraps [`crate::ed25519::verify`]: returns `false` on wrong
    /// signature lengths or invalid signatures, never panics.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        crate::ed25519::verify(&self.public_key, message, signature)
    }
}

/// The portable public data of a user key: canonical unpadded base64url
/// (43 characters for 32 bytes) public key and kid. Public data only —
/// safe to serialize and log.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UserKeyPublic {
    pub public_key: String,
    pub kid: String,
}

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
