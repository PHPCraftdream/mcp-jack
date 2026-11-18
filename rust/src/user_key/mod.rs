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

mod transfer;
pub use transfer::{
    client, server, ConnectionData, ExpectedIdentity, ImportedCredential, IssuedUserKey,
    PublicClientIdentity,
};
