//! Ed25519 signers of the client SDK (Go: client/signer.go). Private keys
//! must never live in config files; profiles carry only public data (spec 01
//! section 6).

use std::fmt;

use ed25519_dalek::SigningKey;
// Aliased to avoid the name clash with client::signer::Signer.
use ed25519_dalek::Signer as DalekSigner;

use crate::client::error::ClientError;
use crate::encoding::{encode_b64url, key_id};

/// Produces Ed25519 signatures over the exact message bytes (Go:
/// client.Signer). OS key stores or ssh-agent signers plug in by implementing
/// this trait. kid() must equal mcp_jack::encoding::key_id(&public_key())
/// over the 32-byte raw Ed25519 public key (spec 01 section 2).
pub trait Signer: Send + Sync {
    /// 64-byte Ed25519 signature of message.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ClientError>;
    /// 32-byte raw Ed25519 public key (returned by value; it is public data).
    fn public_key(&self) -> [u8; 32];
    /// key_id(public_key).
    fn kid(&self) -> &str;
}

/// Signs with an in-process Ed25519 key (Go: client.InMemorySigner).
#[derive(Clone)]
pub struct InMemorySigner {
    signing_key: SigningKey,
    public_key: [u8; 32],
    kid: String,
}

impl InMemorySigner {
    /// Builds a signer from a 32-byte Ed25519 seed (Go: NewInMemorySigner,
    /// including the runtime length check).
    pub fn from_seed(seed: &[u8]) -> Result<Self, ClientError> {
        if seed.len() != 32 {
            return Err(ClientError::Client(format!(
                "jack client: signer seed must be exactly 32 bytes, got {}",
                seed.len()
            )));
        }
        // The length check above makes the copy exact.
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed);
        Ok(Self::from_key(SigningKey::from_bytes(&seed_array)))
    }

    /// Creates a signer from an OS random seed (Go: GenerateSigner).
    pub fn generate() -> Result<Self, ClientError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| ClientError::Client(format!("jack client: generating seed: {e}")))?;
        Ok(Self::from_key(SigningKey::from_bytes(&seed)))
    }

    fn from_key(signing_key: SigningKey) -> Self {
        let public_key = *signing_key.verifying_key().as_bytes();
        let kid = key_id(&public_key);
        Self {
            signing_key,
            public_key,
            kid,
        }
    }
}

impl Signer for InMemorySigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ClientError> {
        // Dalek signing is infallible; the Result keeps the trait open to
        // fallible implementations (OS key stores, ssh-agent).
        Ok(self.signing_key.sign(message).to_bytes().to_vec())
    }

    fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    fn kid(&self) -> &str {
        &self.kid
    }
}

// Manual impl: Debug must never expose seed or key material (spec 01
// section 6 — secrets must not reach logs).
impl fmt::Debug for InMemorySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InMemorySigner {{ kid: {}, public_key: {} }}",
            self.kid,
            encode_b64url(&self.public_key)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::decode_b64url_fixed;

    // keys.json "alice" seed and public data: the conformance fixture is the
    // oracle.
    const ALICE_SEED_HEX: &str = "15949421ee8241acde219c4cff93cc346a0488e049deff61da312798b758d28f";
    const ALICE_PUBLIC_KEY_B64: &str = "kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE";
    const ALICE_KID: &str = "TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs";

    fn hex_bytes(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(pair).expect("valid"), 16)
                .expect("hex digit");
        }
        out
    }

    fn alice() -> InMemorySigner {
        InMemorySigner::from_seed(&hex_bytes(ALICE_SEED_HEX)).expect("32-byte seed")
    }

    #[test]
    fn from_seed_rejects_bad_seed() {
        let err = InMemorySigner::from_seed(&[]).expect_err("empty seed must be rejected");
        assert_eq!(
            err.to_string(),
            "jack client: signer seed must be exactly 32 bytes, got 0"
        );
        let seed31 = [0u8; 31];
        let err = InMemorySigner::from_seed(&seed31).expect_err("31-byte seed must be rejected");
        assert_eq!(
            err.to_string(),
            "jack client: signer seed must be exactly 32 bytes, got 31"
        );
        assert!(InMemorySigner::from_seed(&[9u8; 32]).is_ok());
    }

    #[test]
    fn sign_round_trip() {
        let signer = alice();
        // The seed determines the public key (dalek is the oracle).
        let key = SigningKey::from_bytes(&hex_bytes(ALICE_SEED_HEX));
        let verifying = key.verifying_key();
        let expected = verifying.as_bytes();
        assert_eq!(&signer.public_key(), expected);
        let fixture_key =
            decode_b64url_fixed(ALICE_PUBLIC_KEY_B64, 32).expect("fixture public key decodes");
        assert_eq!(signer.public_key(), fixture_key.as_slice());
        assert_eq!(signer.kid(), ALICE_KID);

        let msg = b"mcp-jack signer round trip test message";
        let sig = signer.sign(msg).expect("infallible signing");
        assert_eq!(64, sig.len());
        assert!(crate::ed25519::verify(&signer.public_key(), msg, &sig));
        let mut tampered = *msg;
        tampered[0] ^= 1;
        assert!(!crate::ed25519::verify(
            &signer.public_key(),
            &tampered,
            &sig
        ));
    }

    #[test]
    fn generate_distinct() {
        let a = InMemorySigner::generate().expect("os randomness");
        let b = InMemorySigner::generate().expect("os randomness");
        assert!(crate::ed25519::validate_public_key(&a.public_key()).is_ok());
        assert!(crate::ed25519::validate_public_key(&b.public_key()).is_ok());
        assert_ne!(a.kid(), b.kid());
    }

    #[test]
    fn debug_hides_seed() {
        let signer = alice();
        let seed_hex = ALICE_SEED_HEX;
        let rendered = format!("{signer:?}");
        assert!(!rendered.contains(seed_hex));
        assert!(!rendered.contains("seed"));
        assert!(rendered.contains(ALICE_KID));
    }
}
