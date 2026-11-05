//! Client configuration profile (Go: client/profile.go). A profile holds
//! ONLY public data — it deliberately has no private-key field, since
//! private keys must never live in config files (spec 01 section 6, README
//! principle 5).

use std::sync::Arc;

use crate::client::error::ClientError;
use crate::client::rpc::{Client, Config};
use crate::client::signer::Signer;
use crate::client::transport::Transport;

/// A client configuration document. Go: dec.DisallowUnknownFields() is
/// covered by `deny_unknown_fields`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub url: String,
    pub aud: String,
    /// Unpadded base64url of the 32-byte server public key.
    pub server_public_key: String,
    /// The client key's identifier (kid), never a private key.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kid: String,
    /// The client key's label.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

/// Reads and validates a profile from JSON text (Go: LoadProfile over an
/// io.Reader). serde_json's from_str rejects trailing data after the value,
/// covering Go's explicit second-decode check.
pub fn load_profile(text: &str) -> Result<Profile, ClientError> {
    let p: Profile = serde_json::from_str(text)
        .map_err(|e| ClientError::Client(format!("jack client: profile: {e}")))?;
    validate_profile(&p)?;
    Ok(p)
}

/// Enforces spec 01 sections 3 and 6 field rules (Go: validateProfile, in
/// the same order).
fn validate_profile(p: &Profile) -> Result<(), ClientError> {
    crate::client::url::validate_base_url(&p.url).map_err(|_| {
        ClientError::Client(
            "jack client: profile url must be an absolute http/https URL with a host".to_string(),
        )
    })?;
    if p.aud.is_empty() {
        return Err(ClientError::Client(
            "jack client: profile aud must be non-empty".to_string(),
        ));
    }
    let server_key =
        crate::encoding::decode_b64url_fixed(&p.server_public_key, 32).map_err(|e| {
            // BadBase64Url's Display is "jack: invalid base64url", matching
            // Go's wrapped ErrBadBase64URL text.
            ClientError::Client(format!("jack client: profile server_public_key: {e}"))
        })?;
    // Local validation never becomes an HTTP response: zero the validator's
    // server-side admission status (spec 01 section 5).
    crate::ed25519::validate_public_key(&server_key).map_err(|mut e| {
        e.http_status = 0;
        ClientError::Protocol(e)
    })?;
    if !p.kid.is_empty() {
        crate::encoding::decode_b64url_fixed(&p.kid, 32)
            .map_err(|e| ClientError::Client(format!("jack client: profile kid: {e}")))?;
    }
    Ok(())
}

/// Renders p as indented JSON with a trailing newline (Go: SaveProfile).
pub fn save_profile(p: &Profile) -> String {
    // to_string_pretty on this struct cannot fail: no maps with
    // non-string keys and no non-finite floats are possible.
    let mut out = serde_json::to_string_pretty(p).expect("profile serialization is infallible");
    out.push('\n');
    out
}

impl Profile {
    /// Returns the decoded 32-byte server public key (Go:
    /// Profile.ServerKeyBytes).
    pub fn server_key_bytes(&self) -> Result<[u8; 32], ClientError> {
        let key =
            crate::encoding::decode_b64url_fixed(&self.server_public_key, 32).map_err(|e| {
                ClientError::Client(format!("jack client: profile server_public_key: {e}"))
            })?;
        // decode_b64url_fixed guaranteed exactly 32 bytes above.
        let bytes: [u8; 32] = key
            .try_into()
            .expect("decode_b64url_fixed guaranteed 32 bytes");
        Ok(bytes)
    }
}

impl Client {
    /// Builds a Client from a validated profile (Go's NewClientFromProfile:
    /// referenced by profile_test.go but not defined in the Go package —
    /// this port defines it).
    pub fn from_profile(
        profile: &Profile,
        signer: Arc<dyn Signer>,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, ClientError> {
        validate_profile(profile)?;
        let server_key = profile.server_key_bytes()?;
        Client::new(Config {
            base_url: profile.url.clone(),
            aud: profile.aud.clone(),
            signer,
            server_key,
            transport,
            now: None,
            nonce: None,
            window_seconds: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::signer::InMemorySigner;
    use crate::client::transport::{HttpRequest, HttpResponse, TransportError};
    use crate::encoding::encode_b64url;

    fn valid_profile() -> (Profile, [u8; 32]) {
        let signer = InMemorySigner::generate().expect("os randomness");
        let key = signer.public_key();
        let p = Profile {
            url: "https://svc.example.test/mcp".to_string(),
            aud: "https://svc.example.test".to_string(),
            server_public_key: encode_b64url(&key),
            kid: signer.kid().to_string(),
            name: "alice-laptop".to_string(),
        };
        (p, key)
    }

    fn doc(p: &Profile) -> String {
        serde_json::to_string(p).expect("profile serialization is infallible")
    }

    struct UnreachableTransport;

    impl Transport for UnreachableTransport {
        fn round_trip(&self, _req: HttpRequest) -> Result<HttpResponse, TransportError> {
            unreachable!("from_profile must not invoke the transport");
        }
    }

    #[test]
    fn profile_round_trip() {
        let (p, key) = valid_profile();
        let saved = save_profile(&p);
        assert!(saved.ends_with('\n'));
        let loaded = load_profile(&saved).expect("round trip");
        assert_eq!(serde_json::to_string(&loaded).expect("serialize"), doc(&p));
        assert_eq!(loaded.server_key_bytes().expect("decode"), key);
    }

    #[test]
    fn profile_json_has_no_private_key() {
        let (p, _) = valid_profile();
        let s = save_profile(&p);
        assert!(!s.contains("private"), "profile JSON contains 'private'");
        assert!(!s.contains("seed"), "profile JSON contains 'seed'");
    }

    #[test]
    fn load_profile_rejects() {
        let (p, _) = valid_profile();
        let kid = p.kid.clone();
        let url_value = p.url.clone();
        let aud_value = p.aud.clone();
        let server_b64 = p.server_public_key.clone();
        let short_key = encode_b64url(&[0u8; 16]);
        let padded_key = format!("{server_b64}=");

        let cases: Vec<(&str, String)> = vec![
            (
                "unknown field",
                format!("{},\"extra\":1}}", doc(&p).trim_end_matches('}')),
            ),
            (
                "server key wrong length",
                doc(&p).replace(&server_b64, &short_key),
            ),
            (
                "padded server key",
                doc(&p).replace(&server_b64, &padded_key),
            ),
            (
                "kid not 32-byte base64url",
                doc(&p).replace(&format!("\"kid\":\"{kid}\""), "\"kid\":\"short\""),
            ),
            (
                "url missing host",
                doc(&p).replace(
                    &format!("\"url\":\"{url_value}\""),
                    "\"url\":\"https:///mcp\"",
                ),
            ),
            (
                "aud empty",
                doc(&p).replace(&format!("\"aud\":\"{aud_value}\""), "\"aud\":\"\""),
            ),
            ("trailing data", format!("{} {{}}", doc(&p))),
        ];
        for (name, d) in cases {
            assert!(
                load_profile(&d).is_err(),
                "{name}: LoadProfile accepted invalid document {d}"
            );
        }
    }

    #[test]
    fn from_profile_rejects_invalid_key_without_http_status() {
        // A key that decodes to 32 bytes but fails spec 03 section 2 must be a
        // client-side rejection: code key_rejected, http_status 0.
        let (p, _) = valid_profile();
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let signer = Arc::new(InMemorySigner::generate().expect("os randomness"));
        let bad = Profile {
            server_public_key: encode_b64url(&identity),
            ..p
        };
        let err = Client::from_profile(&bad, signer, Arc::new(UnreachableTransport))
            .expect_err("identity key must be rejected");
        match err {
            ClientError::Protocol(j) => {
                assert_eq!(j.code, crate::error::codes::KEY_REJECTED);
                assert_eq!(j.http_status, 0, "local validation carries no HTTP status");
            }
            other => panic!("expected ClientError::Protocol, got {other:?}"),
        }
    }

    #[test]
    fn from_profile_ok_and_bad_key() {
        let (p, _) = valid_profile();
        let signer = Arc::new(InMemorySigner::generate().expect("os randomness"));
        Client::from_profile(&p, signer.clone(), Arc::new(UnreachableTransport))
            .expect("valid profile must build");

        let bad = Profile {
            server_public_key: encode_b64url(&[0u8; 16]),
            ..p
        };
        assert!(
            Client::from_profile(&bad, signer, Arc::new(UnreachableTransport)).is_err(),
            "expected error for invalid server public key"
        );
    }
}
