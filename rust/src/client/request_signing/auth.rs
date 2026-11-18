//! Request signing of the client SDK (Go: client/auth.go SignRequest),
//! extended to also return the signing inputs: the design doc
//! docs/design/interop.md sections 5 and 8 require raw-byte access for
//! replay/tamper scenarios.

use crate::auth_header::{format_request_auth, RequestAuth};
use crate::client::error::ClientError;
use crate::client::signer::Signer;
use crate::encoding::encode_b64url;
use crate::signing::request_signing_string;

/// Required nonce length (spec 01 section 2).
pub const NONCE_SIZE: usize = 16;

/// The exact bytes one signed request is built from: the Jack-Auth header
/// value, the parsed header fields, and the signing string. Exposed so
/// interop scenarios can replay and tamper with raw bytes (design doc
/// interop.md sections 5 and 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    pub header_value: String,
    pub auth: RequestAuth,
    pub signing_string: String,
    pub signature: [u8; 64],
}

/// Reports whether s contains an ASCII control character; the signing target
/// must not embed line breaks (spec 01 section 3.1).
pub(crate) fn has_control(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// Builds the signed Jack-Auth header value and signing inputs for one
/// request (spec 01 sections 3 and 3.1; Go: client.SignRequest). `nonce` is
/// the 16 request nonce bytes; `ts` is the Unix-seconds signing time — both
/// are injected by the caller so tests and interop scenarios pin them.
// Go checks a nil signer first; in Rust &dyn Signer cannot be null, so that
// check is unrepresentable.
pub fn sign_request(
    signer: &dyn Signer,
    aud: &str,
    method: &str,
    target: &str,
    body: &[u8],
    nonce: &[u8],
    ts: i64,
) -> Result<SignedRequest, ClientError> {
    if nonce.len() != NONCE_SIZE {
        return Err(ClientError::Client(format!(
            "jack client: nonce must be exactly {NONCE_SIZE} bytes, got {}",
            nonce.len()
        )));
    }
    if method.is_empty() || has_control(method) {
        return Err(ClientError::Client(
            "jack client: empty or control-character HTTP method".to_string(),
        ));
    }
    if target.is_empty() || has_control(target) {
        return Err(ClientError::Client(
            "jack client: empty or control-character target".to_string(),
        ));
    }
    let kid = signer.kid().to_string();
    let nonce_b64 = encode_b64url(nonce);
    let signing_string = request_signing_string(method, target, aud, &kid, ts, &nonce_b64, body);
    let sig_vec = signer.sign(signing_string.as_bytes())?;
    if sig_vec.len() != 64 {
        return Err(ClientError::Client(format!(
            "jack client: signer returned a {}-byte signature, want 64",
            sig_vec.len()
        )));
    }
    // The length check above makes the copy exact.
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_vec);
    let auth = RequestAuth {
        kid,
        ts,
        nonce: nonce_b64,
        sig: encode_b64url(&signature),
    };
    let header_value = format_request_auth(&auth);
    Ok(SignedRequest {
        header_value,
        auth,
        signing_string,
        signature,
    })
}

/// Returns 16 random nonce bytes from the OS RNG (Go: RandomNonce).
pub fn random_nonce() -> Result<[u8; NONCE_SIZE], ClientError> {
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::fill(&mut nonce)
        .map_err(|e| ClientError::Client(format!("jack client: random nonce: {e}")))?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::signer::InMemorySigner;

    // keys.json "alice" seed, same value as the signer.rs tests.
    const ALICE_SEED_HEX: &str = "15949421ee8241acde219c4cff93cc346a0488e049deff61da312798b758d28f";

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
    fn sign_request_shape_and_verification() {
        let signer = alice();
        let aud = "https://svc.example.test";
        let body = br#"{"ping":1}"#;
        let nonce = [7u8; 16];
        let ts = 1767225600;

        let signed = sign_request(&signer, aud, "POST", "/mcp", body, &nonce, ts)
            .expect("valid inputs must sign");

        let want_auth = RequestAuth {
            kid: signer.kid().to_string(),
            ts,
            nonce: encode_b64url(&nonce),
            sig: encode_b64url(&signed.signature),
        };
        assert_eq!(signed.auth, want_auth);
        assert_eq!(signed.header_value, format_request_auth(&want_auth));
        assert_eq!(
            signed.signing_string,
            request_signing_string(
                "POST",
                "/mcp",
                aud,
                signer.kid(),
                ts,
                &encode_b64url(&nonce),
                body
            )
        );
        assert!(crate::ed25519::verify(
            &signer.public_key(),
            signed.signing_string.as_bytes(),
            &signed.signature
        ));
        assert_eq!(
            crate::auth_header::parse_request_auth(&[signed.header_value.as_str()])
                .expect("canonical header must parse"),
            signed.auth
        );
    }

    #[test]
    fn sign_request_rejects_bad_nonce() {
        let signer = alice();
        for (len, n) in [(0usize, 0usize), (17, 17)] {
            let nonce = vec![0u8; len];
            let err = sign_request(&signer, "aud", "POST", "/mcp", b"", &nonce, 1)
                .expect_err("bad nonce must be rejected");
            assert_eq!(
                err.to_string(),
                format!("jack client: nonce must be exactly 16 bytes, got {n}")
            );
        }
    }

    #[test]
    fn sign_request_rejects_method_and_target() {
        let signer = alice();
        let nonce = [1u8; 16];
        let cases = [
            (
                "",
                "/mcp",
                "jack client: empty or control-character HTTP method",
            ),
            (
                "PO\nST",
                "/mcp",
                "jack client: empty or control-character HTTP method",
            ),
            ("POST", "", "jack client: empty or control-character target"),
            (
                "POST",
                "/mcp\nx",
                "jack client: empty or control-character target",
            ),
        ];
        for (method, target, want) in cases {
            let err = sign_request(&signer, "aud", method, target, b"", &nonce, 1)
                .expect_err("bad method/target must be rejected");
            assert!(
                matches!(err, ClientError::Client(_)),
                "expected ClientError::Client, got {err:?}"
            );
            assert_eq!(err.to_string(), want);
        }
    }

    #[test]
    fn random_nonce_length() {
        let nonce = random_nonce().expect("os randomness");
        assert_eq!(nonce.len(), NONCE_SIZE);
    }

    #[test]
    fn has_control_edges() {
        assert!(has_control("\u{7f}"));
        assert!(has_control("\u{1}"));
        assert!(has_control("PO\nST"));
        assert!(!has_control("POST"));
        assert!(!has_control(""));
    }
}
