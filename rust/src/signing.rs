//! Signing-string construction and client-side response verification
//! (Go: signing.go and client/auth.go). The three signing strings (request,
//! response, rotate proof) are UTF-8 lines joined with a single LF, with no
//! trailing LF (spec 01 sections 3.1 and 5, spec 03 section 3.1); ts is
//! plain decimal.

use crate::auth_header::parse_response_auth;
use crate::ed25519::verify;
use crate::encoding::{body_hash, decode_b64url_fixed, key_id};
use crate::error::{codes, JackError};

/// The timestamp acceptance window applied when no explicit window is given
/// (Go: client DefaultWindow).
pub const DEFAULT_WINDOW_SECONDS: i64 = 30;

/// Joins the lines of a signing string with single LFs, no trailing LF.
fn join_lines(parts: &[&str]) -> String {
    parts.join("\n")
}

/// Builds the eight-line v1 request signing string: "mcp-jack/v1/request",
/// method, target, aud, kid, ts, nonce, body-hash (spec 01 section 3.1).
/// body is hashed over its exact bytes.
pub fn request_signing_string(
    method: &str,
    target: &str,
    aud: &str,
    kid: &str,
    ts: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    join_lines(&[
        "mcp-jack/v1/request",
        method,
        target,
        aud,
        kid,
        &ts.to_string(),
        nonce,
        &body_hash(body),
    ])
}

/// Builds the six-line v1 response signing string: "mcp-jack/v1/response",
/// status (decimal), request-sig, kid, ts, body-hash (spec 01 section 5).
pub fn response_signing_string(
    status: i64,
    request_sig: &str,
    kid: &str,
    ts: i64,
    body: &[u8],
) -> String {
    join_lines(&[
        "mcp-jack/v1/response",
        &status.to_string(),
        request_sig,
        kid,
        &ts.to_string(),
        &body_hash(body),
    ])
}

/// Builds the five-line rotate proof string: "mcp-jack/v1/rotate", aud,
/// old kid, new kid, ts (spec 03 section 3.1).
pub fn rotate_proof_string(aud: &str, old_kid: &str, new_kid: &str, ts: i64) -> String {
    join_lines(&["mcp-jack/v1/rotate", aud, old_kid, new_kid, &ts.to_string()])
}

/// Client-side response verification (spec 01 section 5; Go: client
/// VerifyResponse). `server_key` is the pinned server public key — exactly
/// 32 bytes, enforced by the type (Go checks the length at runtime; the Rust
/// API makes a wrong length unrepresentable). `header_values` are the values
/// of all headers named Jack-Auth (case-insensitively collected by the
/// caller), in order. All failure codes here are client-side: they never
/// become HTTP responses, so http_status is 0 (spec 01 section 5).
/// Header-grammar failures are remapped to http_status 0 here (Go keeps the
/// parser's 401 — spec divergence, see client/auth.go).
pub fn verify_response(
    server_key: &[u8; 32],
    status: i64,
    header_values: &[&str],
    request_sig: &str,
    body: &[u8],
    now: i64,
    window_seconds: i64,
) -> Result<(), JackError> {
    // Go: window <= 0 means DefaultWindow.
    let window = if window_seconds <= 0 {
        DEFAULT_WINDOW_SECONDS
    } else {
        window_seconds
    };

    // Spec 01 section 5: every client-side response failure carries no HTTP
    // status. The shared parser doubles as the server-side step 1-3 check and
    // assigns 401 there, so remap it here. Go's client propagates the 401
    // unchanged (client/auth.go) — the spec wins; this is a reported Go divergence.
    let auth = parse_response_auth(header_values).map_err(|mut e| {
        e.http_status = 0;
        e
    })?;

    if auth.kid != key_id(server_key) {
        return Err(JackError::new(
            0,
            codes::UNKNOWN_SERVER_KEY,
            "response signed by an unpinned key",
        ));
    }

    // Inclusive two-sided window compare; abs_diff cannot overflow (the raw
    // subtraction would for extreme now/ts pairs).
    if now.abs_diff(auth.ts) > window.unsigned_abs() {
        return Err(JackError::new(
            0,
            codes::TIMESTAMP_OUT_OF_WINDOW,
            "response timestamp outside the acceptance window",
        ));
    }

    // The parser already enforces a canonical 64-byte sig, so an error here
    // can only be a signature mismatch, not a malformed header.
    let sig = decode_b64url_fixed(&auth.sig, 64)
        .map_err(|_| JackError::new(0, codes::BAD_SIGNATURE, "malformed response signature"))?;

    let msg = response_signing_string(status, request_sig, &auth.kid, auth.ts, body);
    if !verify(server_key, msg.as_bytes(), &sig) {
        return Err(JackError::new(
            0,
            codes::BAD_SIGNATURE,
            "response signature does not verify",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::encode_b64url;
    use ed25519_dalek::{Signer, SigningKey};

    const RFC_SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const TS: i64 = 1767225600;

    fn hex_bytes(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(pair).expect("valid"), 16)
                .expect("hex digit");
        }
        out
    }

    struct Fixture {
        server_pub: [u8; 32],
        kid: String,
        req_sig: String,
        body: &'static [u8],
        header: String,
    }

    /// Builds a signed response from the RFC 8032 TEST 1 key. req_sig is a
    /// stand-in whose value is irrelevant: it is only bound into the signing
    /// string, never itself verified.
    fn fixture(seed: [u8; 32]) -> Fixture {
        let signing = SigningKey::from_bytes(&seed);
        let server_pub = *signing.verifying_key().as_bytes();
        let kid = key_id(&server_pub);
        let req_sig = "a".repeat(86);
        let body = br#"{"jsonrpc":"2.0","id":1}"#;
        let msg = response_signing_string(200, &req_sig, &kid, TS, body);
        let sig = encode_b64url(&signing.sign(msg.as_bytes()).to_bytes());
        let header = format!("v1 kid={kid},ts={TS},sig={sig}");
        Fixture {
            server_pub,
            kid,
            req_sig,
            body,
            header,
        }
    }

    fn good() -> Fixture {
        fixture(hex_bytes(RFC_SEED_HEX))
    }

    #[test]
    fn request_signing_string_shape() {
        let s = request_signing_string("POST", "/mcp", "aud", "k", 1767225600, "n", b"hi");
        let lines: Vec<&str> = s.split('\n').collect();
        assert_eq!(8, lines.len());
        assert_eq!("mcp-jack/v1/request", lines[0]);
        assert_eq!(
            &lines[1..8],
            &[
                "POST",
                "/mcp",
                "aud",
                "k",
                "1767225600",
                "n",
                &body_hash(b"hi")
            ]
        );
        assert!(!s.ends_with('\n'));
    }

    #[test]
    fn response_signing_string_shape() {
        let body = b"body";
        let s = response_signing_string(200, "sig", "kid", 1767225600, body);
        let lines: Vec<&str> = s.split('\n').collect();
        assert_eq!(6, lines.len());
        assert_eq!("mcp-jack/v1/response", lines[0]);
        assert_eq!("200", lines[1]);
        assert_eq!("sig", lines[2]);
        assert_eq!("kid", lines[3]);
        assert_eq!("1767225600", lines[4]);
        assert_eq!(body_hash(body), lines[5]);
        assert!(!s.ends_with('\n'));
    }

    #[test]
    fn rotate_proof_string_shape() {
        let s = rotate_proof_string("aud", "old", "new", 1767225600);
        let lines: Vec<&str> = s.split('\n').collect();
        // Go's comment calls it a five-line string.
        assert_eq!(5, lines.len());
        assert_eq!("mcp-jack/v1/rotate", lines[0]);
        assert_eq!("aud", lines[1]);
        assert_eq!("old", lines[2]);
        assert_eq!("new", lines[3]);
        assert_eq!("1767225600", lines[4]);
        assert!(!s.ends_with('\n'));
    }

    #[test]
    fn ts_renders_as_decimal() {
        // i64 Display mirrors Go's strconv.FormatInt, including the sign.
        let s = response_signing_string(200, "sig", "kid", -5, b"");
        assert!(s.split('\n').any(|line| line == "-5"));
    }

    #[test]
    fn verify_response_accepts() {
        let f = good();
        // kid is a base64url encoding of 32 bytes (43 chars, no padding).
        assert_eq!(43, f.kid.len());
        let now = TS;
        assert_eq!(
            Ok(()),
            verify_response(
                &f.server_pub,
                200,
                &[f.header.as_str()],
                &f.req_sig,
                f.body,
                now,
                30
            )
        );
    }

    #[test]
    fn verify_response_rejections() {
        let f = good();
        let now = TS;

        // Tampered body.
        let err = verify_response(
            &f.server_pub,
            200,
            &[f.header.as_str()],
            &f.req_sig,
            b"tampered",
            now,
            30,
        )
        .expect_err("tampered body");
        assert_eq!(codes::BAD_SIGNATURE, err.code);
        assert_eq!(0, err.http_status);

        // Wrong status.
        let err = verify_response(
            &f.server_pub,
            500,
            &[f.header.as_str()],
            &f.req_sig,
            f.body,
            now,
            30,
        )
        .expect_err("wrong status");
        assert_eq!(codes::BAD_SIGNATURE, err.code);
        assert_eq!(0, err.http_status);

        // Different request_sig.
        let err = verify_response(
            &f.server_pub,
            200,
            &[f.header.as_str()],
            &"b".repeat(86),
            f.body,
            now,
            30,
        )
        .expect_err("different request_sig");
        assert_eq!(codes::BAD_SIGNATURE, err.code);
        assert_eq!(0, err.http_status);

        // Outside the window.
        let err = verify_response(
            &f.server_pub,
            200,
            &[f.header.as_str()],
            &f.req_sig,
            f.body,
            now + 31,
            30,
        )
        .expect_err("outside window");
        assert_eq!(codes::TIMESTAMP_OUT_OF_WINDOW, err.code);
        assert_eq!(0, err.http_status);

        // Inclusive boundary: ts = now ± window accepts.
        assert_eq!(
            Ok(()),
            verify_response(
                &f.server_pub,
                200,
                &[f.header.as_str()],
                &f.req_sig,
                f.body,
                now + 30,
                30
            )
        );
        assert_eq!(
            Ok(()),
            verify_response(
                &f.server_pub,
                200,
                &[f.header.as_str()],
                &f.req_sig,
                f.body,
                now - 30,
                30
            )
        );

        // window 0 means the default window of 30 (Go client
        // TestVerifyResponseDefaultWindow).
        assert_eq!(
            Ok(()),
            verify_response(
                &f.server_pub,
                200,
                &[f.header.as_str()],
                &f.req_sig,
                f.body,
                now + 30,
                0
            )
        );
        let err = verify_response(
            &f.server_pub,
            200,
            &[f.header.as_str()],
            &f.req_sig,
            f.body,
            now + 31,
            0,
        )
        .expect_err("default window");
        assert_eq!(codes::TIMESTAMP_OUT_OF_WINDOW, err.code);
        assert_eq!(0, err.http_status);

        // A response signed by a different (unpinned) key.
        let mut other_seed = hex_bytes(RFC_SEED_HEX);
        other_seed[0] ^= 1;
        let other = fixture(other_seed);
        let err = verify_response(
            &f.server_pub,
            200,
            &[other.header.as_str()],
            &f.req_sig,
            f.body,
            now,
            30,
        )
        .expect_err("unpinned key");
        assert_eq!(codes::UNKNOWN_SERVER_KEY, err.code);
        assert_eq!(0, err.http_status);

        // Missing header: client-side, so the parser's 401 is remapped to 0
        // per spec 01 section 5.
        let err = verify_response(&f.server_pub, 200, &[], &f.req_sig, f.body, now, 30)
            .expect_err("missing header");
        assert_eq!(codes::MISSING_AUTH, err.code);
        assert_eq!(0, err.http_status);

        // Unsupported version: client-side, remapped to 0 per spec 01 section 5.
        let v2 = f.header.replacen("v1", "v2", 1);
        let err = verify_response(
            &f.server_pub,
            200,
            &[v2.as_str()],
            &f.req_sig,
            f.body,
            now,
            30,
        )
        .expect_err("v2 header");
        assert_eq!(codes::UNSUPPORTED_VERSION, err.code);
        assert_eq!(0, err.http_status);
    }

    #[test]
    fn verify_response_extreme_now_does_not_overflow() {
        let f = good();
        let values = [f.header.as_str()];
        // The raw subtraction now - auth.ts would overflow for these extremes;
        // abs_diff must keep the check a plain out-of-window rejection.
        for now in [i64::MIN, i64::MAX] {
            let err = verify_response(&f.server_pub, 200, &values, &f.req_sig, f.body, now, 30)
                .expect_err("extreme now must be out of window");
            assert_eq!(codes::TIMESTAMP_OUT_OF_WINDOW, err.code);
            assert_eq!(0, err.http_status);
        }
    }
}
