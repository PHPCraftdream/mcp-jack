//! Jack `w1` unit tests (spec 06 R4.1-R4.6).
//!
//! The key material is derived the way the generated vectors derive it:
//! the seed of a test key is `sha256("mcp-jack test key: <name>")`. The
//! expected header is the KAT of `webhook-w1-vectors.json`; nothing here
//! reads a file at run time.

use crate::user_key::ServerSigningKey;

use crate::encoding::{body_hash, encode_b64url};
use crate::webhook::encoding::sha256;
use crate::webhook::signatures::ServerKey;
use crate::webhook::w1::{sign, signing_string, verify, JackSigningParts, KID_LEN, SIG_LEN};
use crate::webhook::{codes, WebhookError};

/// The ASCII body of the `w1-kat-basic` vector.
const BODY: &str =
    "{\"eventId\":\"evt_1\",\"name\":\"incident.created\",\"data\":{\"severity\":\"P1\"}}";

/// The audience every vector is bound to (spec 06 R4.3).
const AUD: &str = "https://svc.example.test";

/// The subscription id every vector is bound to (spec 06 R4.3).
const SUBSCRIPTION_ID: &str = "sub_a3f1c8e2b0d49f7e";

/// The `webhook-id` every vector signs (spec 06 R4.2).
const WEBHOOK_ID: &str = "msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f";

/// The callback url every vector is bound to (spec 06 R4.3).
const CALLBACK_URL: &str = "https://hooks.example.test/hooks/alice";

/// The receiver clock of the vectors, in unix seconds.
const NOW: i64 = 1_767_225_600;

/// The Jack window of the vectors, in seconds (spec 06 R4.4).
const WINDOW: i64 = 30;

/// The configured MCP server key id, which is never a webhook key
/// (spec 06 R4.5).
const SERVER_KID: &str = "wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88";

/// Returns the deterministic signing key of the `newbie` test key.
fn webhook_signing_key() -> ServerSigningKey {
    ServerSigningKey::from_bytes(&sha256(b"mcp-jack test key: newbie"))
}

/// Returns the `kid` of a signing key, `base64url(SHA-256(public key))`
/// (spec 06 R4.5).
fn kid_of(key: &ServerSigningKey) -> String {
    encode_b64url(&sha256(key.verifying_key().as_bytes()))
}

/// Returns the signed parts of the KAT with the given timestamp
/// (spec 06 R4.2, R4.3).
fn parts<'a>(timestamp: &'a str) -> JackSigningParts<'a> {
    JackSigningParts {
        aud: AUD,
        subscription_id: SUBSCRIPTION_ID,
        webhook_id: WEBHOOK_ID,
        timestamp,
        callback_url: CALLBACK_URL,
        body: BODY.as_bytes(),
    }
}

/// A minimal accepted webhook key: a `kid` and the raw 32-byte public key.
struct LocalKey {
    kid: String,
    public_key: [u8; 32],
}

impl LocalKey {
    /// Builds the accepted key of one signing key (spec 06 R4.5).
    fn from_signing(key: &ServerSigningKey) -> Self {
        Self {
            kid: kid_of(key),
            public_key: *key.verifying_key().as_bytes(),
        }
    }
}

impl ServerKey for LocalKey {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        crate::ed25519::verify(&self.public_key, message, signature)
    }
}

/// Verifies one attempt and returns the rejection it must produce.
fn expect_error(
    header: Option<&str>,
    parts: &JackSigningParts<'_>,
    keys: &[LocalKey],
    mcp_server_kid: Option<&str>,
) -> WebhookError {
    match verify(header, parts, keys, NOW, WINDOW, mcp_server_kid) {
        Ok(kid) => panic!("{header:?} verified as {kid}"),
        Err(error) => error,
    }
}

#[test]
fn signing_string_is_seven_lf_joined_lines() {
    let signed = parts("1767225600");
    let string = signing_string(&signed);
    assert_eq!(
        string,
        "mcp-jack/webhook1/delivery\nhttps://svc.example.test\nsub_a3f1c8e2b0d49f7e\nmsg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f\n1767225600\nhttps://hooks.example.test/hooks/alice\nwaNYuefabal5CqH6tfMsXhIctaYTpckpyz7GGixz01A"
    );
    let lines: Vec<&str> = string.split('\n').collect();
    assert_eq!(lines.len(), 7, "the signing string is not seven lines");
    assert_eq!(lines[0], "mcp-jack/webhook1/delivery");
    assert_eq!(lines[1], AUD);
    assert_eq!(lines[2], SUBSCRIPTION_ID);
    assert_eq!(lines[3], WEBHOOK_ID);
    assert_eq!(lines[4], "1767225600");
    assert_eq!(lines[5], CALLBACK_URL);
    assert_eq!(lines[6], body_hash(BODY.as_bytes()));
    assert_eq!(lines[6].len(), 43);
    assert!(
        !string.ends_with('\n'),
        "the signing string has a trailing LF"
    );
}

#[test]
fn a_signed_header_verifies_with_the_matching_key() {
    let signing = webhook_signing_key();
    let kid = kid_of(&signing);
    assert_eq!(kid, "imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg");
    assert_eq!(kid.len(), KID_LEN);
    let signed = parts("1767225600");
    let header = sign(&signing, &kid, &signed);
    assert_eq!(
        header,
        "w1 kid=imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg,sig=2puBkudzjDrRRhixyc1cfCcCpE6-LrapTfOB0cUdETqr9VOM6JRBUMru67LoM6F94VzxCYaCq4tAgiB-dvyEAQ"
    );
    let keys = [LocalKey::from_signing(&signing)];
    match verify(Some(&header), &signed, &keys, NOW, WINDOW, None) {
        Ok(returned) => assert_eq!(returned, kid),
        Err(error) => panic!("the KAT header was rejected: {error}"),
    }
}

#[test]
fn the_six_failure_codes_are_checked_in_order() {
    let signing = webhook_signing_key();
    let kid = kid_of(&signing);
    let keys = [LocalKey::from_signing(&signing)];
    let in_window = parts("1767225600");
    let honest_header = sign(&signing, &kid, &in_window);
    let malformed = "w1 kid=short,sig=short";
    let server_header = format!("w1 kid={SERVER_KID},sig={}", "A".repeat(SIG_LEN));
    let other_signing = ServerSigningKey::from_bytes(&sha256(b"mcp-jack test key: mallory"));
    let unknown_header = sign(&other_signing, &kid_of(&other_signing), &in_window);
    let stale = parts("1700000000");
    let stale_header = sign(&signing, &kid, &stale);
    let tampered = JackSigningParts {
        body: b"{\"eventId\":\"evt_2\"}",
        ..in_window
    };

    let cases = [
        (None, &in_window, None, codes::MISSING_JACK_AUTH, 401),
        (
            Some(malformed),
            &in_window,
            None,
            codes::MALFORMED_JACK_AUTH,
            400,
        ),
        (
            Some(server_header.as_str()),
            &in_window,
            Some(SERVER_KID),
            codes::WEBHOOK_KEY_IS_SERVER_KEY,
            401,
        ),
        (
            Some(unknown_header.as_str()),
            &in_window,
            None,
            codes::UNKNOWN_WEBHOOK_KEY,
            401,
        ),
        (
            Some(stale_header.as_str()),
            &stale,
            None,
            codes::JACK_TIMESTAMP_OUT_OF_WINDOW,
            401,
        ),
        (
            Some(honest_header.as_str()),
            &tampered,
            None,
            codes::BAD_JACK_SIGNATURE,
            401,
        ),
    ];
    for (header, parts, mcp_server_kid, code, status) in cases {
        let error = expect_error(header, parts, &keys, mcp_server_kid);
        assert_eq!(error.code, code, "header {header:?}");
        assert_eq!(error.http_status, status, "header {header:?}");
    }
}

#[test]
fn the_first_failing_check_wins() {
    let signing = webhook_signing_key();
    let kid = kid_of(&signing);
    let keys = [LocalKey::from_signing(&signing)];
    let stale = parts("1700000000");
    let stale_header = sign(&signing, &kid, &stale);
    let malformed = "w1 kid=short,sig=short";
    let server_header = format!("w1 kid={SERVER_KID},sig={}", "A".repeat(SIG_LEN));
    let unknown_signing = ServerSigningKey::from_bytes(&sha256(b"mcp-jack test key: mallory"));
    let unknown_header = sign(&unknown_signing, &kid_of(&unknown_signing), &stale);

    // Presence beats every later check.
    assert_eq!(
        expect_error(None, &stale, &keys, Some(SERVER_KID)).code,
        codes::MISSING_JACK_AUTH
    );
    // The grammar beats the server-key boundary.
    assert_eq!(
        expect_error(Some(malformed), &stale, &keys, Some(SERVER_KID)).code,
        codes::MALFORMED_JACK_AUTH
    );
    // The server-key boundary beats the unknown-key lookup.
    assert_eq!(
        expect_error(Some(&server_header), &stale, &keys, Some(SERVER_KID)).code,
        codes::WEBHOOK_KEY_IS_SERVER_KEY
    );
    // The key lookup beats the window.
    assert_eq!(
        expect_error(Some(&unknown_header), &stale, &keys, None).code,
        codes::UNKNOWN_WEBHOOK_KEY
    );
    // The window beats the signature.
    assert_eq!(
        expect_error(Some(&stale_header), &stale, &keys, None).code,
        codes::JACK_TIMESTAMP_OUT_OF_WINDOW
    );
}

#[test]
fn the_window_boundary_is_inclusive_in_both_directions() {
    let signing = webhook_signing_key();
    let kid = kid_of(&signing);
    let keys = [LocalKey::from_signing(&signing)];
    for offset in [-WINDOW, WINDOW] {
        let timestamp = (NOW + offset).to_string();
        let signed = parts(&timestamp);
        let header = sign(&signing, &kid, &signed);
        match verify(Some(&header), &signed, &keys, NOW, WINDOW, None) {
            Ok(returned) => assert_eq!(returned, kid),
            Err(error) => panic!("offset {offset} was rejected: {error}"),
        }
    }
    for offset in [-WINDOW - 1, WINDOW + 1] {
        let timestamp = (NOW + offset).to_string();
        let signed = parts(&timestamp);
        let header = sign(&signing, &kid, &signed);
        let error = expect_error(Some(&header), &signed, &keys, None);
        assert_eq!(
            error.code,
            codes::JACK_TIMESTAMP_OUT_OF_WINDOW,
            "offset {offset}"
        );
    }
}

#[test]
fn rejections_never_render_the_header_value_or_the_body() {
    let signing = webhook_signing_key();
    let kid = kid_of(&signing);
    let keys = [LocalKey::from_signing(&signing)];
    let in_window = parts("1767225600");

    let header_marker = "headerbyte";
    let malformed = format!("w1 kid={header_marker},sig={header_marker}");
    let error = expect_error(Some(&malformed), &in_window, &keys, None);
    assert_eq!(error.code, codes::MALFORMED_JACK_AUTH);
    let rendered = error.to_string();
    assert!(
        !rendered.contains(header_marker),
        "{rendered} rendered the header value"
    );
    assert!(
        !rendered.contains(&malformed),
        "{rendered} rendered the header value"
    );

    let body_marker = "bodybyte";
    let body_text = format!("{{\"name\":\"{body_marker}\"}}");
    let signed = JackSigningParts {
        body: body_text.as_bytes(),
        ..in_window
    };
    let header = sign(&signing, &kid, &signed);
    let tampered = JackSigningParts {
        body: b"{\"name\":\"other\"}",
        ..in_window
    };
    let error = expect_error(Some(&header), &tampered, &keys, None);
    assert_eq!(error.code, codes::BAD_JACK_SIGNATURE);
    let rendered = error.to_string();
    assert!(
        !rendered.contains(body_marker),
        "{rendered} rendered the body text"
    );
    assert!(
        !rendered.contains(&header),
        "{rendered} rendered the header value"
    );
}
