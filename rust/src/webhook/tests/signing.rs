//! Signature-layer unit tests (spec 06 section 2).
//!
//! Every vector is copied verbatim from
//! `spec/fixtures/modern/webhook-signature-vectors.json` (kind `secret`) or
//! from RFC 4648 section 10; nothing here reads a file at run time.

use crate::webhook::encoding::*;
use crate::webhook::{codes, WebhookError};

/// The RFC 4648 section 10 standard base64 test vectors, as
/// (plain, padded standard base64) pairs.
const RFC4648_VECTORS: [(&str, &str); 7] = [
    ("", ""),
    ("f", "Zg=="),
    ("fo", "Zm8="),
    ("foo", "Zm9v"),
    ("foob", "Zm9vYg=="),
    ("fooba", "Zm9vYmE="),
    ("foobar", "Zm9vYmFy"),
];

/// Inputs that are not canonical padded standard base64 (spec 06 R2.1), used
/// for the strict decoder and for the error-rendering test.
const REJECT_BODIES: [&str; 7] = ["ab=", "ab==", "a", "abc", "a b", "+_==", "ab=c"];

/// Returns every eight-character substring of `text`.
fn eight_char_substrings(text: &str) -> impl Iterator<Item = &str> {
    (0..text.len()).filter_map(move |start| text.get(start..start + 8))
}

/// Asserts a fixture value is a valid secret decoding to `key_b64u`.
fn assert_secret_accept(value: &str, key_b64u: &str) {
    let secret = match WebhookSecret::parse(value) {
        Ok(secret) => secret,
        Err(error) => panic!("fixture value {value} was rejected: {error}"),
    };
    assert_eq!(crate::encoding::encode_b64url(secret.as_bytes()), key_b64u);
}

/// Asserts a fixture value is rejected with exactly `code` and `reason`.
fn assert_secret_reject(value: &str, code: &str, reason: &str) {
    let error = match WebhookSecret::parse(value) {
        Ok(_) => panic!("fixture value {value} was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code, code);
    assert_eq!(error.reason(), Some(reason));
}

#[test]
fn rfc4648_standard_base64_round_trips() {
    for (plain, encoded) in RFC4648_VECTORS {
        assert_eq!(encode_b64_std(plain.as_bytes()), encoded);
        assert_eq!(
            decode_b64_std_strict(encoded),
            Some(plain.as_bytes().to_vec())
        );
    }
}

#[test]
fn strict_decoder_rejects_noncanonical_standard_base64() {
    for body in REJECT_BODIES {
        assert_eq!(decode_b64_std_strict(body), None, "{body} was accepted");
    }
}

#[test]
fn misplaced_padding_reports_the_padding_reason() {
    let error = match WebhookSecret::parse("whsec_ab=c") {
        Ok(_) => panic!("whsec_ab=c was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code, codes::INVALID_SECRET);
    assert_eq!(error.reason(), Some("padding"));
}

#[test]
fn secret_vectors_accept_32_bytes() {
    assert_secret_accept(
        "whsec_Ha+2nPDW61Z9H5/Uc/1B8csaLDZJ6SeG9jHX+FmQbZk=",
        "Ha-2nPDW61Z9H5_Uc_1B8csaLDZJ6SeG9jHX-FmQbZk",
    );
}

#[test]
fn secret_vectors_accept_24_bytes() {
    assert_secret_accept(
        "whsec_+Zzlgla8N3pwerY+qnV84RsV/0dtERRT",
        "-Zzlgla8N3pwerY-qnV84RsV_0dtERRT",
    );
}

#[test]
fn secret_vectors_accept_64_bytes() {
    assert_secret_accept(
        "whsec_zLSJ1aPKmSHQvG60Sq8f7svGCs/I7q9nBs2C2F5vmen8wqpwwOPe9y4JGS6S7NKxwS0duaHkFCBfqUCAJLc1Kg==",
        "zLSJ1aPKmSHQvG60Sq8f7svGCs_I7q9nBs2C2F5vmen8wqpwwOPe9y4JGS6S7NKxwS0duaHkFCBfqUCAJLc1Kg",
    );
}

#[test]
fn secret_vectors_reject_23_bytes() {
    assert_secret_reject(
        "whsec_+g1Ds02EwhXKdvy+pIUWn7usVGdfX7I=",
        "invalid_secret",
        "length",
    );
}

#[test]
fn secret_vectors_reject_65_bytes() {
    assert_secret_reject(
        "whsec_TSct4DduQoaHViH2UF5yF8s3DDpvY/4TEtZam0t8G4+DRo7nHqzT6M86aUlCjNZEhTy25x3+acLYqHchQK5K3SQ=",
        "invalid_secret",
        "length",
    );
}

#[test]
fn secret_vectors_reject_missing_prefix() {
    assert_secret_reject(
        "Ha+2nPDW61Z9H5/Uc/1B8csaLDZJ6SeG9jHX+FmQbZk=",
        "invalid_secret",
        "prefix",
    );
}

#[test]
fn secret_vectors_reject_uppercase_prefix() {
    assert_secret_reject(
        "WHSEC_Ha+2nPDW61Z9H5/Uc/1B8csaLDZJ6SeG9jHX+FmQbZk=",
        "invalid_secret",
        "prefix",
    );
}

#[test]
fn secret_vectors_reject_base64url_alphabet() {
    assert_secret_reject(
        "whsec_+-zlgla8N3pwerY+qnV84RsV/0dtERRT",
        "invalid_secret",
        "alphabet",
    );
}

#[test]
fn secret_vectors_reject_missing_padding() {
    assert_secret_reject(
        "whsec_zLSJ1aPKmSHQvG60Sq8f7svGCs/I7q9nBs2C2F5vmen8wqpwwOPe9y4JGS6S7NKxwS0duaHkFCBfqUCAJLc1Kg=",
        "invalid_secret",
        "padding",
    );
}

#[test]
fn secret_vectors_reject_extra_padding() {
    assert_secret_reject(
        "whsec_Ha+2nPDW61Z9H5/Uc/1B8csaLDZJ6SeG9jHX+FmQbZk==",
        "invalid_secret",
        "padding",
    );
}

#[test]
fn secret_vectors_reject_noncanonical_bits() {
    assert_secret_reject(
        "whsec_w+PCtEAcabFtndwb1W/QtjSyhFxdhbOXtB==",
        "invalid_secret",
        "canonical",
    );
}

#[test]
fn secret_vectors_reject_whitespace() {
    assert_secret_reject(
        "whsec_+Z lgla8N3pwerY+qnV84RsV/0dtERRT",
        "invalid_secret",
        "alphabet",
    );
}

#[test]
fn constant_time_eq_truth_table() {
    assert!(constant_time_eq(b"", b""));
    assert!(constant_time_eq(b"foobar", b"foobar"));
    assert!(constant_time_eq(&[0u8; 32], &[0u8; 32]));
    assert!(!constant_time_eq(b"foobar", b"foobaz"));
    assert!(!constant_time_eq(b"foobar", b"fooba"));
    assert!(!constant_time_eq(b"foobar", b"foobarX"));
    assert!(!constant_time_eq(b"", b"a"));
    assert!(!constant_time_eq(&[0u8; 32], &[0u8; 31]));
    // A difference in the very last byte still fails.
    let mut left = [7u8; 32];
    let mut right = [7u8; 32];
    right[31] = 8;
    assert!(!constant_time_eq(&left, &right));
    left[31] = 8;
    assert!(constant_time_eq(&left, &right));
}

#[test]
fn secret_debug_never_renders_the_bytes() {
    let secret = match WebhookSecret::parse("whsec_Ha+2nPDW61Z9H5/Uc/1B8csaLDZJ6SeG9jHX+FmQbZk=") {
        Ok(secret) => secret,
        Err(error) => panic!("fixture value was rejected: {error}"),
    };
    let debug = format!("{secret:?}");
    let body = encode_b64_std(secret.as_bytes());
    assert!(!debug.contains(&body), "debug rendered the secret body");
    assert!(debug.contains("redacted"), "debug is not marked redacted");
}

#[test]
fn invalid_secret_error_never_renders_the_input() {
    // Every rejected body below still yields the one fixed `invalid_secret`
    // code; the message itself is asserted once, by the redaction part.
    for body in REJECT_BODIES {
        let value = format!("whsec_{body}");
        let error = match WebhookSecret::parse(&value) {
            Ok(_) => panic!("{value} was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, codes::INVALID_SECRET, "{value}");
    }

    // A fixed byte pattern whose base64 text no message literal contains, so
    // neither the body nor any eight-character window of it can appear in a
    // rendered error by accident (spec 06 section 3).
    let pattern = |len: u8| -> Vec<u8> {
        (0..len)
            .map(|index| index.wrapping_mul(37).wrapping_add(11))
            .collect()
    };
    // The prefix is wrong here, so the value is refused before the body is
    // even looked at.
    let body = encode_b64_std(&pattern(32));
    assert_eq!(body.len(), 44, "the body is 32 bytes of padded base64");
    let value = format!("WHSEC_{body}");
    let error = match WebhookSecret::parse(&value) {
        Ok(_) => panic!("{value} was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code, codes::INVALID_SECRET);
    assert_eq!(error.reason(), Some("prefix"));
    let rendered = error.to_string();
    assert!(!rendered.contains(&body), "{rendered} rendered the input");
    for window in eight_char_substrings(&body) {
        assert!(
            !rendered.contains(window),
            "{rendered} rendered an input substring"
        );
    }

    // The same pattern under the literal prefix is canonical base64 but 65
    // bytes, one over the limit, so the length rule refuses it after the bytes
    // exist and the failure must still not render them.
    let long_body = encode_b64_std(&pattern(65));
    let long_value = format!("whsec_{long_body}");
    let long_error = match WebhookSecret::parse(&long_value) {
        Ok(_) => panic!("{long_value} was accepted"),
        Err(error) => error,
    };
    assert_eq!(long_error.code, codes::INVALID_SECRET);
    assert_eq!(long_error.reason(), Some("length"));
    let long_rendered = long_error.to_string();
    assert!(
        !long_rendered.contains(&long_body),
        "{long_rendered} rendered the input"
    );
    for window in eight_char_substrings(&long_body) {
        assert!(
            !long_rendered.contains(window),
            "{long_rendered} rendered an input substring"
        );
    }
}

#[test]
fn webhook_error_is_a_std_error() {
    let error = match WebhookSecret::parse("whsec_ab=c") {
        Ok(_) => panic!("whsec_ab=c was accepted"),
        Err(error) => error,
    };
    let as_trait: &dyn std::error::Error = &error;
    assert_eq!(as_trait.to_string(), error.to_string());
    let typed: WebhookError = error;
    assert_eq!(typed.http_status, 400);
}
