//! The R5.9 document verdict of spec 06 section 5, including the size cap
//! that must win over a valid JSON prefix.

use crate::webhook::codes;
use crate::webhook::verification::document::{
    document_verdict, DocumentResponse, MAX_DOCUMENT_BYTES,
};

/// A valid receiver document body that is well below the cap
/// (spec 06 R5.9).
const BODY: &[u8] = br#"{"receivers":["/hooks/"]}"#;

#[test]
fn a_valid_document_is_accepted() {
    let document = document_verdict(&DocumentResponse {
        status: 200,
        body: BODY,
        declared_length: Some(BODY.len() as u64),
        overflow: false,
    })
    .expect("a 200 with a valid body is a document");

    assert_eq!(document.receivers, vec!["/hooks/".to_string()]);
}

#[test]
fn an_overflow_wins_over_a_valid_json_prefix() {
    let mut body = BODY.to_vec();
    body.resize(MAX_DOCUMENT_BYTES * 2, b' ');

    let error = document_verdict(&DocumentResponse {
        status: 200,
        body: &body,
        declared_length: None,
        overflow: true,
    })
    .expect_err("an overflowed read is too large");

    assert_eq!(error.code, codes::DOCUMENT_FETCH_FAILED);
    assert_eq!(error.reason.as_deref(), Some("too_large"));
}

#[test]
fn a_declared_length_over_the_cap_wins_over_a_valid_json_prefix() {
    let error = document_verdict(&DocumentResponse {
        status: 200,
        body: BODY,
        declared_length: Some(MAX_DOCUMENT_BYTES as u64 + 1),
        overflow: false,
    })
    .expect_err("a declared length above the cap is too large");

    assert_eq!(error.code, codes::DOCUMENT_FETCH_FAILED);
    assert_eq!(error.reason.as_deref(), Some("too_large"));
}

#[test]
fn a_non_200_status_keeps_its_status_reason() {
    let error = document_verdict(&DocumentResponse {
        status: 204,
        body: BODY,
        declared_length: None,
        overflow: false,
    })
    .expect_err("a 204 is not a document");

    assert_eq!(error.code, codes::DOCUMENT_FETCH_FAILED);
    assert_eq!(error.reason.as_deref(), Some("status_204"));
}
