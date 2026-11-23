//! Runner for `spec/fixtures/modern/header-encoding-vectors.json`: the 51
//! value-encoding and request-construction cases of spec 04 section 4 and 6,
//! driven through `build_mirrors`, `text_of_value`, `encode_header_value` and
//! `decode_header_value`.

use serde_json::Value;

use mcp_jack::client::modern::{build_mirrors, text_of_value};
use mcp_jack::modern::{decode_header_value, encode_header_value, DecodeHeaderValueError};

use super::fixtures::*;

/// The case count stated in `spec/tests/modern/CASES.md`.
const EXPECTED_CASES: usize = 51;

/// `kind: "build"`: `_meta` and mirror headers of one request (`C1`, `C2`).
fn check_build(case: &Value) -> Result<(), String> {
    let version = text(case, &["version"]);
    let method = text(case, &["method"]);
    let params = at(case, &["params"]).clone();
    let mirrors = build_mirrors(version, method, &params)
        .map_err(|e| format!("build_mirrors({method:?}) failed: {e}"))?;
    let expected_meta = at(case, &["expect", "meta"]);
    if mirrors.meta != *expected_meta {
        return Err(format!(
            "meta {} != expected {}",
            mirrors.meta, expected_meta
        ));
    }
    let expected_headers = header_pairs(case, at(case, &["expect", "headers"]));
    if mirrors.headers != expected_headers {
        return Err(format!(
            "headers {:?} != expected {:?}",
            mirrors.headers, expected_headers
        ));
    }
    Ok(())
}

/// `kind: "encode"`: type-to-text (`C3`) then the sentinel encoding.
fn check_encode(case: &Value) -> Result<(), String> {
    let ty = text(case, &["type"]);
    let value = at(case, &["value"]);
    let want = text(case, &["expect", "header_value"]);
    let text_value = text_of_value(value, ty)
        .ok_or_else(|| format!("text_of_value({value}, {ty:?}) is None"))?;
    let encoded = encode_header_value(&text_value);
    if encoded != want {
        return Err(format!("encoded `{}` != expected `{}`", encoded, want));
    }
    Ok(())
}

/// `kind: "decode"`: an accepted sentinel decodes to its text, a refused one
/// fails with `BadEncoding`.
fn check_decode(case: &Value) -> Result<(), String> {
    let header_value = text(case, &["header_value"]);
    let decoded = decode_header_value(header_value);
    let ok = at(case, &["expect", "ok"])
        .as_bool()
        .unwrap_or_else(|| panic!("case {}: `expect.ok` is not a boolean", case_id(case)));
    if ok {
        let want = text(case, &["expect", "text"]);
        match decoded {
            Ok(text_value) if text_value == want => Ok(()),
            Ok(text_value) => Err(format!("decoded `{}` != expected `{}`", text_value, want)),
            Err(e) => Err(format!("decode of `{}` failed: {}", header_value, e)),
        }
    } else {
        let reason = text(case, &["expect", "reason"]);
        if reason != "bad_encoding" {
            return Err(format!("refused case carries reason `{}`", reason));
        }
        match decoded {
            Err(DecodeHeaderValueError::BadEncoding) => Ok(()),
            Ok(text_value) => Err(format!(
                "decode of `{}` succeeded as `{}`, expected BadEncoding",
                header_value, text_value
            )),
        }
    }
}

/// Runs every assertion of one case, returning the first failure.
fn check_case(case: &Value) -> Result<(), String> {
    match text(case, &["kind"]) {
        "build" => check_build(case),
        "encode" => check_encode(case),
        "decode" => check_decode(case),
        other => Err(format!("unknown `kind` `{}`", other)),
    }
}

#[test]
fn header_encoding_vectors() {
    let document = load_header_encoding_vectors();
    let listed = cases(&document);
    assert_eq!(
        listed.len(),
        EXPECTED_CASES,
        "Value encoding and request construction \
         (`fixtures/modern/header-encoding-vectors.json`, 51 cases)"
    );

    let mut failures: Vec<(String, String)> = Vec::new();
    let mut pass = 0usize;
    for case in listed {
        match check_case(case) {
            Ok(()) => pass += 1,
            Err(message) => failures.push((case_id(case).to_owned(), message)),
        }
    }

    println!(
        "VECTOR-SUMMARY corpus=header-encoding sdk=rust pass={} excluded=0 deviation=0",
        pass
    );

    if pass != EXPECTED_CASES {
        let listing: Vec<String> = failures
            .iter()
            .map(|(id, message)| format!("  {}: {}", id, message))
            .collect();
        panic!(
            "header encoding vectors: {}/{} passed; failures:\n{}",
            pass,
            EXPECTED_CASES,
            listing.join("\n")
        );
    }
}
