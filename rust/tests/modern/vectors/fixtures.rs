//! Loaders for the modern-profile corpora, plus the small accessors the
//! runners need. Files are read in place from the shared spec directory.

// The accessors are shared by every runner; individual runners read only part
// of them.
#![allow(dead_code)]
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// The directory holding the modern corpora.
pub fn modern_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/fixtures/modern")
}

fn modern_path(name: &str) -> PathBuf {
    modern_dir().join(name)
}

/// Reads one corpus and checks its `format` member starts with the given prefix.
fn load(name: &str, format_prefix: &str) -> Value {
    let path = modern_path(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("modern corpus {}: read failed: {}", path.display(), e));
    let document: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("modern corpus {}: decode failed: {}", path.display(), e));
    let format = document
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "modern corpus {}: missing string member `format`",
                path.display()
            )
        });
    if !format.starts_with(format_prefix) {
        panic!(
            "modern corpus {}: format is `{}`, expected prefix `{}`",
            path.display(),
            format,
            format_prefix
        );
    }
    document
}

pub fn load_modern_request_vectors() -> Value {
    load(
        "modern-request-vectors.json",
        "mcp-jack-modern-request-vectors-v1",
    )
}

pub fn load_header_encoding_vectors() -> Value {
    load(
        "header-encoding-vectors.json",
        "mcp-jack-modern-header-encoding-v1",
    )
}

pub fn load_x_mcp_header_vectors() -> Value {
    load(
        "x-mcp-header-vectors.json",
        "mcp-jack-modern-x-mcp-header-v1",
    )
}

pub fn load_era_detection_vectors() -> Value {
    load(
        "era-detection-vectors.json",
        "mcp-jack-modern-era-detection-v1",
    )
}

/// Loads `spec/fixtures/response-vectors.json` (spec 01 section 5), the
/// corpus the request runner's `cache-replay` by-reference entry points at.
/// It carries no `format` member, so [`load`] cannot be used.
pub fn load_response_vectors() -> Value {
    let path = modern_dir().join("../response-vectors.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("response vectors {}: read failed: {}", path.display(), e));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("response vectors {}: decode failed: {}", path.display(), e))
}

/// The `cases` array of a corpus.
pub fn cases(document: &Value) -> &Vec<Value> {
    document
        .get("cases")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("corpus has no `cases` array"))
}

/// The `id` of one case (panics when absent).
pub fn case_id(case: &Value) -> &str {
    case.get("id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case without a string `id`: {}", case))
}

/// One required string member (`path` walks nested objects).
pub fn text<'a>(case: &'a Value, path: &[&str]) -> &'a str {
    at(case, path).as_str().unwrap_or_else(|| {
        panic!(
            "case {}: `{}` is not a string",
            case_id(case),
            path.join(".")
        )
    })
}

/// An optional string member.
pub fn opt_text<'a>(case: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut node = case;
    for key in path {
        node = node.get(*key)?;
    }
    node.as_str()
}

/// A required JSON member.
pub fn at<'a>(case: &'a Value, path: &[&str]) -> &'a Value {
    let mut node = case;
    for key in path {
        node = node
            .get(*key)
            .unwrap_or_else(|| panic!("case {}: missing `{}`", case_id(case), path.join(".")));
    }
    node
}

/// A `[[name, value], ...]` header list as owned pairs (panics on any other
/// shape).
pub fn header_pairs(case: &Value, value: &Value) -> Vec<(String, String)> {
    let rows = value.as_array().unwrap_or_else(|| {
        panic!(
            "case {}: header list is not an array: {}",
            case_id(case),
            value
        )
    });
    rows.iter()
        .map(|row| {
            let pair = row
                .as_array()
                .filter(|pair| pair.len() == 2)
                .unwrap_or_else(|| {
                    panic!(
                        "case {}: header row is not a [name, value] pair: {}",
                        case_id(case),
                        row
                    )
                });
            let name = pair[0].as_str().unwrap_or_else(|| {
                panic!(
                    "case {}: header name is not a string: {}",
                    case_id(case),
                    pair[0]
                )
            });
            let value = pair[1].as_str().unwrap_or_else(|| {
                panic!(
                    "case {}: header value is not a string: {}",
                    case_id(case),
                    pair[1]
                )
            });
            (name.to_owned(), value.to_owned())
        })
        .collect()
}

#[test]
fn modern_vector_files_load() {
    for (name, document) in [
        ("modern-request-vectors.json", load_modern_request_vectors()),
        (
            "header-encoding-vectors.json",
            load_header_encoding_vectors(),
        ),
        ("x-mcp-header-vectors.json", load_x_mcp_header_vectors()),
        ("era-detection-vectors.json", load_era_detection_vectors()),
    ] {
        let listed = cases(&document);
        assert!(!listed.is_empty(), "{} has no cases", name);
        let mut seen = HashSet::new();
        for case in listed {
            let id = case_id(case);
            assert!(seen.insert(id), "{} repeats case id {}", name, id);
        }
    }
}

#[test]
fn modern_vector_counts() {
    let requests = load_modern_request_vectors();
    assert_eq!(
        cases(&requests).len(),
        98,
        "Request classification (`fixtures/modern/modern-request-vectors.json`, 98 cases)"
    );
    let by_reference = requests
        .get("by_reference")
        .and_then(Value::as_array)
        .expect("modern-request-vectors.json: `by_reference` is not an array");
    assert_eq!(
        by_reference.len(),
        1,
        "By-reference cases (`fixtures/modern/modern-request-vectors.json`, 1 entries)"
    );

    assert_eq!(
        cases(&load_header_encoding_vectors()).len(),
        51,
        "Value encoding and request construction \
         (`fixtures/modern/header-encoding-vectors.json`, 51 cases)"
    );
    assert_eq!(
        cases(&load_x_mcp_header_vectors()).len(),
        84,
        "x-mcp-header validation and projection \
         (`fixtures/modern/x-mcp-header-vectors.json`, 84 cases)"
    );
    assert_eq!(
        cases(&load_era_detection_vectors()).len(),
        38,
        "Era detection (`fixtures/modern/era-detection-vectors.json`, 38 cases)"
    );
}
