//! Runner for `spec/fixtures/modern/x-mcp-header-vectors.json`: the 84
//! `x-mcp-header` validation and projection cases of spec 04 `C5`, `C6` and
//! `C11`, driven through `validate_annotations` and `project_arguments`.

use serde_json::Value;

use mcp_jack::client::modern::{project_arguments, validate_annotations};

use super::fixtures::*;

/// The case count stated in `spec/tests/modern/CASES.md`.
const EXPECTED_CASES: usize = 84;

/// `kind: "validate"` / `"validate-event"`: the `inputSchema` of `tool` or
/// `event` either validates or fails with the stated reason token.
fn check_validate(case: &Value, holder: &str) -> Result<(), String> {
    let schema = at(case, &[holder, "inputSchema"]);
    let outcome = validate_annotations(schema);
    let valid = at(case, &["expect", "valid"])
        .as_bool()
        .unwrap_or_else(|| panic!("case {}: `expect.valid` is not a boolean", case_id(case)));
    if valid {
        let reason = opt_text(case, &["expect", "reason"]);
        if let Some(reason) = reason {
            return Err(format!("valid case carries reason `{}`", reason));
        }
        match outcome {
            Ok(()) => Ok(()),
            Err(e) => Err(format!("validate_annotations failed: {}", e.as_str())),
        }
    } else {
        let reason = text(case, &["expect", "reason"]);
        match outcome {
            Ok(()) => Err(format!(
                "validate_annotations succeeded, expected `{}`",
                reason
            )),
            Err(e) if e.as_str() == reason => Ok(()),
            Err(e) => Err(format!(
                "validate_annotations failed with `{}`, expected `{}`",
                e.as_str(),
                reason
            )),
        }
    }
}

/// `kind: "project"` / `"project-event"`: the arguments of one `tool` or
/// `event` inputSchema become exactly the expected headers, or the projection
/// is refused with the stated reason token.
fn check_project(case: &Value, holder: &str) -> Result<(), String> {
    let schema = at(case, &[holder, "inputSchema"]);
    let arguments = at(case, &["arguments"]);
    let outcome = project_arguments(schema, arguments);
    match text(case, &["expect", "outcome"]) {
        "headers" => {
            let expected = header_pairs(case, at(case, &["expect", "headers"]));
            match outcome {
                Ok(headers) if headers == expected => Ok(()),
                Ok(headers) => Err(format!("headers {:?} != expected {:?}", headers, expected)),
                Err(e) => Err(format!("project_arguments failed: {}", e.as_str())),
            }
        }
        "refuse" => {
            let reason = text(case, &["expect", "reason"]);
            match outcome {
                Ok(headers) => Err(format!(
                    "project_arguments succeeded as {:?}, expected `{}`",
                    headers, reason
                )),
                Err(e) if e.as_str() == reason => Ok(()),
                Err(e) => Err(format!(
                    "project_arguments failed with `{}`, expected `{}`",
                    e.as_str(),
                    reason
                )),
            }
        }
        other => Err(format!("unknown `expect.outcome` `{}`", other)),
    }
}

/// Runs every assertion of one case, returning the first failure.
fn check_case(case: &Value) -> Result<(), String> {
    match text(case, &["kind"]) {
        "validate" => check_validate(case, "tool"),
        "validate-event" => check_validate(case, "event"),
        "project" => check_project(case, "tool"),
        "project-event" => check_project(case, "event"),
        other => Err(format!("unknown `kind` `{}`", other)),
    }
}

#[test]
fn x_mcp_header_vectors() {
    let document = load_x_mcp_header_vectors();
    let listed = cases(&document);
    assert_eq!(
        listed.len(),
        EXPECTED_CASES,
        "x-mcp-header validation and projection \
         (`fixtures/modern/x-mcp-header-vectors.json`, 84 cases)"
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
        "VECTOR-SUMMARY corpus=x-mcp-header sdk=rust pass={} excluded=0 deviation=0",
        pass
    );

    if pass != EXPECTED_CASES {
        let listing: Vec<String> = failures
            .iter()
            .map(|(id, message)| format!("  {}: {}", id, message))
            .collect();
        panic!(
            "x-mcp-header vectors: {}/{} passed; failures:\n{}",
            pass,
            EXPECTED_CASES,
            listing.join("\n")
        );
    }
}
