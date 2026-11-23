//! Runner for `spec/fixtures/modern/era-detection-vectors.json`: the 38 era
//! detection cases of spec 04 `C9`, driven through `detect_era`.

use serde_json::Value;

use mcp_jack::client::modern::{detect_era, VerifiedResponse};
use mcp_jack::modern::Era;

use super::fixtures::*;

/// The case count stated in `spec/tests/modern/CASES.md`.
const EXPECTED_CASES: usize = 38;

/// The expected era of one case: `None` for `"none"`.
fn era_of(value: &str) -> Option<Era> {
    match value {
        "modern" => Some(Era::Modern),
        "legacy" => Some(Era::Legacy),
        "none" => None,
        other => panic!("unknown `expect.era` `{}`", other),
    }
}

/// Runs every assertion of one case, returning the first failure.
fn check_case(case: &Value) -> Result<(), String> {
    let verified = at(case, &["response", "verified"])
        .as_bool()
        .unwrap_or_else(|| {
            panic!(
                "case {}: `response.verified` is not a boolean",
                case_id(case)
            )
        });
    let status = at(case, &["response", "status"])
        .as_u64()
        .unwrap_or_else(|| {
            panic!(
                "case {}: `response.status` is not an integer",
                case_id(case)
            )
        });
    let body_text = opt_text(case, &["response", "body_text"]).unwrap_or("");
    let client_versions: Vec<&str> = at(case, &["clientVersions"])
        .as_array()
        .unwrap_or_else(|| panic!("case {}: `clientVersions` is not an array", case_id(case)))
        .iter()
        .map(|version| {
            version.as_str().unwrap_or_else(|| {
                panic!(
                    "case {}: client version is not a string: {}",
                    case_id(case),
                    version
                )
            })
        })
        .collect();

    let detection = detect_era(
        &VerifiedResponse {
            verified,
            status: u16::try_from(status)
                .unwrap_or_else(|_| panic!("case {}: status out of range", case_id(case))),
            body: body_text.as_bytes(),
        },
        &client_versions,
    );

    let want_era = era_of(text(case, &["expect", "era"]));
    if detection.era != want_era {
        return Err(format!(
            "era {:?} != expected {:?}",
            detection.era, want_era
        ));
    }

    let want_action = text(case, &["expect", "action"]);
    if detection.action.as_str() != want_action {
        return Err(format!(
            "action `{}` != expected `{}`",
            detection.action.as_str(),
            want_action
        ));
    }

    match opt_text(case, &["expect", "reason"]) {
        None => {
            if let Some(reason) = detection.reason {
                return Err(format!("reason `{}`, expected none", reason.as_str()));
            }
        }
        Some(want) => match detection.reason {
            Some(reason) if reason.as_str() == want => {}
            Some(reason) => {
                return Err(format!(
                    "reason `{}` != expected `{}`",
                    reason.as_str(),
                    want
                ));
            }
            None => return Err(format!("no reason, expected `{}`", want)),
        },
    }

    let supported = at(case, &["expect"])
        .get("supported")
        .map(|listed| {
            listed
                .as_array()
                .unwrap_or_else(|| {
                    panic!("case {}: `expect.supported` is not an array", case_id(case))
                })
                .iter()
                .map(|version| {
                    version
                        .as_str()
                        .unwrap_or_else(|| {
                            panic!(
                                "case {}: supported entry is not a string: {}",
                                case_id(case),
                                version
                            )
                        })
                        .to_owned()
                })
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    if detection.supported != supported {
        return Err(format!(
            "supported {:?} != expected {:?}",
            detection.supported, supported
        ));
    }

    Ok(())
}

#[test]
fn era_detection_vectors() {
    let document = load_era_detection_vectors();
    let listed = cases(&document);
    assert_eq!(
        listed.len(),
        EXPECTED_CASES,
        "Era detection (`fixtures/modern/era-detection-vectors.json`, 38 cases)"
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
        "VECTOR-SUMMARY corpus=era-detection sdk=rust pass={} excluded=0 deviation=0",
        pass
    );

    if pass != EXPECTED_CASES {
        let listing: Vec<String> = failures
            .iter()
            .map(|(id, message)| format!("  {}: {}", id, message))
            .collect();
        panic!(
            "era detection vectors: {}/{} passed; failures:\n{}",
            pass,
            EXPECTED_CASES,
            listing.join("\n")
        );
    }
}
