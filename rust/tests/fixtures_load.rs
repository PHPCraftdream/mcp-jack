mod common;

use std::collections::HashSet;

use common::fixtures::*;

#[test]
fn keys_load() {
    let v = load_keys().expect("load keys.json");
    // Current materialized keys.json: exactly 15 test keys.
    assert_eq!(v.keys.len(), 15);
    let ids: HashSet<_> = v.keys.iter().map(|k| k.kid.as_str()).collect();
    assert_eq!(ids.len(), v.keys.len());
}

#[test]
fn registry_load() {
    let v = load_registry().expect("load registry.json");
    // Current materialized registry.json: exactly 7 keys.
    assert_eq!(v.keys.len(), 7);
    let ids: HashSet<_> = v.keys.iter().map(|k| k.kid.as_str()).collect();
    assert_eq!(ids.len(), v.keys.len());
}

#[test]
fn request_vectors_load() {
    let v = load_request_vectors().expect("load request-vectors.json");
    // Current materialized request-vectors.json: exactly 85 cases, unique ids.
    assert_eq!(v.cases.len(), 85);
    let ids: HashSet<_> = v.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), v.cases.len());
}

#[test]
fn admin_vectors_load() {
    let v = load_admin_vectors().expect("load admin-vectors.json");
    // Current materialized admin-vectors.json: exactly 94 cases, unique ids.
    assert_eq!(v.cases.len(), 94);
    let ids: HashSet<_> = v.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), v.cases.len());
    // Runner contract: every sequence has at least one step.
    for case in &v.cases {
        assert!(!case.steps.is_empty(), "case {} has no steps", case.id);
    }
}

#[test]
fn key_vectors_load() {
    let v = load_key_vectors().expect("load key-vectors.json");
    // Current materialized key-vectors.json: exactly 24 cases, unique ids.
    assert_eq!(v.cases.len(), 24);
    let ids: HashSet<_> = v.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), v.cases.len());
}

#[test]
fn response_vectors_load() {
    let v = load_response_vectors().expect("load response-vectors.json");
    // Current materialized response-vectors.json: exactly 14 cases, unique ids.
    assert_eq!(v.cases.len(), 14);
    let ids: HashSet<_> = v.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), v.cases.len());
}

#[test]
fn load_vectors_load() {
    let v = load_load_vectors().expect("load load-vectors.json");
    // Current materialized load-vectors.json: registry documents only,
    // exactly 19 registries with unique ids.
    assert_eq!(v.registries.len(), 19);
    let registry_ids: HashSet<_> = v.registries.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(registry_ids.len(), v.registries.len());
}

#[test]
fn state_file_vectors_load() {
    let v = load_state_file_vectors().expect("load state-file-vectors.json");
    // Current materialized state-file-vectors.json: exactly 18 cases, unique
    // ids, each expecting valid or invalid.
    assert_eq!(v.cases.len(), 18);
    let ids: HashSet<_> = v.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), v.cases.len());
    for case in &v.cases {
        assert!(
            case.expect == "valid" || case.expect == "invalid",
            "case {}: unknown expect {}",
            case.id,
            case.expect
        );
    }
}
