mod common;

use std::collections::HashSet;

use common::fixtures::*;

#[test]
fn keys_load() {
    let v = load_keys().expect("load keys.json");
    assert!(v.keys.len() >= 15);
    let ids: HashSet<_> = v.keys.iter().map(|k| k.kid.as_str()).collect();
    assert_eq!(ids.len(), v.keys.len());
}

#[test]
fn registry_load() {
    let v = load_registry().expect("load registry.json");
    assert!(v.keys.len() >= 7);
    let ids: HashSet<_> = v.keys.iter().map(|k| k.kid.as_str()).collect();
    assert_eq!(ids.len(), v.keys.len());
}

#[test]
fn request_vectors_load() {
    let v = load_request_vectors().expect("load request-vectors.json");
    assert!(v.cases.len() >= 79);
    let ids: HashSet<_> = v.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), v.cases.len());
    // Runner contract: every case's state.policy names a loaded policy.
    for case in &v.cases {
        assert!(
            v.policies.contains_key(case.state.policy.as_str()),
            "case {} policy {} not in policies",
            case.id,
            case.state.policy
        );
    }
}

#[test]
fn admin_vectors_load() {
    let v = load_admin_vectors().expect("load admin-vectors.json");
    assert!(v.cases.len() >= 71);
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
    assert!(v.cases.len() >= 24);
    let ids: HashSet<_> = v.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), v.cases.len());
}

#[test]
fn pattern_vectors_load() {
    let v = load_pattern_vectors().expect("load pattern-vectors.json");
    assert!(v.cases.len() >= 22);
    let ids: HashSet<_> = v.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), v.cases.len());
}

#[test]
fn response_vectors_load() {
    let v = load_response_vectors().expect("load response-vectors.json");
    assert!(v.cases.len() >= 14);
    let ids: HashSet<_> = v.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), v.cases.len());
}

#[test]
fn load_vectors_load() {
    let v = load_load_vectors().expect("load load-vectors.json");
    assert!(v.policies.len() >= 17);
    assert!(v.registries.len() >= 15);
    // Ids repeat across the two collections (valid-default, ...): check each alone.
    let policy_ids: HashSet<_> = v.policies.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(policy_ids.len(), v.policies.len());
    let registry_ids: HashSet<_> = v.registries.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(registry_ids.len(), v.registries.len());
}

#[test]
fn default_policy_load() {
    let v = load_default_policy().expect("load policy.json");
    let rules = v
        .get("rules")
        .and_then(|r| r.as_array())
        .expect("rules array");
    assert!(!rules.is_empty());
}

#[test]
fn wildcard_policy_load() {
    let v = load_wildcard_policy().expect("load policy-wildcard.json");
    let rules = v
        .get("rules")
        .and_then(|r| r.as_array())
        .expect("rules array");
    assert!(!rules.is_empty());
}
