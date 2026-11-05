//! Conformance runner: every request-vectors.json case through the verifier.

mod common;

use std::fs;
use std::sync::Arc;

use common::fixtures::{self, RequestCase, RequestVectors};
use common::harness;

use mcp_jack::encoding::decode_b64url;
use mcp_jack::server::audit::{AuditSink, MemoryAuditSink};
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::policy::Policy;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, Config, Request, Verifier};

fn seed_registry(state: &MemoryState, registry: &fixtures::RegistryDocument) {
    // kind omitted in a fixture means "human" (spec 02 section 1); the Go
    // runner misses this default, the Rust side must not copy that gap.
    state
        .update(&mut |edit| {
            for e in &registry.keys {
                edit.put_key(RegistryEntry {
                    kid: e.kid.clone(),
                    public_key: e.public_key.clone(),
                    name: e.name.clone(),
                    kind: e.kind.clone().unwrap_or_else(|| "human".to_string()),
                    scopes: e.scopes.clone(),
                    not_before: e.not_before,
                    not_after: e.not_after,
                });
            }
            Ok(())
        })
        .expect("seed registry");
}

fn check_outcome(
    label: &str,
    res: &mcp_jack::server::verify::VerifyResult,
    case: &RequestCase,
    sink: &MemoryAuditSink,
) {
    let want = &case.expect;
    match want.result.as_str() {
        "accept" => assert!(
            res.accepted,
            "case {}: got reject {} {}",
            label, res.http_status, res.code
        ),
        "reject" => assert!(!res.accepted, "case {}: got accept, want reject", label),
        other => panic!("case {}: unknown expectation {}", label, other),
    }
    if res.accepted {
        assert_eq!(res.kid, want.kid, "case {}: kid", label);
    } else {
        assert_eq!(
            res.http_status as i64, want.http_status,
            "case {}: http_status",
            label
        );
        assert_eq!(res.code, want.code, "case {}: code", label);
    }
    assert_eq!(
        res.nonce_recorded, want.nonce_recorded,
        "case {}: nonce_recorded",
        label
    );
    harness::check_audit(label, &res.audit, &want.audit, sink);
    if let Some(want_structured) = &want.structured {
        // Native expectations may embed the "<b64u43>" placeholder.
        assert!(
            harness::structured_matches(
                want_structured,
                res.structured.as_ref().unwrap_or(&serde_json::Value::Null)
            ),
            "case {}: structured result, want {:?}, got {:?}",
            label,
            want_structured,
            res.structured
        );
    }
}

fn run_case(vectors: &RequestVectors, registry: &fixtures::RegistryDocument, case: &RequestCase) {
    let label = &case.id;
    let body = decode_b64url(&case.request.body_b64u).expect("body_b64u");
    let policy_file = vectors
        .policies
        .get(case.state.policy.as_str())
        .unwrap_or_else(|| panic!("case {}: unknown policy {}", label, case.state.policy));
    let bytes = fs::read(fixtures::fixture_path(policy_file))
        .unwrap_or_else(|e| panic!("case {}: read policy {}: {}", label, policy_file, e));
    let policy = Arc::new(
        Policy::parse(&bytes)
            .unwrap_or_else(|e| panic!("case {}: policy parses: {}", label, e.reason)),
    );

    // Seeding at now=0 mirrors the Go runner; retain_until governs liveness
    // at the case clock.
    let nonces = NonceStore::new();
    for n in &case.state.nonce_cache {
        nonces.check_and_record(&n.kid, &n.nonce, 0, n.retain_until);
    }

    let state = MemoryState::new();
    seed_registry(&state, registry);

    let sink = Arc::new(MemoryAuditSink::new());
    let audit: Arc<dyn AuditSink> = sink.clone();
    let now = case.state.now;
    let now_clock: Clock = Arc::new(move || now);
    let verifier = Verifier::new(Config {
        aud: case.state.aud.clone(),
        state: Arc::new(state),
        nonces: Arc::new(nonces),
        policy,
        audit: Some(audit),
        // The real jack.* tools; OS randomness is fine here because the
        // expectations use the "<b64u43>" placeholder, never a literal code.
        native: Some(Arc::new(Native::new(NativeOptions::default()))),
        window_seconds: case.state.window_seconds,
        now: now_clock,
    })
    .expect("verifier");

    // Header names are case-insensitive per the runner rules.
    let auth_values: Vec<String> = case
        .request
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("Jack-Auth"))
        .map(|h| h.value.clone())
        .collect();

    let req = Request {
        method: case.request.method.clone(),
        target: case.request.target.clone(),
        auth_values,
        body,
    };
    let res = verifier.verify(&req);
    check_outcome(label, &res, case, &sink);
}

#[test]
fn request_vectors_run() {
    let vectors = fixtures::load_request_vectors().expect("load request-vectors.json");
    assert!(
        !vectors.cases.is_empty(),
        "request-vectors.json has no cases"
    );
    let registry = fixtures::load_registry().expect("load registry.json");
    for case in &vectors.cases {
        run_case(&vectors, &registry, case);
    }
}
