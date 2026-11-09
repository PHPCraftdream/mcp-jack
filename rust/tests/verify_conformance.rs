//! Conformance runner: every request-vectors.json case through the verifier.

mod common;

use std::sync::Arc;

use common::fixtures::{self, RequestCase};
use common::harness;

use mcp_jack::encoding::decode_b64url;
use mcp_jack::server::audit::{AuditSink, MemoryAuditSink};
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, Config, Request, Verifier};

fn seed_registry(state: &MemoryState, registry: &fixtures::RegistryDocument) {
    // Entries pass through verbatim: admin defaults to false when absent
    // (spec 02 section 1), not_before/not_after as written.
    state
        .update(&mut |edit| {
            for e in &registry.keys {
                edit.put_key(RegistryEntry {
                    kid: e.kid.clone(),
                    public_key: e.public_key.clone(),
                    name: e.name.clone(),
                    admin: e.admin,
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
    // Counterfactual identity pair: forwarded accepts carry the verified
    // caller identity (02 section 3); native jack.* accepts and rejections
    // carry none. Reverting the hand-off fails the Some side; leaking
    // identity onto native accepts or rejections fails the None side.
    if let Some(want_ident) = &want.identity {
        let got = res
            .identity
            .as_ref()
            .unwrap_or_else(|| panic!("case {label}: forwarded accept must carry identity"));
        assert_eq!(got.kid(), want_ident.kid, "case {label}: identity kid");
        assert_eq!(got.name(), want_ident.name, "case {label}: identity name");
        assert_eq!(
            got.admin(),
            want_ident.admin,
            "case {label}: identity admin"
        );
    } else {
        assert!(
            res.identity.is_none(),
            "case {label}: identity must be absent, got {:?}",
            res.identity.as_ref().map(|i| i.name())
        );
    }
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

fn run_case(
    _vectors: &common::fixtures::RequestVectors,
    registry: &fixtures::RegistryDocument,
    case: &RequestCase,
) {
    let label = &case.id;
    let body = decode_b64url(&case.request.body_b64u).expect("body_b64u");

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
    let _ = &vectors.registry;
    for case in &vectors.cases {
        run_case(&vectors, &registry, case);
    }
}
