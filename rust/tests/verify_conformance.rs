//! Conformance runner: every request-vectors.json case through the verifier.

mod common;

use std::fs;
use std::sync::Arc;

use common::fixtures::{self, AuditExpect, RequestCase, RequestVectors};

use mcp_jack::encoding::decode_b64url;
use mcp_jack::error::{codes, JackError};
use mcp_jack::server::audit::{AuditSink, MemoryAuditSink};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::policy::Policy;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, Config, NativeCall, NativeResult, Request, Verifier};

/// Minimal native-tool double: admin tools enforce the caller's admin scope
/// (spec 03 section 4 rule 1) so the audit expectations of the vectors
/// (failure + code) are reproduced; everything else succeeds with an empty
/// structured result. The real jack.* tools are the native.rs task.
struct StubNative;

impl mcp_jack::server::verify::NativeTools for StubNative {
    fn call(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        c.target = c.kid.to_owned();
        let admin = c
            .caller
            .is_some_and(|e| e.scopes.iter().any(|s| s == "admin"));
        if c.tool.starts_with("jack.admin.") && !admin {
            return Err(JackError::new(
                403,
                codes::INSUFFICIENT_SCOPE,
                "stub: admin required",
            ));
        }
        Ok(NativeResult {
            structured: serde_json::Value::Null,
        })
    }
}

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

fn check_audit(
    label: &str,
    got: &Option<mcp_jack::server::audit::AuditEvent>,
    want: &Option<AuditExpect>,
    sink: &MemoryAuditSink,
) {
    match (want, got) {
        (None, Some(a)) => panic!("case {}: unexpected audit event {:?}", label, a),
        (Some(w), None) => panic!("case {}: missing audit event, want {:?}", label, w),
        (Some(w), Some(a)) => {
            let want_code = w.code.clone().unwrap_or_default();
            assert_eq!(a.tool, w.tool, "case {}: audit tool", label);
            assert_eq!(a.outcome, w.outcome, "case {}: audit outcome", label);
            assert_eq!(a.code, want_code, "case {}: audit code", label);
            assert_eq!(a.actor_kid, w.actor_kid, "case {}: audit actor_kid", label);
            // The sink must have recorded exactly this event.
            let events = sink.events();
            let last = events
                .last()
                .unwrap_or_else(|| panic!("case {}: audit sink empty", label));
            assert_eq!(last, a, "case {}: audit sink last event", label);
        }
        (None, None) => {}
    }
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
    check_audit(label, &res.audit, &want.audit, sink);
    if let Some(want_structured) = &want.structured {
        if res.native {
            // structuredContent comparison skipped: StubNative returns an empty
            // result; the real jack.* tools are the native.rs task.
        } else {
            assert_eq!(
                res.structured.as_ref(),
                Some(want_structured),
                "case {}: structured result",
                label
            );
        }
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
        native: Some(Arc::new(StubNative)),
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
