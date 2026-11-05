//! Conformance runner: every admin-vectors.json sequence through the real
//! verifier and the real native tools (spec tests README runner rules).

mod common;

use std::sync::Arc;

use common::fixtures::{self};
use common::harness;

use mcp_jack::encoding::{decode_b64url, decode_b64url_fixed, encode_b64url};
use mcp_jack::server::audit::{AuditSink, MemoryAuditSink};
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::policy::Policy;
use mcp_jack::server::state::{InviteRecord, MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, Config, Request, Verifier};
use sha2::{Digest, Sha256};

/// The generator's seeded invite codes: base64url(SHA-256("seeded invite <label>")).
fn seeded_code(label: &str) -> String {
    encode_b64url(&Sha256::digest(format!("seeded invite {label}").as_bytes()))
}

/// base64url(SHA-256(code bytes)) (gen-fixtures.mjs inviteIdOf).
fn invite_id_of(code: &str) -> String {
    let raw = decode_b64url_fixed(code, 32).expect("seeded code is canonical 32-byte b64u");
    encode_b64url(&Sha256::digest(raw.as_slice()))
}

/// The labels gen-fixtures.mjs actually seeds (grep inv(' there).
const SEEDED_LABELS: [&str; 3] = ["i1", "live", "old"];

/// Asserts each seeded fixture invite id equals the id derived from the
/// documented code derivation for one of the generator's seeded labels.
fn check_seeded_ids(case: &fixtures::AdminCase) {
    for i in &case.state.invites {
        let derived: Vec<String> = SEEDED_LABELS
            .iter()
            .map(|l| invite_id_of(&seeded_code(l)))
            .collect();
        assert!(
            derived.contains(&i.invite_id),
            "case {}: seeded invite_id {} does not match any documented derivation",
            case.id,
            i.invite_id
        );
    }
}

/// Loads policy.json for the one policy admin cases use.
fn policy_for(case: &fixtures::AdminCase) -> Arc<Policy> {
    match case.state.policy.as_str() {
        "default" => {
            let bytes = std::fs::read(fixtures::fixture_path("policy.json"))
                .unwrap_or_else(|e| panic!("case {}: read policy.json: {}", case.id, e));
            Arc::new(
                Policy::parse(&bytes).unwrap_or_else(|e| {
                    panic!("case {}: policy.json parses: {}", case.id, e.reason)
                }),
            )
        }
        name => panic!("case {}: unknown admin policy {name}", case.id),
    }
}

/// Seeds the store from the fixture state (spec 02 section 1: omitted kind
/// means human; an omitted stored invite kind stays empty).
fn seed_state(state: &MemoryState, case: &fixtures::AdminCase) {
    state
        .update(&mut |edit| {
            for e in &case.state.registry {
                edit.put_key(RegistryEntry {
                    kid: e.kid.clone(),
                    public_key: e.public_key.clone(),
                    name: e.name.clone(),
                    kind: e.kind.clone().unwrap_or_else(|| "human".to_owned()),
                    scopes: e.scopes.clone(),
                    not_before: e.not_before,
                    not_after: e.not_after,
                });
            }
            // An omitted stored kind stays empty; the native tools apply the
            // human default at read time (kind_or_human).
            for i in &case.state.invites {
                edit.put_invite(InviteRecord {
                    invite_id: i.invite_id.clone(),
                    scopes: i.scopes.clone(),
                    kind: i.kind.clone().unwrap_or_default(),
                    created_by: i.created_by.clone(),
                    created_at: i.created_at,
                    expires_at: i.expires_at,
                    key_ttl_seconds: i.key_ttl_seconds,
                });
            }
            Ok(())
        })
        .unwrap_or_else(|e| panic!("case {}: seed state: {:?}", case.id, e));
}

/// Builds the users array of an after expectation from the store: sorted by
/// name, scopes sorted lexicographically (the generator's JS default sort).
fn after_users(state: &MemoryState) -> serde_json::Value {
    let mut keys = state.view().keys;
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    let users: Vec<serde_json::Value> = keys
        .iter()
        .map(|e| {
            let mut scopes = e.scopes.clone();
            scopes.sort();
            serde_json::json!({
                "name": e.name,
                "kid": e.kid,
                "kind": if e.kind.is_empty() { "human" } else { &e.kind },
                "scopes": scopes,
                "not_before": e.not_before,
                "not_after": e.not_after,
            })
        })
        .collect();
    serde_json::Value::Array(users)
}

fn run_step(
    case: &fixtures::AdminCase,
    i: usize,
    step: &fixtures::Step,
    verifier: &Verifier,
    state: &MemoryState,
    sink: &MemoryAuditSink,
    now: i64,
) {
    let label = format!("{} step {i}", case.id);
    let want = &step.expect;

    let body = decode_b64url(&step.request.body_b64u)
        .unwrap_or_else(|e| panic!("case {label}: decode body_b64u: {e:?}"));
    // Header names are case-insensitive per the runner rules.
    let auth_values: Vec<String> = step
        .request
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("Jack-Auth"))
        .map(|h| h.value.clone())
        .collect();
    let req = Request {
        method: step.request.method.clone(),
        target: step.request.target.clone(),
        auth_values,
        body,
    };
    let res = verifier.verify(&req);

    match want.result.as_str() {
        "accept" => {
            assert!(
                res.accepted,
                "case {label}: got reject {} {}",
                res.http_status, res.code
            );
            assert_eq!(res.kid, want.kid, "case {label}: kid");
        }
        "reject" => {
            assert!(!res.accepted, "case {label}: got accept, want reject");
            assert_eq!(
                res.http_status as i64, want.http_status,
                "case {label}: http_status"
            );
            assert_eq!(res.code, want.code, "case {label}: code");
        }
        other => panic!("case {label}: unknown expectation {other}"),
    }
    assert_eq!(
        res.nonce_recorded, want.nonce_recorded,
        "case {label}: nonce_recorded"
    );
    harness::check_audit(&label, &res.audit, &want.audit, sink);
    if let Some(want_structured) = &want.structured {
        assert!(
            harness::structured_matches(
                want_structured,
                res.structured.as_ref().unwrap_or(&serde_json::Value::Null)
            ),
            "case {label}: structured result, want {want_structured}, got {:?}",
            res.structured
        );
    }

    // Every sequence step carries an after summary.
    let after = want.after.as_ref().unwrap_or_else(|| {
        panic!("case {label}: missing after expectation (runner rules require it)")
    });
    let got_users = after_users(state);
    let want_users = serde_json::to_value(&after.users)
        .unwrap_or_else(|e| panic!("case {label}: serialize after.users: {e}"));
    assert_eq!(
        got_users, want_users,
        "case {label}: after.users, want {want_users}, got {got_users}"
    );
    // Used/revoked invites leave the store, so live == stored && unexpired.
    let live_invites = state
        .view()
        .invites
        .iter()
        .filter(|inv| now < inv.expires_at)
        .count() as i64;
    assert_eq!(live_invites, after.invites, "case {label}: after.invites");
}

fn run_case(case: &fixtures::AdminCase) {
    let state = Arc::new(MemoryState::new());
    check_seeded_ids(case);
    seed_state(&state, case);

    let nonces = NonceStore::new();
    for n in &case.state.nonce_cache {
        nonces.check_and_record(&n.kid, &n.nonce, 0, n.retain_until);
    }

    let sink = Arc::new(MemoryAuditSink::new());
    let audit: Arc<dyn AuditSink> = sink.clone();
    let now = case.state.now;
    let now_clock: Clock = Arc::new(move || now);
    let verifier = Verifier::new(Config {
        aud: case.state.aud.clone(),
        state: Arc::clone(&state) as Arc<dyn StateStore>,
        nonces: Arc::new(nonces),
        policy: policy_for(case),
        audit: Some(audit),
        // Real jack.* tools with OS randomness: expectations use the
        // "<b64u43>" placeholder, never a literal code.
        native: Some(Arc::new(Native::new(NativeOptions::default()))),
        window_seconds: case.state.window_seconds,
        now: now_clock,
    })
    .expect("verifier");

    for (i, step) in case.steps.iter().enumerate() {
        run_step(case, i, step, &verifier, &state, &sink, now);
    }
}

#[test]
fn admin_vectors_run() {
    let vectors = fixtures::load_admin_vectors().expect("load admin-vectors.json");
    assert!(!vectors.cases.is_empty(), "admin-vectors.json has no cases");
    for case in &vectors.cases {
        run_case(case);
    }
}
