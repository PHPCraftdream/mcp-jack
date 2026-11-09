//! Conformance runner: every admin-vectors.json sequence through the real
//! verifier and the real native tools (spec tests README runner rules).

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::fixtures;
use common::harness;

use mcp_jack::encoding::{decode_b64url, decode_b64url_fixed, encode_b64url};
use mcp_jack::server::audit::{AuditSink, MemoryAuditSink};
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{InviteRecord, MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::state_file::FileState;
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

/// Seeds the store from the fixture state (entries and invite records pass
/// through verbatim; admin defaults to false when the fixture omits it).
fn seed_state(state: &MemoryState, case: &fixtures::AdminCase) {
    state
        .update(&mut |edit| {
            for e in &case.state.registry {
                edit.put_key(RegistryEntry {
                    kid: e.kid.clone(),
                    public_key: e.public_key.clone(),
                    name: e.name.clone(),
                    admin: e.admin,
                    not_before: e.not_before,
                    not_after: e.not_after,
                });
            }
            for i in &case.state.invites {
                edit.put_invite(InviteRecord {
                    invite_id: i.invite_id.clone(),
                    admin: i.admin,
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

fn run_step(
    case: &fixtures::AdminCase,
    i: usize,
    step: &fixtures::Step,
    verifier: &Verifier,
    state: &dyn StateStore,
    sink: &MemoryAuditSink,
    raw_state_path: Option<&Path>,
) -> bool {
    let label = format!("{} step {i}", case.id);
    let want = &step.expect;
    let before_view = state.view();
    let before_bytes = raw_state_path.map(|path| {
        fs::read(path).unwrap_or_else(|e| panic!("case {label}: read state before verify: {e}"))
    });

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
    if !res.accepted {
        assert_eq!(
            state.view(),
            before_view,
            "case {label}: rejected step changed StateView"
        );
        if let (Some(path), Some(before)) = (raw_state_path, before_bytes.as_ref()) {
            let after = fs::read(path)
                .unwrap_or_else(|e| panic!("case {label}: read rejected state bytes: {e}"));
            assert_eq!(
                after, *before,
                "case {label}: rejection changed raw state bytes"
            );
        }
    }
    harness::check_audit(&label, &res.audit, &want.audit, sink);
    // Forwarded accepts carry the verified caller identity; native jack.*
    // steps (and rejections) carry none (02 section 3).
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
        assert!(
            harness::structured_matches(
                want_structured,
                res.structured.as_ref().unwrap_or(&serde_json::Value::Null)
            ),
            "case {label}: structured result, want {want_structured}, got {:?}",
            res.structured
        );
    }

    check_after(case, i, state);
    res.accepted
}

fn check_after(case: &fixtures::AdminCase, i: usize, state: &dyn StateStore) {
    let label = format!("{} step {i}", case.id);
    let after = case.steps[i].expect.after.as_ref().unwrap_or_else(|| {
        panic!("case {label}: missing after expectation (runner rules require it)")
    });
    let got_users = harness::after_users_json(state);
    let want_users = serde_json::to_value(&after.users)
        .unwrap_or_else(|e| panic!("case {label}: serialize after.users: {e}"));
    assert_eq!(
        got_users, want_users,
        "case {label}: after.users, want {want_users}, got {got_users}"
    );
    let got_invites = harness::stored_invites_sorted(state);
    assert_eq!(
        got_invites.len(),
        after.invites.len(),
        "case {label}: after.invites length"
    );
    for (idx, (want_inv, got_inv)) in after.invites.iter().zip(&got_invites).enumerate() {
        assert!(
            harness::structured_matches(want_inv, got_inv),
            "case {label}: after.invites[{idx}], want {want_inv}, got {got_inv}"
        );
    }
}

fn run_case(case: &fixtures::AdminCase) {
    let state = Arc::new(MemoryState::new());
    check_seeded_ids(case);
    seed_state(&state, case);

    let nonces = Arc::new(NonceStore::new());
    seed_nonces(case, &nonces);
    let sink = Arc::new(MemoryAuditSink::new());
    let native = Arc::new(Native::new(NativeOptions::default()));
    let now = case.state.now;
    let now_clock: Clock = Arc::new(move || now);
    let state_trait: Arc<dyn StateStore> = state.clone();
    let verifier = make_verifier(
        case,
        state_trait,
        Arc::clone(&nonces),
        Arc::clone(&sink),
        native,
        Arc::clone(&now_clock),
    );

    for (i, step) in case.steps.iter().enumerate() {
        run_step(case, i, step, &verifier, state.as_ref(), &sink, None);
    }
}

fn seed_nonces(case: &fixtures::AdminCase, nonces: &NonceStore) {
    for n in &case.state.nonce_cache {
        nonces.check_and_record(&n.kid, &n.nonce, 0, n.retain_until);
    }
}

fn make_verifier(
    case: &fixtures::AdminCase,
    state: Arc<dyn StateStore>,
    nonces: Arc<NonceStore>,
    sink: Arc<MemoryAuditSink>,
    native: Arc<Native>,
    now_clock: Clock,
) -> Verifier {
    let audit: Arc<dyn AuditSink> = sink;
    Verifier::new(Config {
        aud: case.state.aud.clone(),
        state,
        nonces,
        audit: Some(audit),
        native: Some(native),
        window_seconds: case.state.window_seconds,
        now: now_clock,
    })
    .expect("verifier")
}

static TEMP_DIR_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct TempCaseDir(PathBuf);

impl TempCaseDir {
    fn new(case_id: &str) -> Self {
        let unique = TEMP_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "admin-conformance-{}-{unique}-{case_id}",
                std::process::id()
            ));
        fs::create_dir_all(&path).unwrap_or_else(|e| {
            panic!(
                "case {case_id}: create temporary state directory {}: {e}",
                path.display()
            )
        });
        Self(path)
    }

    fn state_path(&self) -> PathBuf {
        self.0.join("state.json")
    }
}

impl Drop for TempCaseDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn raw_case_state(case: &fixtures::AdminCase) -> serde_json::Value {
    let vectors: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(fixtures::fixture_path("admin-vectors.json"))
            .expect("read raw admin-vectors.json"),
    )
    .expect("parse raw admin-vectors.json");
    let raw_case = vectors["cases"]
        .as_array()
        .and_then(|cases| cases.iter().find(|candidate| candidate["id"] == case.id))
        .unwrap_or_else(|| panic!("case {}: missing raw case fixture", case.id));
    raw_case["state"].clone()
}

fn seed_file_state(path: &Path, case: &fixtures::AdminCase) {
    let raw_state = raw_case_state(case);
    let document = serde_json::json!({
        "version": 1,
        "keys": raw_state["registry"],
        "invites": raw_state["invites"],
    });
    let bytes = serde_json::to_vec(&document).expect("serialize raw initial state document");
    fs::write(path, &bytes).unwrap_or_else(|e| {
        panic!(
            "case {}: write initial state {}: {e}",
            case.id,
            path.display()
        )
    });
}

fn run_file_case(case: &fixtures::AdminCase) {
    check_seeded_ids(case);
    let temp = TempCaseDir::new(&case.id);
    let path = temp.state_path();
    seed_file_state(&path, case);
    let initial_bytes = fs::read(&path).expect("read seeded state file");
    let mut state = Arc::new(FileState::open(&path).expect("open seeded FileState"));
    assert_eq!(
        fs::read(&path).expect("read state after open"),
        initial_bytes,
        "case {}: opening state must not rewrite raw fixture members",
        case.id
    );

    let nonces = Arc::new(NonceStore::new());
    seed_nonces(case, &nonces);
    let sink = Arc::new(MemoryAuditSink::new());
    let native = Arc::new(Native::new(NativeOptions::default()));
    let now = case.state.now;
    let now_clock: Clock = Arc::new(move || now);

    for (i, step) in case.steps.iter().enumerate() {
        let state_trait: Arc<dyn StateStore> = state.clone();
        let verifier = make_verifier(
            case,
            state_trait,
            Arc::clone(&nonces),
            Arc::clone(&sink),
            Arc::clone(&native),
            Arc::clone(&now_clock),
        );
        let bytes_before_step = fs::read(&path).expect("read state before sequence step");
        let accepted = run_step(case, i, step, &verifier, state.as_ref(), &sink, Some(&path));
        let bytes_after_step = fs::read(&path).expect("read state after sequence step");
        check_disk_document(
            case,
            i,
            &bytes_after_step,
            state.as_ref(),
            bytes_after_step != bytes_before_step,
        );

        // Reopen after every step. FileState::open is a pure load and must
        // preserve the just-observed bytes; the reopened instance handles the
        // next request while the sequence's nonce cache and audit sink persist.
        let reopened = Arc::new(
            FileState::open(&path)
                .unwrap_or_else(|e| panic!("case {} step {i}: reopen state: {e}", case.id)),
        );
        assert_eq!(
            fs::read(&path).expect("read after reopen"),
            bytes_after_step,
            "case {} step {i}: reopening state rewrote bytes",
            case.id
        );
        assert_eq!(
            reopened.view(),
            state.view(),
            "case {} step {i}: reopened state view",
            case.id
        );
        check_after(case, i, reopened.as_ref());
        if !accepted {
            assert_eq!(
                bytes_after_step, bytes_before_step,
                "case {} step {i}: rejected operation changed original raw bytes",
                case.id
            );
        }
        state = reopened;
    }
}

fn check_disk_document(
    case: &fixtures::AdminCase,
    i: usize,
    bytes: &[u8],
    state: &dyn StateStore,
    was_written: bool,
) {
    let label = format!("{} step {i}", case.id);
    let document: serde_json::Value = serde_json::from_slice(bytes)
        .unwrap_or_else(|e| panic!("case {label}: parse persisted document: {e}"));
    let raw_invites = document["invites"]
        .as_array()
        .unwrap_or_else(|| panic!("case {label}: persisted invites is not an array"));
    let view = state.view();
    let mut decoded_invites = Vec::with_capacity(raw_invites.len());
    for raw in raw_invites {
        let stored: InviteRecord = serde_json::from_value(raw.clone())
            .unwrap_or_else(|e| panic!("case {label}: decode persisted invite: {e}"));
        let ttl = raw.get("key_ttl_seconds");
        match stored.key_ttl_seconds {
            None => assert!(
                ttl.is_none(),
                "case {label}: None TTL must be absent, got {ttl:?}"
            ),
            Some(value) => assert_eq!(
                ttl.and_then(serde_json::Value::as_i64),
                Some(value),
                "case {label}: persisted TTL must be an integer, never null"
            ),
        }
        decoded_invites.push(stored);
    }
    decoded_invites.sort_by(|a, b| a.invite_id.cmp(&b.invite_id));
    assert_eq!(
        decoded_invites, view.invites,
        "case {label}: persisted invites differ from StateView"
    );

    if was_written {
        let expected_keys = serde_json::to_value(&view.keys).expect("serialize state keys");
        let expected_invites =
            serde_json::to_value(&view.invites).expect("serialize state invites");
        assert_eq!(
            document["keys"], expected_keys,
            "case {label}: persisted keys serialization"
        );
        assert_eq!(
            document["invites"], expected_invites,
            "case {label}: persisted invites serialization"
        );

        let after = case.steps[i]
            .expect
            .after
            .as_ref()
            .expect("after expectation");
        let mut disk_keys = document["keys"].as_array().expect("keys array").clone();
        disk_keys.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        let expected_users = serde_json::to_value(&after.users).expect("serialize after.users");
        assert_eq!(
            serde_json::Value::Array(disk_keys),
            expected_users,
            "case {label}: persisted full keys versus literal after.users"
        );
        let mut disk_invites = raw_invites.to_vec();
        disk_invites.sort_by(|a, b| {
            a["invite_id"]
                .as_str()
                .cmp(&b["invite_id"].as_str())
                .then(a["created_at"].as_i64().cmp(&b["created_at"].as_i64()))
        });
        assert_eq!(
            disk_invites.len(),
            after.invites.len(),
            "case {label}: disk invite count"
        );
        for (idx, (got, want)) in disk_invites.iter().zip(&after.invites).enumerate() {
            assert!(
                harness::structured_matches(want, got),
                "case {label}: persisted literal invite[{idx}], want {want}, got {got}"
            );
        }
    }
}

#[test]
fn admin_vectors_run() {
    let vectors = fixtures::load_admin_vectors().expect("load admin-vectors.json");
    assert!(!vectors.cases.is_empty(), "admin-vectors.json has no cases");
    for case in &vectors.cases {
        run_case(case);
        run_file_case(case);
    }
}
