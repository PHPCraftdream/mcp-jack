//! Linux-gated restart and crash tests for the durable nonce admission seam:
//! reopen after a simulated crash between the intent and the final
//! transaction, replay refusal after restart, and fail-closed clock step-back
//! after a purge. All clocks are injected; no real time is read.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use mcp_jack::user_key::ServerSigningKey;
use sha2::{Digest, Sha256};

use mcp_jack::auth_header::{format_request_auth, RequestAuth};
use mcp_jack::encoding::encode_b64url;
use mcp_jack::server::durable_admission::SharedDurableNonceStore;
use mcp_jack::server::durable_format::DurableStoreError;
use mcp_jack::server::durable_recovery::{inspect_recovery, reconcile_unknown};
use mcp_jack::server::durable_store::{DurableNonceStore, DurableStoreOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, Config, Request, Verifier};
use mcp_jack::signing::request_signing_string;

const AUD: &str = "candidate-vector-test";
const WINDOW: i64 = 30;

fn digest(name: &str) -> [u8; 32] {
    Sha256::digest(name.as_bytes()).into()
}

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "jack-rust-nonce-restart-{}",
            encode_b64url(&random)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn file(&self) -> PathBuf {
        self.0.join("nonce-store")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, dir_permissions(0o700));
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn dir_permissions(mode: u32) -> fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    fs::Permissions::from_mode(mode)
}

/// Scripted clock: replays the samples in order, then repeats the last one.
#[derive(Clone)]
struct ScriptedClock {
    state: Arc<Mutex<ClockState>>,
}

struct ClockState {
    queue: Vec<i64>,
    index: usize,
    fault_offset: Option<usize>,
    fault: Option<Box<dyn FnMut() + Send>>,
}

impl ScriptedClock {
    fn new(samples: &[i64]) -> Self {
        Self {
            state: Arc::new(Mutex::new(ClockState {
                queue: samples.to_vec(),
                index: 0,
                fault_offset: None,
                fault: None,
            })),
        }
    }

    /// Arms a one-shot fault that fires when sample `offset` of the current
    /// script is taken (used to fail a transaction persist).
    fn arm_fault(&self, offset: usize, fault: Box<dyn FnMut() + Send>) {
        let mut state = self.state.lock().unwrap();
        state.fault_offset = Some(offset);
        state.fault = Some(fault);
    }

    fn sample(&self) -> i64 {
        let mut state = self.state.lock().unwrap();
        let ordinal = state.index.min(state.queue.len() - 1);
        if state.fault_offset == Some(ordinal) {
            state.fault_offset = None;
            if let Some(fault) = state.fault.as_mut() {
                fault();
            }
        }
        if state.index < state.queue.len() - 1 {
            let value = state.queue[state.index];
            state.index += 1;
            value
        } else {
            state.queue[ordinal]
        }
    }

    fn verifier_clock(&self) -> Clock {
        let clock = self.clone();
        Arc::new(move || clock.sample())
    }

    fn boxed(&self) -> Box<dyn FnMut() -> i64 + Send> {
        let clock = self.clone();
        Box::new(move || clock.sample())
    }
}

fn options() -> DurableStoreOptions {
    DurableStoreOptions {
        deployment_id: "candidate-test-deployment".into(),
        window: WINDOW,
    }
}

/// Registers the synthetic signing key and returns the signed GET request.
fn signed_get(state: &Arc<MemoryState>, ts: i64, nonce_name: &str) -> Request {
    let seed = digest("candidate-vector/key/kid-alice");
    let key = ServerSigningKey::from_bytes(&seed);
    let public = key.verifying_key().to_bytes();
    let kid = encode_b64url(&digest("candidate-vector/kid/kid-alice"));
    state
        .update(&mut |edit| {
            edit.put_key(RegistryEntry {
                kid: kid.clone(),
                public_key: encode_b64url(&public),
                name: "candidate-vector-kid-alice".to_owned(),
                admin: false,
                not_before: None,
                not_after: None,
            });
            Ok(())
        })
        .unwrap();
    let nonce = encode_b64url(&digest(&format!("candidate-vector/nonce/{nonce_name}"))[..16]);
    let signing = request_signing_string("GET", "/mcp", AUD, &kid, ts, &nonce, &[]);
    let sig = encode_b64url(&key.sign(signing.as_bytes()));
    Request {
        method: "GET".to_owned(),
        target: "/mcp".to_owned(),
        auth_values: vec![format_request_auth(&RequestAuth {
            kid,
            ts,
            nonce,
            sig,
        })],
        body: Vec::new(),
    }
}

fn verifier(
    store: &Arc<SharedDurableNonceStore>,
    state: &Arc<MemoryState>,
    clock: &ScriptedClock,
) -> Verifier {
    let config = Config {
        aud: AUD.to_owned(),
        state: Arc::clone(state) as Arc<dyn StateStore>,
        nonces: Arc::new(NonceStore::new()),
        audit: None,
        native: None,
        window_seconds: WINDOW,
        now: clock.verifier_clock(),
    };
    Verifier::new(config)
        .expect("verifier config")
        .with_durable_nonces(Arc::clone(store))
}

#[test]
fn replay_after_restart_is_refused() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    let clock = ScriptedClock::new(&[100, 100]);
    DurableNonceStore::initialize_unused(&path, &options(), ScriptedClock::new(&[100]).boxed())
        .unwrap();
    let store = Arc::new(DurableNonceStore::open(&path, &options(), clock.boxed()).unwrap());
    let state = Arc::new(MemoryState::new());
    let request = signed_get(&state, 100, "restart");
    let result = verifier(&store, &state, &clock).verify(&request);
    assert!(result.accepted, "code: {}", result.code);
    assert!(result.nonce_recorded);
    // The accepted request holds its serving lease; close drains leases.
    std::mem::drop(result);
    store.close().unwrap();

    // Restart: the same pair replays and is refused, still unsigned.
    let reopened = Arc::new(DurableNonceStore::open(&path, &options(), clock.boxed()).unwrap());
    let replay = verifier(&reopened, &state, &clock).verify(&request);
    assert_eq!(replay.http_status, 401);
    assert_eq!(replay.code, "replayed_nonce");
    assert!(!replay.nonce_recorded, "replays stay unsigned");
    reopened.close().unwrap();
}

#[test]
fn crash_between_intent_and_final_never_reopens() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    let dir = sandbox.0.clone();
    let clock = ScriptedClock::new(&[100, 100, 100, 100, 100, 100]);
    // Fault the final transaction persist at the fourth sample (open, verify
    // entry, store entry, intent, FINAL): the intent transaction is committed,
    // the final one never reaches the disk.
    clock.arm_fault(
        4,
        Box::new(move || fs::set_permissions(&dir, dir_permissions(0o500)).unwrap()),
    );
    DurableNonceStore::initialize_unused(&path, &options(), ScriptedClock::new(&[100]).boxed())
        .unwrap();
    let store = Arc::new(DurableNonceStore::open(&path, &options(), clock.boxed()).unwrap());
    let state = Arc::new(MemoryState::new());
    let request = signed_get(&state, 100, "crash");
    let result = verifier(&store, &state, &clock).verify(&request);
    assert_eq!(result.http_status, 503);
    assert_eq!(result.code, "durability_unavailable");
    assert!(!result.accepted && !result.nonce_recorded, "never dispatch");
    let _ = fs::set_permissions(&sandbox.0, dir_permissions(0o700));
    assert!(
        matches!(store.close(), Err(DurableStoreError::RecoveryRequired)),
        "unknown outcome fences the store"
    );

    // Crash recovery: exactly one unresolved intent, reconciled to a terminal
    // no-redelivery tombstone.
    let report = inspect_recovery(&path, &options()).unwrap();
    assert!(report.dirty);
    assert_eq!(
        report.intents.len(),
        1,
        "the prepared intent survived the crash"
    );
    assert!(report.live.is_empty() && report.tombstones.is_empty());
    let claim = report.intents[0].clone();
    reconcile_unknown(&path, &options(), &report.hash, &claim).unwrap();
    let after = inspect_recovery(&path, &options()).unwrap();
    assert_eq!(after.tombstones.len(), 1);
    assert!(after.live.is_empty() && after.intents.is_empty());

    // The reconciled store keeps the dirty gate: a refused reopen.
    assert!(matches!(
        DurableNonceStore::open(&path, &options(), ScriptedClock::new(&[100]).boxed()),
        Err(DurableStoreError::RecoveryRequired)
    ));
}

#[test]
fn clock_step_back_after_purge_fails_closed() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    DurableNonceStore::initialize_unused(&path, &options(), ScriptedClock::new(&[100]).boxed())
        .unwrap();
    // Owner epoch at H=216 (a purge/persist established that high water).
    let store =
        DurableNonceStore::open(&path, &options(), ScriptedClock::new(&[216]).boxed()).unwrap();
    store.close().unwrap();

    // Raw time 215 after a purge at 216: fail closed and latch unsafe.
    assert!(matches!(
        DurableNonceStore::open(&path, &options(), ScriptedClock::new(&[215]).boxed()),
        Err(DurableStoreError::RecoveryRequired)
    ));
    // The latch persists at catch-up: even the correct sample stays closed.
    assert!(matches!(
        DurableNonceStore::open(&path, &options(), ScriptedClock::new(&[216]).boxed()),
        Err(DurableStoreError::RecoveryRequired)
    ));
}

// ---------------------------------------------------------------------------
// Reservation-time registry revalidation (Go: state.WithAdmission +
// sameEntry/currentKnown at every authoritative sample) and the durable
// window construction refusal (Go: NewVerifier).
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicUsize, Ordering};

use mcp_jack::encoding::key_id;
use mcp_jack::error::JackError;
use mcp_jack::server::durable_admission::nonce_store_info;
use mcp_jack::server::state::{InviteRecord, StateEdit, StateView};
use mcp_jack::server::verify::{NativeCall, NativeResult, NativeTools};

/// Mutation applied right before the Nth registry lookup: the reservation
/// revalidation is the SECOND lookup of a verify pass.
enum Mutation {
    Revoke,
    Demote,
    Expire,
    Register,
}

/// StateStore wrapper that changes the caller entry between the verifier's
/// lookup and the reservation (the live registry diverges from the snapshot).
struct MutatingState {
    inner: Arc<MemoryState>,
    kid: String,
    entry: RegistryEntry,
    lookups: AtomicUsize,
    mutate_on: usize,
    kind: Mutation,
}

impl MutatingState {
    fn apply(&self) {
        match self.kind {
            Mutation::Revoke => {
                let kid = self.kid.clone();
                self.inner
                    .update(&mut |edit| {
                        edit.remove_key(&kid);
                        Ok(())
                    })
                    .unwrap();
            }
            Mutation::Demote | Mutation::Expire => {
                let kid = self.kid.clone();
                let demote = matches!(self.kind, Mutation::Demote);
                self.inner
                    .update(&mut |edit| {
                        let mut entry = edit.key(&kid).expect("entry present");
                        if demote {
                            entry.admin = false;
                        } else {
                            entry.not_after = Some(0);
                        }
                        edit.put_key(entry.clone());
                        Ok(())
                    })
                    .unwrap();
            }
            Mutation::Register => {
                let entry = self.entry.clone();
                self.inner
                    .update(&mut |edit| {
                        edit.put_key(entry.clone());
                        Ok(())
                    })
                    .unwrap();
            }
        }
    }
}

impl StateStore for MutatingState {
    fn view(&self) -> StateView {
        self.inner.view()
    }

    fn lookup(&self, kid: &str) -> Option<RegistryEntry> {
        if self.lookups.fetch_add(1, Ordering::SeqCst) + 1 == self.mutate_on {
            self.apply();
        }
        self.inner.lookup(kid)
    }

    fn lookup_invite(&self, invite_id: &str) -> Option<InviteRecord> {
        self.inner.lookup_invite(invite_id)
    }

    fn update(
        &self,
        f: &mut dyn FnMut(&mut StateEdit) -> Result<(), JackError>,
    ) -> Result<(), JackError> {
        self.inner.update(f)
    }
}

/// Native handler counting calls, so a test can prove no handler ran.
struct CountingNative {
    calls: AtomicUsize,
}

impl NativeTools for CountingNative {
    fn call(&self, _c: &mut NativeCall) -> Result<NativeResult, JackError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(NativeResult {
            structured: serde_json::Value::Null,
        })
    }
}

fn open_store(clock: &ScriptedClock) -> (Sandbox, Arc<SharedDurableNonceStore>) {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    DurableNonceStore::initialize_unused(&path, &options(), ScriptedClock::new(&[100]).boxed())
        .unwrap();
    let store = Arc::new(DurableNonceStore::open(&path, &options(), clock.boxed()).unwrap());
    (sandbox, store)
}

fn verifier_with_state(
    store: &Arc<SharedDurableNonceStore>,
    state: Arc<dyn StateStore>,
    clock: &ScriptedClock,
    native: Option<Arc<dyn NativeTools>>,
) -> Verifier {
    let config = Config {
        aud: AUD.to_owned(),
        state,
        nonces: Arc::new(NonceStore::new()),
        audit: None,
        native,
        window_seconds: WINDOW,
        now: clock.verifier_clock(),
    };
    Verifier::new(config)
        .expect("verifier config")
        .with_durable_nonces(Arc::clone(store))
}

fn durable_child(
    kid_name: &str,
    nonce_name: &str,
    ts: i64,
    mutate_on: usize,
    kind: Mutation,
    state: &Arc<MemoryState>,
) -> (Arc<MutatingState>, Request) {
    let seed = digest(kid_name);
    let key = ServerSigningKey::from_bytes(&seed);
    let public = key.verifying_key().to_bytes();
    let kid = encode_b64url(&digest(&format!("candidate-vector/kid/{kid_name}")));
    let entry = RegistryEntry {
        kid: kid.clone(),
        public_key: encode_b64url(&public),
        name: format!("candidate-vector-{kid_name}"),
        admin: true,
        not_before: None,
        not_after: None,
    };
    state
        .update(&mut |edit| {
            edit.put_key(entry.clone());
            Ok(())
        })
        .unwrap();
    let nonce = encode_b64url(&digest(&format!("candidate-vector/nonce/{nonce_name}"))[..16]);
    let signing = request_signing_string("GET", "/mcp", AUD, &kid, ts, &nonce, &[]);
    let sig = encode_b64url(&key.sign(signing.as_bytes()));
    let request = Request {
        method: "GET".to_owned(),
        target: "/mcp".to_owned(),
        auth_values: vec![format_request_auth(&RequestAuth {
            kid: kid.clone(),
            ts,
            nonce,
            sig,
        })],
        body: Vec::new(),
    };
    (
        Arc::new(MutatingState {
            inner: Arc::clone(state),
            kid,
            entry,
            lookups: AtomicUsize::new(0),
            mutate_on,
            kind,
        }),
        request,
    )
}

/// Asserts the 503 state_changed shape of a reservation refused because the
/// live registry diverged from the captured snapshot: no nonce consumed,
/// zero committed rows, store not fenced, no authorization effect.
fn assert_state_changed(
    result: &mcp_jack::server::verify::VerifyResult,
    store: &Arc<SharedDurableNonceStore>,
    stable_request: &Request,
    stable_state: &Arc<MemoryState>,
    clock: &ScriptedClock,
) {
    assert!(!result.accepted, "code: {}", result.code);
    assert_eq!(result.http_status, 503, "code: {}", result.code);
    assert_eq!(result.code, "state_changed");
    assert!(!result.nonce_recorded);
    let info = nonce_store_info(store);
    assert_eq!(info.live, 0);
    assert_eq!(info.intents, 0);
    assert!(!info.unsafe_latched);
    // The store is NOT fenced: an unchanged caller is still served.
    let verifier = verifier_with_state(
        store,
        Arc::clone(stable_state) as Arc<dyn StateStore>,
        clock,
        None,
    );
    let second = verifier.verify(stable_request);
    assert!(second.accepted, "store fenced: {}", second.code);
}

fn snapshot_change_case(kind: Mutation) {
    let clock = ScriptedClock::new(&[100]);
    let (_sandbox, store) = open_store(&clock);
    let inner = Arc::new(MemoryState::new());
    // A second, untouched caller proves the store stays unfenced.
    let (stable_wrapper, stable_request) = durable_child(
        "kid-stable",
        "stable",
        100,
        usize::MAX,
        Mutation::Revoke,
        &inner,
    );
    let (wrapper, request) = durable_child("kid-alice", "snap", 100, 2, kind, &inner);
    let verifier = verifier_with_state(
        &store,
        Arc::clone(&wrapper) as Arc<dyn StateStore>,
        &clock,
        None,
    );
    let result = verifier.verify(&request);
    assert_state_changed(&result, &store, &stable_request, &inner, &clock);
    drop(stable_wrapper);
}

#[test]
fn reservation_refuses_when_caller_is_revoked_before_commit() {
    snapshot_change_case(Mutation::Revoke);
}

#[test]
fn reservation_refuses_when_caller_loses_admin_before_commit() {
    snapshot_change_case(Mutation::Demote);
}

#[test]
fn reservation_refuses_when_caller_validity_changes_before_commit() {
    snapshot_change_case(Mutation::Expire);
}

/// Enrollment exception: a kid that becomes REGISTERED between the verifier's
/// lookup and the reservation must refuse with 503 state_changed and run no
/// native handler.
#[test]
fn reservation_refuses_when_enrollment_kid_becomes_registered() {
    let clock = ScriptedClock::new(&[100]);
    let (_sandbox, store) = open_store(&clock);
    let inner = Arc::new(MemoryState::new());
    let seed = digest("enroll-key");
    let signing = ServerSigningKey::from_bytes(&seed);
    let public = signing.verifying_key().to_bytes();
    let kid = key_id(&public);
    let raw_code: [u8; 32] = Sha256::digest(b"invite-code").into();
    let code = encode_b64url(&raw_code);
    let invite_id = encode_b64url(&Sha256::digest(raw_code));
    inner
        .update(&mut |edit| {
            edit.put_invite(InviteRecord {
                invite_id: invite_id.clone(),
                admin: false,
                created_by: "root".to_owned(),
                created_at: 0,
                expires_at: 1_000_000_000_000,
                key_ttl_seconds: None,
            });
            Ok(())
        })
        .unwrap();
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"jack.enroll","arguments":{{"code":"{code}","public_key":"{}"}}}}}}"#,
        encode_b64url(&public)
    )
    .into_bytes();
    let nonce = encode_b64url(&digest("candidate-vector/nonce/enroll")[..16]);
    let request_signing = request_signing_string("POST", "/mcp", AUD, &kid, 100, &nonce, &body);
    let sig = encode_b64url(&signing.sign(request_signing.as_bytes()));
    let request = Request {
        method: "POST".to_owned(),
        target: "/mcp".to_owned(),
        auth_values: vec![format_request_auth(&RequestAuth {
            kid: kid.clone(),
            ts: 100,
            nonce,
            sig,
        })],
        body,
    };
    let native = Arc::new(CountingNative {
        calls: AtomicUsize::new(0),
    });
    // The wrapper registers the kid on the SECOND lookup (reservation time).
    let wrapper = Arc::new(MutatingState {
        inner: Arc::clone(&inner),
        kid: kid.clone(),
        entry: RegistryEntry {
            kid,
            public_key: encode_b64url(&public),
            name: "late-registration".to_owned(),
            admin: false,
            not_before: None,
            not_after: None,
        },
        lookups: AtomicUsize::new(0),
        mutate_on: 2,
        kind: Mutation::Register,
    });
    let verifier = verifier_with_state(
        &store,
        Arc::clone(&wrapper) as Arc<dyn StateStore>,
        &clock,
        Some(Arc::clone(&native) as Arc<dyn NativeTools>),
    );
    let result = verifier.verify(&request);
    assert_eq!(result.http_status, 503, "code: {}", result.code);
    assert_eq!(result.code, "state_changed");
    assert!(!result.nonce_recorded);
    assert_eq!(native.calls.load(Ordering::SeqCst), 0, "handler ran");
    let info = nonce_store_info(&store);
    assert_eq!(info.live, 0);
    assert_eq!(info.intents, 0);
}

/// Invalid windows are rejected by Verifier::new before a durable profile can
/// be attached; the private builder-latch regression lives beside Verifier.
#[test]
fn durable_window_out_of_bounds_rejected_at_construction() {
    let clock = ScriptedClock::new(&[100]);
    let (_sandbox, store) = open_store(&clock);
    let state = Arc::new(MemoryState::new());
    let config = Config {
        aud: AUD.to_owned(),
        state: Arc::clone(&state) as Arc<dyn StateStore>,
        nonces: Arc::new(NonceStore::new()),
        audit: None,
        native: None,
        window_seconds: 121,
        now: clock.verifier_clock(),
    };
    let error = match Verifier::new(config) {
        Err(error) => error,
        Ok(_) => panic!("out-of-range window must be rejected"),
    };
    assert_eq!(
        error,
        mcp_jack::server::verify::VerifierConfigError::InvalidWindow
    );
    assert_eq!(
        error.to_string(),
        "server: window must be 0 (default 30) or an integer between 1 and 120 seconds"
    );
    store.close().expect("close unused durable store");
}
