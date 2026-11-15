//! Linux-gated restart and crash tests for the durable nonce admission seam:
//! reopen after a simulated crash between the intent and the final
//! transaction, replay refusal after restart, and fail-closed clock step-back
//! after a purge. All clocks are injected; no real time is read.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use mcp_jack::auth_header::{format_request_auth, RequestAuth};
use mcp_jack::encoding::encode_b64url;
use mcp_jack::server::durable_admission::SharedDurableNonceStore;
use mcp_jack::server::durable_recovery::{inspect_recovery, reconcile_unknown};
use mcp_jack::server::durable_store::{DurableNonceStore, DurableStoreError, DurableStoreOptions};
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
    let key = SigningKey::from_bytes(&seed);
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
    let sig = encode_b64url(&key.sign(signing.as_bytes()).to_bytes());
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
