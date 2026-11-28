use super::*;
use crate::encoding::encode_b64url;
use crate::server::audit::MemoryAuditSink;
use crate::server::native::{Native, NativeOptions};
use crate::server::nonce::{NonceAdmission, NonceStore};
use crate::server::state::{InviteRecord, MemoryState, StateEdit};
use crate::user_key::ServerSigningKey;
use sha2::{Digest, Sha256};

const NOW: i64 = 1_767_225_600;
const AUD: &str = "https://svc.example.test";
const PING: &str = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;

/// Deterministic test key pair derived from a fixed id (mirrors
/// state.rs state_test_key).
fn test_key(id: &str) -> (ServerSigningKey, RegistryEntry) {
    let seed = Sha256::digest(id.as_bytes());
    let signing = ServerSigningKey::from_bytes(&seed.into());
    let public = signing.verifying_key().to_bytes();
    (
        signing,
        RegistryEntry {
            kid: key_id(&public),
            public_key: encode_b64url(&public),
            name: id.to_string(),
            admin: false,
            not_before: None,
            not_after: None,
        },
    )
}

/// Like `test_key` but with the admin flag set.
fn admin_key(id: &str) -> (ServerSigningKey, RegistryEntry) {
    let (key, mut entry) = test_key(id);
    entry.admin = true;
    (key, entry)
}

fn seeded_state(entries: &[&RegistryEntry]) -> Arc<dyn StateStore> {
    let state = MemoryState::new();
    state
        .update(&mut |edit: &mut StateEdit| {
            for entry in entries {
                edit.put_key((*entry).clone());
            }
            Ok(())
        })
        .expect("seeding must succeed");
    Arc::new(state)
}

const INVITE_CODE_RAW: [u8; 32] = [7u8; 32];

/// Canonical wire form of the test invite code.
fn invite_code() -> String {
    encode_b64url(&INVITE_CODE_RAW)
}

/// Stores the invite for `invite_code()` expiring at `expires_at`.
fn add_invite(state: &Arc<dyn StateStore>, expires_at: i64) {
    state
        .update(&mut |edit: &mut StateEdit| {
            edit.put_invite(InviteRecord {
                invite_id: invite_id_of(&INVITE_CODE_RAW),
                admin: false,
                created_by: "root".to_owned(),
                created_at: NOW - 10,
                expires_at,
                key_ttl_seconds: None,
            });
            Ok(())
        })
        .expect("seeding must succeed");
}

/// Arguments of an enrollment carrying the test invite code.
fn enroll_args(public_key: &str) -> String {
    format!(
        r#"{{"code":"{}","public_key":"{public_key}"}}"#,
        invite_code()
    )
}

fn config(now: i64, state: Arc<dyn StateStore>, native: Option<Arc<dyn NativeTools>>) -> Config {
    config_with_nonces(now, state, native, Arc::new(NonceStore::new()))
}

fn config_with_nonces(
    now: i64,
    state: Arc<dyn StateStore>,
    native: Option<Arc<dyn NativeTools>>,
    nonces: Arc<dyn NonceAdmission>,
) -> Config {
    Config {
        aud: AUD.to_owned(),
        state,
        nonces,
        audit: None,
        native,
        window_seconds: 30,
        now: Arc::new(move || now),
    }
}

fn verifier(cfg: Config) -> Verifier {
    VerifierBuilder::new(cfg.aud, cfg.state)
        .nonces(cfg.nonces)
        .audit(cfg.audit)
        .native_tools(cfg.native)
        .window_seconds(cfg.window_seconds)
        .now(cfg.now)
        .try_build()
        .expect("test config is valid")
}

fn call_body(tool: &str, arguments: Option<&str>) -> String {
    match arguments {
        Some(args) => format!(
            r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"{tool}","arguments":{args}}}}}"#
        ),
        None => format!(
            r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"{tool}"}}}}"#
        ),
    }
}

/// Builds a canonically signed request (spec 01 section 3).
fn signed(
    method: &str,
    target: &str,
    body: &[u8],
    key: &ServerSigningKey,
    kid: &str,
    ts: i64,
    nonce: &str,
) -> Request {
    let signing = request_signing_string(method, target, AUD, kid, ts, nonce, body);
    let sig = encode_b64url(&key.sign(signing.as_bytes()));
    Request {
        method: method.to_owned(),
        target: target.to_owned(),
        auth_values: vec![format!("v1 kid={kid},ts={ts},nonce={nonce},sig={sig}")],
        body: body.to_vec(),
    }
}

/// Canonical 22-char nonce for a counter (16 bytes, spec 01 sections 2-3).
fn nonce(n: u64) -> String {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    encode_b64url(&bytes)
}

fn post_call(
    tool: &str,
    arguments: Option<&str>,
    key: &ServerSigningKey,
    kid: &str,
    nonce: &str,
) -> Request {
    let body = call_body(tool, arguments);
    signed("POST", "/mcp", body.as_bytes(), key, kid, NOW, nonce)
}

fn get(key: &ServerSigningKey, kid: &str, ts: i64, nonce: &str) -> Request {
    signed("GET", "/mcp", b"", key, kid, ts, nonce)
}

/// Config whose clock is the shared atomic, so tests can step it.
fn stepping_config(clock: &Arc<AtomicI64>, state: Arc<dyn StateStore>) -> Config {
    let mut cfg = config(NOW, state, None);
    let clock = Arc::clone(clock);
    cfg.now = Arc::new(move || clock.load(Ordering::SeqCst));
    cfg
}

struct TimeRecordingNative(Arc<AtomicI64>);

impl NativeTools for TimeRecordingNative {
    fn call(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        self.0.store(c.now, Ordering::SeqCst);
        c.target = c.kid.to_owned();
        Ok(NativeResult {
            structured: serde_json::Value::Null,
        })
    }
}

#[cfg(target_os = "linux")]
struct DurableTestSandbox(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl Drop for DurableTestSandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(target_os = "linux")]
fn durable_test_store() -> (
    DurableTestSandbox,
    Arc<crate::server::durable_admission::SharedDurableNonceStore>,
) {
    use crate::server::durable_store::{DurableNonceStore, DurableStoreOptions};
    use std::os::unix::fs::DirBuilderExt;

    let mut random = [0u8; 16];
    getrandom::fill(&mut random).expect("test sandbox entropy");
    let directory = std::env::temp_dir().join(format!(
        "jack-rust-verify-window-{}",
        encode_b64url(&random)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .expect("create private test directory");
    let path = directory.join("nonce-store");
    let options = DurableStoreOptions {
        deployment_id: "verify-window-test".to_owned(),
        window: 30,
    };
    let init_clock: Box<dyn FnMut() -> i64 + Send> = Box::new(|| 100);
    DurableNonceStore::initialize_unused(&path, &options, init_clock)
        .expect("initialize durable test store");
    let store_clock: Box<dyn FnMut() -> i64 + Send> = Box::new(|| 100);
    let store = Arc::new(
        DurableNonceStore::open(&path, &options, store_clock).expect("open durable test store"),
    );
    (DurableTestSandbox(directory), store)
}

struct StubNative;

impl NativeTools for StubNative {
    fn call(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        c.target = c.kid.to_owned();
        if c.tool == TOOL_ENROLL && c.caller.is_some() {
            return Err(JackError::new(
                409,
                codes::KEY_EXISTS,
                "stub: already registered",
            ));
        }
        if c.tool.starts_with("jack.admin.") && !c.caller.is_some_and(|e| e.admin) {
            return Err(JackError::new(
                403,
                codes::ADMIN_REQUIRED,
                "stub: admin required",
            ));
        }
        Ok(NativeResult {
            structured: serde_json::Value::Null,
        })
    }
}

fn stub() -> Arc<dyn NativeTools> {
    Arc::new(StubNative)
}

/// Enrollment request of a fresh key with the given arguments.
fn enroll_request(arguments: &str, n: u64) -> (Request, String) {
    let (key, entry) = test_key("carol");
    let body = call_body(TOOL_ENROLL, Some(arguments));
    let req = signed(
        "POST",
        "/mcp",
        body.as_bytes(),
        &key,
        &entry.kid,
        NOW,
        &nonce(n),
    );
    (req, entry.public_key)
}

mod bodies_and_identity;

mod constructor_and_time;

mod enrollment;

mod request_pipeline;

mod two_phase;
