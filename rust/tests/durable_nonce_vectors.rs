//! Linux-gated candidate durable-nonce vector runner (spec/fixtures/
//! candidate/nonce-vectors.json). Mirrors the Go runner
//! durable/nonce_vectors_linux_test.go: every drivable admission case runs
//! through the real file-backed store plus the real verifier durable path;
//! cases that cannot be expressed are listed in EXCLUSIONS and cases driven
//! with a documented deviation in DEVIATIONS, with the Go reasons verbatim.
//! All clocks are injected; no real time is read.
#![cfg(target_os = "linux")]

use std::cell::Cell;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use mcp_jack::auth_header::{format_request_auth, RequestAuth};

use mcp_jack::encoding::encode_b64url;
use mcp_jack::error::JackError;
use mcp_jack::server::durable_admission::{
    nonce_store_info, seed_nonce_rows, BoxedDurableClock, SeedKind, SeedRow,
    SharedDurableNonceStore,
};
use mcp_jack::server::durable_recovery::{inspect_recovery, reconcile_unknown};
use mcp_jack::server::durable_store::{DurableAdmission, DurableNonceStore, DurableStoreOptions};
use mcp_jack::server::native::NativeTools;
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, Config, Request, Verifier, VerifyResult};
use mcp_jack::signing::request_signing_string;

const FIXTURE_FORMAT: &str = "mcp-jack-candidate-durable-nonce-v1";
const AUD: &str = "candidate-vector-test";
const TOOL_WHOAMI: &str = "jack.whoami";
const DEFAULT_DEPLOYMENT: &str = "candidate-test-deployment";

// ---------------------------------------------------------------------------
// Fixture schema (serde ignores unknown members: version/captured/... etc.).
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct VectorFixture {
    format: String,
    status_codes: HashMap<String, u16>,
    cases: Vec<VectorCase>,
}

#[derive(Deserialize)]
struct VectorCase {
    id: String,
    #[serde(default)]
    state: Option<VectorState>,
    #[serde(default)]
    event: Option<VectorEvent>,
    #[serde(default)]
    sequence: Vec<VectorEvent>,
    #[serde(default)]
    expect: VectorExpect,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorState {
    #[serde(default)]
    deployment: String,
    #[serde(default)]
    window: i64,
    #[serde(default)]
    high_water: i64,
    #[serde(default)]
    intents: Vec<VectorSeedRow>,
    #[serde(default)]
    live: Vec<VectorSeedRow>,
    #[serde(default)]
    tombstones: Vec<VectorTombstone>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorSeedRow {
    key: String,
    #[serde(default)]
    ts: i64,
    #[serde(default)]
    retain_until: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorTombstone {
    intent_id: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorEvent {
    kid: String,
    nonce: String,
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    request_identity: String,
    #[serde(default)]
    window: i64,
    #[serde(default)]
    ts: i64,
    #[serde(default)]
    entry_now: i64,
    #[serde(default)]
    intent_now: i64,
    #[serde(default)]
    final_now: i64,
    #[serde(default)]
    authorization: String,
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct VectorExpect {
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    code: String,
    #[serde(default)]
    statuses: Option<Vec<(u16, String)>>,
    #[serde(default)]
    callbacks: Option<serde_json::Value>,
    #[serde(default)]
    writes: Option<serde_json::Value>,
    #[serde(default)]
    dispatches: Option<serde_json::Value>,
    #[serde(default)]
    confirmed_commits: Option<i64>,
    #[serde(default)]
    high_water: i64,
    #[serde(default)]
    live_count: i64,
    #[serde(default)]
    intent_count: i64,
    #[serde(default)]
    tombstone_count: i64,
    #[serde(default)]
    fenced: bool,
    #[serde(default)]
    effects: VectorEffects,
    #[serde(default)]
    preserve_live: bool,
    #[serde(default)]
    preserve_tombstones: bool,
}

#[derive(Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "camelCase")]
struct VectorEffects {
    #[serde(default)]
    authorization: i64,
    #[serde(default)]
    handler: i64,
    #[serde(default)]
    state_mutation: i64,
}

fn count_list(raw: &Option<serde_json::Value>) -> Vec<i64> {
    match raw {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Number(n)) => vec![n.as_i64().unwrap_or_default()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|v| v.as_i64().unwrap_or_default())
            .collect(),
        Some(other) => panic!("count field is not a number or list: {other}"),
    }
}

fn load_fixture() -> VectorFixture {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/fixtures/candidate/nonce-vectors.json");
    let text = fs::read_to_string(&path).expect("candidate nonce vectors fixture");
    let fixture: VectorFixture = serde_json::from_str(&text).expect("fixture JSON");
    assert_eq!(fixture.format, FIXTURE_FORMAT, "fixture format");
    for code in [
        "durability_unavailable",
        "state_changed",
        "clock_unsafe",
        "capacity_exhausted",
    ] {
        assert_eq!(fixture.status_codes[code], 503, "status_codes[{code}]");
    }
    fixture
}

// ---------------------------------------------------------------------------
// Exclusions and deviations: data, not comments. Reasons are copied verbatim
// from the Go runner durable/nonce_vectors_linux_test.go.
// ---------------------------------------------------------------------------

struct VectorExclusion {
    reason: &'static str,
    spec: &'static str,
}

fn exclusions() -> HashMap<&'static str, VectorExclusion> {
    HashMap::from([
        (
            "generation-change-zero-commit",
            VectorExclusion {
                reason: "Not expressible against the Go seam: server.NonceAdmission carries no \
                     captured owner/store generation, so a per-request generation mismatch \
                     cannot be injected. Go revalidates the captured store state structurally \
                     under the admission mutex (transaction.go decodes and compares the full \
                     metadata), and a second owner is refused at Open (lifetime-exclusive \
                     ownership), which is the structural counterpart of this vector. The Rust \
                     seam has the same shape: DurableAdmission carries no captured \
                     owner/store generation and the store revalidates its full metadata under \
                     the admission mutex.",
                spec: "spec/candidate/durable-nonces.md L42: \"capture immutable \
                     active-key/registered-caller/enrollment snapshot, positive immutable W, \
                     accepting owner and store generation\"; L44: \"Store admission uses a \
                     lifetime-exclusive owner; a second process opening it is refused.\"",
            },
        ),
        (
            "definite-abort-confirmed-cleanup",
            VectorExclusion {
                reason: "The Go implementation reports a confirmed-cleanup abort with its \
                     step's status (401 timestamp_out_of_window), not the JS model's 503 \
                     classification; the drivable instance is identical to \
                     delayed-final-after-confirmed-intent, which is driven and asserts the \
                     confirmed cleanup (2 writes, 0 live, 0 intents, 0 dispatch). The Rust \
                     implementation reports the same step status for the same drivable \
                     instance.",
                spec: "spec/candidate/durable-nonces.md L48: \"Any failure needing intent \
                     cleanup is reported with its step's status only after cleanup is \
                     confirmed; uncertain cleanup/fence becomes unknown 503 \
                     durability_unavailable.\"",
            },
        ),
    ])
}

fn deviations() -> HashMap<&'static str, Vec<&'static str>> {
    HashMap::from([
        (
            "crash-after-commit-no-dispatch",
            vec![
                "expect.status 503/durability_unavailable and expect.effects zeros are the JS \
                 model's lost-response placeholder; the Rust store returns the committed \
                 response in-process and there is no in-process crash. This driver asserts the \
                 durable claims instead: commit succeeded (live=1, 2 writes), no native/dispatch \
                 side effect, clean Close, reopen succeeds unfenced, and the same pair replays \
                 401 replayed_nonce with zero further writes and no re-dispatch.",
                "Spec quote, spec/candidate/durable-nonces.md L74: \"crash after confirmed \
                 reservation but before dispatch leaves the pair consumed and never \
                 auto-redelivers.\"",
            ],
        ),
        (
            "window-decrease-refused",
            vec![
                "Rust divergence from Go: the Rust store fences on every 503-class refusal, \
                 including state_changed, so the close after the refusal reports the recovery \
                 gate (expect.fenced=false in the fixture). Go leaves a definite refusal \
                 unfenced. The status/code/writes behavior is asserted exactly.",
            ],
        ),
        (
            "window-increase-refused",
            vec!["Same state_changed fencing divergence as window-decrease-refused."],
        ),
        (
            "key-snapshot-change-zero-commit",
            vec![
                "Same state_changed fencing divergence as window-decrease-refused, on the \
                 store-direct drive.",
            ],
        ),
        (
            "enrollment-snapshot-change-zero-commit",
            vec!["Same state_changed fencing divergence as key-snapshot-change-zero-commit."],
        ),
        (
            "capacity-live-plus-intent",
            vec![
                "Vector state (highWater=0 with ts=100 rows) is loader-rejectable per spec L58 \
                 and record.go validateRecord; seeded with metadata.HighWater=100 (the derivable \
                 floor). expect.highWater=0 is therefore not assertable; the driver asserts \
                 highWater=100 and everything else exactly (503 capacity_exhausted, 4096 live \
                 rows preserved row-for-row, unfenced, effects 0).",
                "expect.callbacks=0/expect.writes=0 count committed mutations in the JS model; \
                 the Rust store performs the atomic capacity check inside the intent \
                 transaction (spec L48 step 5), so one aborted transaction is observed. \
                 Transaction counting itself is not observable through the public Rust API, \
                 so the driver asserts the unchanged metadata and row counts instead.",
            ],
        ),
        (
            "capacity-tombstones",
            vec![
                "Same high-water floor and aborted-transaction counting deviations as \
                 capacity-live-plus-intent.",
            ],
        ),
        (
            "unknown-final-present",
            vec![
                "The reservationFound distinction is unobservable in single-snapshot \
                 transaction semantics: an injected fault after apply leaves the final state \
                 uncommitted on disk with the prepared intent row. The driver asserts the \
                 identical terminal state for both variants: fenced, 503 durability_unavailable, \
                 exactly one unresolved row in InspectRecovery, ReconcileUnknown producing \
                 exactly one terminal tombstone (tombstoneCount=1), and Open refused after \
                 reconciliation. expect.tombstoneOutcome unknown_found/unknown_absent is not \
                 separately assertable.",
            ],
        ),
        (
            "unknown-final-absent",
            vec!["Same rollback-resting-state deviation as unknown-final-present."],
        ),
        (
            "unknown-intent-absent",
            vec![
                "Partially driven. Unassertable expect fields: highWater=100 and writes=1 \
                 (committed) because the H advance and the intent commit are one atomic \
                 transaction per spec L62 (\"durably advance H to the raw sample in an atomic \
                 ordered transaction\"); a failed intent transaction leaves H=0 with zero \
                 committed writes and one aborted transaction call. Asserted instead: 503 \
                 durability_unavailable, fenced, no rows, the Dirty recovery gate, \
                 ReconcileUnknown refusal on empty history (manual fence), and a refused \
                 reopen.",
            ],
        ),
        (
            "all-cases",
            vec![
                "expect.callbacks/expect.writes count store transactions, which are not \
                 observable through the public Rust integration API; guarded assertions cover \
                 status, code, nonce_recorded, high-water, row counts, fence state, and \
                 effect counters instead.",
            ],
        ),
    ])
}

// ---------------------------------------------------------------------------
// Deterministic synthetic identities (identical to the Go runner).
// ---------------------------------------------------------------------------

fn digest(name: &str) -> [u8; 32] {
    Sha256::digest(name.as_bytes()).into()
}

fn kid_raw(name: &str) -> [u8; 32] {
    digest(&format!("candidate-vector/kid/{name}"))
}

fn kid(name: &str) -> String {
    encode_b64url(&kid_raw(name))
}

fn nonce_raw(name: &str) -> [u8; 16] {
    let full = digest(&format!("candidate-vector/nonce/{name}"));
    let mut raw = [0; 16];
    raw.copy_from_slice(&full[..16]);
    raw
}

fn nonce(name: &str) -> String {
    encode_b64url(&nonce_raw(name))
}

fn signature(name_pair: &str) -> String {
    let mut raw = [0; 64];
    raw[..32].copy_from_slice(&digest(&format!("candidate-vector/sig-a/{name_pair}")));
    raw[32..].copy_from_slice(&digest(&format!("candidate-vector/sig-b/{name_pair}")));
    encode_b64url(&raw)
}

fn operation(kid_name: &str, nonce_name: &str) -> [u8; 16] {
    let full = digest(&format!("candidate-vector/op/{kid_name}/{nonce_name}"));
    let mut raw = [0; 16];
    raw.copy_from_slice(&full[..16]);
    raw
}

/// Registry signing key for a kid name (Go: vectorRegisteredKey seed).
fn signing_key(kid_name: &str) -> SigningKey {
    let seed = digest(&format!("candidate-vector/key/{kid_name}"));
    SigningKey::from_bytes(&seed)
}

/// Splits a seed-row key on ':'; single-name capacity rows fall back to a
/// whole-key derivative for the nonce name (Go: vectorSplitRowKey).
fn split_row_key(key: &str) -> (String, String) {
    match key.split_once(':') {
        Some((kid_name, nonce_name)) => (kid_name.to_owned(), nonce_name.to_owned()),
        None => (key.to_owned(), format!("{key}/nonce")),
    }
}

/// Receipt high water satisfying validateRecord (Go: vectorRowHighWater).
fn row_high_water(metadata_high_water: i64, ts: i64) -> i64 {
    if metadata_high_water > 0 {
        metadata_high_water
    } else {
        ts
    }
}

// ---------------------------------------------------------------------------
// Seeding: fresh store + scripted clock + the store's own record path.
// ---------------------------------------------------------------------------

fn seed_row_record(
    kind: SeedKind,
    kid_name: &str,
    nonce_name: &str,
    ts: i64,
    retain_until: i64,
    high_water: i64,
) -> SeedRow {
    let signing = request_signing_string(
        "GET",
        "/mcp",
        AUD,
        &kid(kid_name),
        ts,
        &nonce(nonce_name),
        &[],
    );
    SeedRow {
        kind,
        kid: kid(kid_name),
        nonce: nonce(nonce_name),
        signature: signature(&format!("{kid_name}:{nonce_name}")),
        request_hash: mcp_jack::encoding::body_hash(signing.as_bytes()),
        operation_id: operation(kid_name, nonce_name),
        ts,
        retain_until,
        high_water,
    }
}

/// Seeds every abstract row of a case through the store's own validated
/// record path; the deployment/high-water metadata comes from the opened
/// store (Go: seedVectorState).
fn seed_state(store: &SharedDurableNonceStore, case: &VectorCase) {
    let Some(state) = case.state.as_ref() else {
        return; // sequence cases start from a fresh empty store
    };
    let info = nonce_store_info(store);
    let mut rows = Vec::new();
    for row in &state.live {
        let (kid_name, nonce_name) = split_row_key(&row.key);
        rows.push(seed_row_record(
            SeedKind::Live,
            &kid_name,
            &nonce_name,
            row.ts,
            row.retain_until,
            row_high_water(info.high_water, row.ts),
        ));
    }
    for row in &state.intents {
        let (kid_name, nonce_name) = split_row_key(&row.key);
        rows.push(seed_row_record(
            SeedKind::Intent,
            &kid_name,
            &nonce_name,
            row.ts,
            row.retain_until,
            row_high_water(info.high_water, row.ts),
        ));
    }
    for row in &state.tombstones {
        rows.push(seed_row_record(
            SeedKind::Tombstone,
            &row.intent_id,
            &format!("{}-pair", row.intent_id),
            100,
            130,
            row_high_water(info.high_water, 100),
        ));
    }
    seed_nonce_rows(store, &rows).expect("seed vector state");
}

// ---------------------------------------------------------------------------
// Harness: sandbox, scripted clock, counters, verifier.
// ---------------------------------------------------------------------------

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "jack-rust-nonce-vectors-{}",
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
        // Restore write permission so cleanup cannot fail on a faulted dir.
        let _ = fs::set_permissions(&self.0, read_write_dir());
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn read_write_dir() -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(0o700)
}

#[cfg(unix)]
fn read_only_dir() -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(0o500)
}

/// Scripted clock shared between the verifier (Clock) and the store (boxed
/// FnMut). Replays queued samples in order, then repeats the last; one
/// optional fault fires exactly once at a given sample ordinal within the
/// current event (used to fail the intent/final persist, the filesystem
/// equivalent of a crash between the two transactions).
#[derive(Clone)]
struct ScriptedClock {
    state: Arc<Mutex<ClockState>>,
}

struct ClockState {
    queue: Vec<i64>,
    index: usize,
    since_event: usize,
    fault_offset: Option<usize>,
    fault: Option<Box<dyn FnMut() + Send>>,
}

impl ScriptedClock {
    fn new(samples: &[i64]) -> Self {
        Self {
            state: Arc::new(Mutex::new(ClockState {
                queue: samples.to_vec(),
                index: 0,
                since_event: 0,
                fault_offset: None,
                fault: None,
            })),
        }
    }

    fn arm_fault(&self, offset: usize, fault: Box<dyn FnMut() + Send>) {
        let mut state = self.state.lock().unwrap();
        state.fault_offset = Some(offset);
        state.fault = Some(fault);
    }

    /// Starts one event: the five samples of the mapping contract
    /// (verifier entry, store entry, intent, final, verifier post-commit).
    fn start_event(&self, event: &VectorEvent) {
        let mut state = self.state.lock().unwrap();
        state.queue = vec![
            event.entry_now,
            event.entry_now,
            event.intent_now,
            event.final_now,
            event.final_now,
        ];
        state.index = 0;
        state.since_event = 0;
    }

    /// Same scripted sequence for direct store drives (three store samples).
    fn start_store_drive(&self, event: &VectorEvent) {
        let mut state = self.state.lock().unwrap();
        state.queue = vec![event.entry_now, event.intent_now, event.final_now];
        state.index = 0;
        state.since_event = 0;
    }

    fn sample(&self) -> i64 {
        let mut state = self.state.lock().unwrap();
        let ordinal = state.since_event;
        state.since_event += 1;
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
            state.queue[state.queue.len() - 1]
        }
    }

    fn verifier_clock(&self) -> Clock {
        let clock = self.clone();
        Arc::new(move || clock.sample())
    }

    fn boxed(&self) -> BoxedDurableClock {
        let clock = self.clone();
        Box::new(move || clock.sample())
    }
}

/// Harness counters (Go: vectorCounters); effects are harness counters only.
#[derive(Default)]
struct Counters {
    native_calls: usize,
    accepted: usize,
}

/// Native handler refusing after admission (Go: refusingNative): the native
/// 403 authorization refusal.
struct RefusingNative {
    counters: Arc<Mutex<Counters>>,
}

impl NativeTools for RefusingNative {
    fn call(
        &self,
        _c: &mut mcp_jack::server::verify::NativeCall,
    ) -> Result<mcp_jack::server::verify::NativeResult, JackError> {
        self.counters.lock().unwrap().native_calls += 1;
        Err(JackError::new(
            403,
            "authorization_refused",
            "authorization refused",
        ))
    }
}

fn deployment_of(case: &VectorCase) -> String {
    match case.state.as_ref() {
        Some(state) if !state.deployment.is_empty() => state.deployment.clone(),
        _ => DEFAULT_DEPLOYMENT.to_owned(),
    }
}

fn window_of(case: &VectorCase) -> i64 {
    match case.state.as_ref() {
        Some(state) => state.window,
        None => 30,
    }
}

fn open_now_of(case: &VectorCase, plan: &Plan) -> i64 {
    if let Plan::Capacity = plan {
        return 100;
    }
    match case.state.as_ref() {
        Some(state) => state.high_water,
        None => 100, // sequence cases expect highWater=100 on a fresh store
    }
}

struct Harness {
    sandbox: Sandbox,
    path: PathBuf,
    options: DurableStoreOptions,
    store: Arc<SharedDurableNonceStore>,
    clock: ScriptedClock,
    counters: Arc<Mutex<Counters>>,
    state: Arc<MemoryState>,
}

fn options_for(case: &VectorCase) -> DurableStoreOptions {
    DurableStoreOptions {
        deployment_id: deployment_of(case),
        window: window_of(case),
    }
}

/// Creates a fresh store for one case, seeds the vector state, and registers
/// the synthetic key for every event kid (Go: newSingleStore).
fn new_harness(case: &VectorCase, plan: &Plan) -> Harness {
    let open_now = open_now_of(case, plan);
    let init_clock = ScriptedClock::new(&[open_now]);
    let event_clock = ScriptedClock::new(&[open_now, open_now]);
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    let options = options_for(case);
    DurableNonceStore::initialize_unused(&path, &options, init_clock.boxed())
        .expect("initialize unused store");
    let store = Arc::new(
        DurableNonceStore::open(&path, &options, event_clock.boxed()).expect("open store"),
    );
    seed_state(&store, case);
    let info = nonce_store_info(&store);
    assert_eq!(info.generation, 1, "case {}: generation", case.id);
    assert_eq!(info.window, window_of(case), "case {}: window", case.id);
    // Register a signing key for every kid used by the case.
    let state = Arc::new(MemoryState::new());
    let mut kids = Vec::new();
    if let Some(event) = case.event.as_ref() {
        kids.push(event.kid.clone());
    }
    for event in &case.sequence {
        kids.push(event.kid.clone());
    }
    kids.sort();
    kids.dedup();
    for kid_name in kids {
        let key = signing_key(&kid_name);
        let public = key.verifying_key().to_bytes();
        state
            .update(&mut |edit| {
                edit.put_key(RegistryEntry {
                    kid: kid(&kid_name),
                    public_key: encode_b64url(&public),
                    name: format!("candidate-vector-{kid_name}"),
                    admin: false,
                    not_before: None,
                    not_after: None,
                });
                Ok(())
            })
            .expect("register vector key");
    }
    Harness {
        sandbox,
        path,
        options,
        store,
        clock: event_clock,
        counters: Arc::new(Mutex::new(Counters::default())),
        state,
    }
}

fn drop(harness: Harness) {
    let _ = harness.store.close();
}

/// Builds and signs the request of one event (Go: vectorRequest). A
/// non-authenticated event tampers the target after signing so signature
/// verification must fail pre-admission.
fn build_request(
    harness: &Harness,
    event: &VectorEvent,
    target: &str,
    refuse_authorization: bool,
) -> Request {
    let kid_name = event.kid.clone();
    let key = signing_key(&kid_name);
    let kid_value = kid(&kid_name);
    let nonce_value = nonce(&event.nonce);
    let (method, body): (&str, Vec<u8>) = if refuse_authorization {
        (
            "POST",
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{TOOL_WHOAMI}","arguments":{{}}}}}}"#,
            )
            .into_bytes(),
        )
    } else {
        ("GET", Vec::new())
    };
    let signing = request_signing_string(
        method,
        target,
        AUD,
        &kid_value,
        event.ts,
        &nonce_value,
        &body,
    );
    let sig = encode_b64url(&key.sign(signing.as_bytes()).to_bytes());
    let target = if event.authenticated {
        target.to_owned()
    } else {
        format!("{target}/tampered")
    };
    Request {
        method: method.to_owned(),
        target,
        auth_values: vec![format_request_auth(&RequestAuth {
            kid: kid_value,
            ts: event.ts,
            nonce: nonce_value,
            sig,
        })],
        body,
    }
}

/// Runs one full-path event through a fresh verifier wired to the real
/// durable store (Go: driveVectorEvent). The verifier consumes the entry
/// sample, the store entry/intent/final samples, and the verifier the
/// post-commit sample (5 pushes per event).
fn drive_event(harness: &Harness, event: &VectorEvent, target: &str) -> VerifyResult {
    let refuse = event.authorization == "refused";
    harness.counters.lock().unwrap().accepted = 0;
    harness.clock.start_event(event);
    let request = build_request(harness, event, target, refuse);
    let native: Option<Arc<dyn NativeTools>> = if refuse {
        Some(Arc::new(RefusingNative {
            counters: Arc::clone(&harness.counters),
        }))
    } else {
        None
    };
    let config = Config {
        aud: AUD.to_owned(),
        state: Arc::clone(&harness.state) as Arc<dyn StateStore>,
        nonces: Arc::new(NonceStore::new()),
        audit: None,
        native,
        window_seconds: event.window,
        now: harness.clock.verifier_clock(),
    };
    let verifier = Verifier::new(config)
        .expect("verifier config")
        .with_durable_nonces(Arc::clone(&harness.store));
    let result = verifier.verify(&request);
    if result.accepted {
        harness.counters.lock().unwrap().accepted += 1;
    }
    result
}

fn effect_counters(harness: &Harness) -> (i64, i64, i64) {
    let counters = harness.counters.lock().unwrap();
    let authorization = (counters.native_calls + counters.accepted) as i64;
    (authorization, counters.accepted as i64, 0)
}

// ---------------------------------------------------------------------------
// Assertions.
// ---------------------------------------------------------------------------

fn assert_status(case_id: &str, result: &VerifyResult, status: u16, code: &str) {
    if code == "committed" {
        assert!(
            result.accepted,
            "{case_id}: expected committed accept, got {}/{} accepted={}",
            result.http_status, result.code, result.accepted
        );
        return;
    }
    assert_eq!(result.http_status, status, "{case_id}: status");
    assert_eq!(result.code, code, "{case_id}: code");
}

fn assert_recorded(case_id: &str, result: &VerifyResult, recorded: bool) {
    assert_eq!(result.nonce_recorded, recorded, "{case_id}: nonce_recorded");
}

/// Shared terminal expectations (Go: assertVectorEnd). Transaction
/// callbacks/writes are not observable through the public Rust API (see the
/// all-cases deviation); row counts and metadata counts stand in for them.
fn assert_end(harness: &Harness, case: &VectorCase, expect: &VectorExpect, skip_effects: bool) {
    let info = nonce_store_info(&harness.store);
    assert_eq!(
        info.high_water, expect.high_water,
        "case {}: highWater",
        case.id
    );
    assert_eq!(
        info.live, expect.live_count as usize,
        "case {}: liveRows",
        case.id
    );
    assert_eq!(
        info.intents, expect.intent_count as usize,
        "case {}: intentRows",
        case.id
    );
    assert_eq!(
        info.tombstones, expect.tombstone_count as usize,
        "case {}: tombstoneRows",
        case.id
    );
    if !skip_effects {
        let (auth, handler, mutation) = effect_counters(harness);
        assert_eq!(
            auth, expect.effects.authorization,
            "case {}: effects.authorization",
            case.id
        );
        assert_eq!(
            handler, expect.effects.handler,
            "case {}: effects.handler",
            case.id
        );
        assert_eq!(
            mutation, expect.effects.state_mutation,
            "case {}: effects.stateMutation",
            case.id
        );
    }
}

/// Final close must reflect the fence state (Go: fenced flag assertion).
fn assert_close_fencing(harness: Harness, case: &VectorCase, expect: &VectorExpect) {
    use mcp_jack::server::durable_store::DurableStoreError;
    let closed = harness.store.close();
    if expect.fenced {
        assert!(
            matches!(closed, Err(DurableStoreError::RecoveryRequired)),
            "case {}: fenced close, got {:?}",
            case.id,
            closed
        );
    } else {
        assert!(
            closed.is_ok(),
            "case {}: clean close, got {:?}",
            case.id,
            closed
        );
    }
    drop(harness);
}

fn expects_reopen_refused(harness: &Harness, case_id: &str) {
    use mcp_jack::server::durable_store::DurableStoreError;
    let reopened = DurableNonceStore::open(
        &harness.path,
        &harness.options,
        ScriptedClock::new(&[100]).boxed(),
    );
    assert!(
        matches!(reopened, Err(DurableStoreError::RecoveryRequired)),
        "{case_id}: reopened a fenced store: {:?}",
        reopened
    );
}

// ---------------------------------------------------------------------------
// Per-case plans and runners.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Plan {
    /// Full path through the real verifier; `recorded` pins nonce_recorded;
    /// `fenced` overrides expect.fenced where the Rust store deliberately
    /// fences on every 503-class refusal (see DEVIATIONS).
    Single {
        recorded: Option<bool>,
        assert_unsafe: bool,
        fenced: Option<bool>,
    },
    Sequence,
    /// Direct store reservation with a scripted validate closure
    /// (snapshot-change vectors).
    StoreDirect,
    Crash,
    UnknownFinal,
    UnknownIntent,
    Capacity,
}

fn plan_of(id: &str) -> Option<Plan> {
    use Plan::*;
    Some(match id {
        "same-second-restart-replay" => Single {
            recorded: Some(false),
            assert_unsafe: false,
            fenced: None,
        },
        "future-ts-restart-replay" => Single {
            recorded: Some(false),
            assert_unsafe: false,
            fenced: None,
        },
        "concurrent-same-pair" | "concurrent-different-request-identity" => Sequence,
        "expiry-equality" => Single {
            recorded: Some(false),
            assert_unsafe: false,
            fenced: None,
        },
        "expiry-plus-one-fresh-timestamp" => Single {
            recorded: Some(true),
            assert_unsafe: false,
            fenced: None,
        },
        "delayed-crypto-final-freshness" => Single {
            recorded: Some(false),
            assert_unsafe: false,
            fenced: None,
        },
        "delayed-final-after-confirmed-intent" => Single {
            recorded: None,
            assert_unsafe: false,
            fenced: None,
        },
        "purge-highwater-rollback" => Single {
            recorded: Some(false),
            assert_unsafe: true,
            fenced: None,
        },
        // The Rust store fences on every 503-class refusal, including
        // state_changed; see the window-refusal deviation entry.
        "window-decrease-refused" | "window-increase-refused" => Single {
            recorded: Some(false),
            assert_unsafe: false,
            fenced: Some(true),
        },
        "key-snapshot-change-zero-commit" | "enrollment-snapshot-change-zero-commit" => StoreDirect,
        "bad-signature-zero-writes" => Single {
            recorded: Some(false),
            assert_unsafe: false,
            fenced: None,
        },
        "commit-then-authorization-refusal" => Single {
            recorded: Some(true),
            assert_unsafe: false,
            fenced: None,
        },
        "crash-after-commit-no-dispatch" => Crash,
        "unknown-final-present" | "unknown-final-absent" | "no-effects-without-final-commit" => {
            UnknownFinal
        }
        "unknown-intent-absent" => UnknownIntent,
        "capacity-live-plus-intent" | "capacity-tombstones" => Capacity,
        _ => return None,
    })
}

fn run_single(case: &VectorCase, plan: Plan) {
    let Plan::Single {
        recorded,
        assert_unsafe,
        fenced,
    } = plan
    else {
        unreachable!()
    };
    let harness = new_harness(case, &plan);
    let event = case.event.as_ref().expect("single event");
    let result = drive_event(&harness, event, "/mcp");
    if let Some(status) = case.expect.status {
        assert_status(&case.id, &result, status, &case.expect.code);
    }
    if let Some(recorded) = recorded {
        assert_recorded(&case.id, &result, recorded);
    }
    if assert_unsafe {
        let info = nonce_store_info(&harness.store);
        assert!(
            info.unsafe_latched,
            "case {}: unsafe latch not durably set",
            case.id
        );
    }
    assert_end(&harness, case, &case.expect, false);
    // The fence expectation may be overridden by the plan (see deviations).
    let mut expect = case.expect.clone();
    if let Some(fenced) = fenced {
        expect.fenced = fenced;
    }
    assert_close_fencing(harness, case, &expect);
}

fn run_sequence(case: &VectorCase, plan: Plan) {
    let harness = new_harness(case, &plan);
    let statuses = case.expect.statuses.as_ref().expect("expect.statuses");
    let dispatches = count_list(&case.expect.dispatches);
    let mut recorded = 0;
    let mut accepted_total = 0;
    for (index, event) in case.sequence.iter().enumerate() {
        let target = if index > 0 && event.request_identity != case.sequence[0].request_identity {
            // A different signed request identity: different exact signing bytes.
            "/alternate"
        } else {
            "/mcp"
        };
        let result = drive_event(&harness, event, target);
        let (status, code) = statuses[index];
        assert_status(&case.id, &result, status, &code);
        if result.nonce_recorded {
            recorded += 1;
        }
        accepted_total += harness.counters.lock().unwrap().accepted;
        if let Some(want) = dispatches.get(index) {
            let accepted = harness.counters.lock().unwrap().accepted as i64;
            assert_eq!(accepted, *want, "case {}: dispatches[{index}]", case.id);
        }
    }
    assert_eq!(
        recorded,
        case.expect.confirmed_commits.unwrap_or_default(),
        "case {}: confirmedCommits",
        case.id
    );
    // Sequence effects accumulate across events; assert them here and skip
    // the per-event assertion inside assert_end (accepted resets per event,
    // so the running total is the authorization/handler effect count).
    assert_eq!(
        (accepted_total as i64, accepted_total as i64, 0,),
        (
            case.expect.effects.authorization,
            case.expect.effects.handler,
            case.expect.effects.state_mutation
        ),
        "case {}: effects",
        case.id
    );
    assert_end(&harness, case, &case.expect, true);
    assert_close_fencing(harness, case, &case.expect);
}

// Snapshot revalidation for the store-direct vectors: accepts the entry
// sample and rejects every later sample, the Rust expression of a snapshot
// that changed after cryptography (the verifier builds this from registry
// state and cannot be forced to flip mid-request from outside).
thread_local! {
    static VALIDATE_CALLS: Cell<u32> = const { Cell::new(0) };
}

fn flaky_snapshot_valid(_now: i64) -> bool {
    VALIDATE_CALLS.with(|calls| {
        let next = calls.get() + 1;
        calls.set(next);
        next == 1
    })
}

fn run_store_direct(case: &VectorCase, plan: Plan) {
    let harness = new_harness(case, &plan);
    let event = case.event.as_ref().expect("store-direct event");
    harness.clock.start_store_drive(event);
    VALIDATE_CALLS.with(|calls| calls.set(0));
    let kid_value = kid(&event.kid);
    let nonce_value = nonce(&event.nonce);
    let signing =
        request_signing_string("GET", "/mcp", AUD, &kid_value, event.ts, &nonce_value, &[]);
    let admission = DurableAdmission {
        kid: &kid_value,
        nonce: &nonce_value,
        signature: &signature(&format!("{}:{}", event.kid, event.nonce)),
        signing_bytes: signing.as_bytes(),
        timestamp: event.ts,
        window: event.window,
        snapshot_valid: flaky_snapshot_valid,
    };
    let reserve = harness.store.reserve(&admission);
    match reserve {
        Err(error) => {
            assert_eq!(error.status, 503, "case {}: status", case.id);
            assert_eq!(error.code, "state_changed", "case {}: code", case.id);
        }
        Ok(_) => panic!("case {}: reserve accepted with a changed snapshot", case.id),
    }
    let validate_calls = VALIDATE_CALLS.with(|calls| calls.get());
    assert_eq!(validate_calls, 2, "case {}: validateCalls", case.id);
    assert_end(&harness, case, &case.expect, false);
    // Deviation: the Rust store fences on every 503-class refusal, including
    // state_changed (Go leaves a definite refusal unfenced).
    assert!(
        harness.store.close().is_err(),
        "case {}: state_changed refusal must fence the store",
        case.id
    );
    drop(harness);
}

/// Fails the persist of the final transaction: the fault fires when the final
/// clock sample is taken (sample ordinal 2 of the event), so the intent
/// transaction is committed and the final transaction never reaches the disk
/// — the filesystem equivalent of a crash between the two transactions.
fn fault_final_persist(dir: &Path) -> Box<dyn FnMut() + Send> {
    let dir = dir.to_path_buf();
    Box::new(move || fs::set_permissions(&dir, read_only_dir()).expect("fault: read-only dir"))
}

/// Fails the persist of the intent transaction (sample ordinal 1).
fn fault_intent_persist(dir: &Path) -> Box<dyn FnMut() + Send> {
    let dir = dir.to_path_buf();
    Box::new(move || fs::set_permissions(&dir, read_only_dir()).expect("fault: read-only dir"))
}

/// Shared terminal flow of the unknown-outcome vectors: fenced refusal,
/// exactly one unresolved row, terminal no-redelivery tombstone, and a
/// refused reopen (Go: runUnknownFinalVector, with the documented deviation).
fn run_unknown_final(case: &VectorCase, plan: Plan) {
    let harness = new_harness(case, &plan);
    let event = case.event.as_ref().expect("unknown-final event");
    harness.clock.start_event(event);
    harness
        .clock
        .arm_fault(3, fault_final_persist(&harness.sandbox.0));
    let result = drive_event(&harness, event, "/mcp");
    assert_status(&case.id, &result, 503, "durability_unavailable");
    assert!(
        !result.accepted,
        "case {}: unknown outcome dispatched",
        case.id
    );
    assert!(
        !result.nonce_recorded,
        "case {}: unknown outcome recorded",
        case.id
    );
    let (auth, handler, mutation) = effect_counters(&harness);
    assert_eq!(
        (auth, handler, mutation),
        (0, 0, 0),
        "case {}: effects",
        case.id
    );
    // The intent transaction durably advanced H; the rolled-back final
    // transaction leaves that advance intact, so expect.highWater holds.
    let info = nonce_store_info(&harness.store);
    assert_eq!(
        info.high_water, case.expect.high_water,
        "case {}: highWater",
        case.id
    );
    // Fenced close leaves the persisted dirty epoch; recovery follows.
    assert!(
        harness.store.close().is_err(),
        "case {}: fenced close",
        case.id
    );
    let report = inspect_recovery(&harness.path, &harness.options).expect("inspect recovery");
    assert!(
        report.dirty,
        "case {}: recovery report lost the dirty gate",
        case.id
    );
    let unresolved = report.live.len() + report.intents.len() + report.tombstones.len();
    assert_eq!(unresolved, 1, "case {}: unresolved rows", case.id);
    let claim = if report.live.len() == 1 {
        report.live[0].clone()
    } else {
        report.intents[0].clone()
    };
    reconcile_unknown(&harness.path, &harness.options, &report.hash, &claim)
        .expect("reconcile unknown");
    let after = inspect_recovery(&harness.path, &harness.options).expect("post-reconcile inspect");
    assert_eq!(
        after.tombstones.len(),
        case.expect.tombstone_count as usize,
        "case {}: tombstones",
        case.id
    );
    assert_eq!(
        after.live.len(),
        case.expect.live_count as usize,
        "case {}: live",
        case.id
    );
    assert_eq!(
        after.intents.len(),
        case.expect.intent_count as usize,
        "case {}: intents",
        case.id
    );
    expects_reopen_refused(&harness, &case.id);
    drop(harness);
}

/// Drives unknown-intent-absent as far as the Rust seam allows (Go:
/// runUnknownIntentVector; see the deviation entry).
fn run_unknown_intent(case: &VectorCase, plan: Plan) {
    let harness = new_harness(case, &plan);
    let event = case.event.as_ref().expect("unknown-intent event");
    harness.clock.start_event(event);
    harness
        .clock
        .arm_fault(2, fault_intent_persist(&harness.sandbox.0));
    let result = drive_event(&harness, event, "/mcp");
    assert_status(&case.id, &result, 503, "durability_unavailable");
    assert!(
        !result.accepted,
        "case {}: unknown intent admitted",
        case.id
    );
    assert!(
        !result.nonce_recorded,
        "case {}: unknown intent recorded",
        case.id
    );
    assert!(
        harness.store.close().is_err(),
        "case {}: fenced close",
        case.id
    );
    // Failed intent transaction persisted no H advance (deviation).
    let report = inspect_recovery(&harness.path, &harness.options).expect("inspect recovery");
    assert!(
        report.dirty,
        "case {}: absent unknown operation lost the dirty gate",
        case.id
    );
    let unresolved = report.live.len() + report.intents.len() + report.tombstones.len();
    assert_eq!(unresolved, 0, "case {}: rows after failed intent", case.id);
    assert_eq!(
        report.high_water, 0,
        "case {}: failed intent persisted an H advance",
        case.id
    );
    let claim = mcp_jack::server::durable_format::DurableReceipt {
        version: 1,
        deployment: report.deployment_id.clone(),
        store_generation: report.store_generation,
        owner_generation: report.owner_generation,
        intent_id: "candidate-vector-claim".to_owned(),
        operation_id: [7; 16],
        kid: kid(&event.kid),
        nonce: nonce(&event.nonce),
        signature: signature(&format!("{}:{}", event.kid, event.nonce)),
        request_hash: encode_b64url(&[9; 32]),
        timestamp: event.ts,
        retain_until: event.ts + event.window,
        high_water: 0,
    };
    use mcp_jack::server::durable_store::DurableStoreError;
    let reconciled = reconcile_unknown(&harness.path, &harness.options, &report.hash, &claim);
    assert!(
        matches!(reconciled, Err(DurableStoreError::RecoveryRequired)),
        "case {}: empty unknown history treated as abort: {:?}",
        case.id,
        reconciled
    );
    expects_reopen_refused(&harness, &case.id);
    drop(harness);
}

/// Crash-after-commit-no-dispatch with the documented deviation: the Rust
/// store returns the committed response in-process, so the driver asserts
/// the durable claims plus clean reopen and replay (Go: runCrashVector).
fn run_crash(case: &VectorCase, plan: Plan) {
    let harness = new_harness(case, &plan);
    let event = case.event.as_ref().expect("crash event");
    let result = drive_event(&harness, event, "/mcp");
    assert!(
        result.accepted && result.nonce_recorded,
        "case {}: committed reservation did not survive to the response",
        case.id
    );
    assert_eq!(
        harness.counters.lock().unwrap().native_calls,
        0,
        "case {}: nativeCalls",
        case.id
    );
    let info = nonce_store_info(&harness.store);
    assert_eq!(info.live, 1, "case {}: liveRows", case.id);
    assert_eq!(
        info.high_water, case.expect.high_water,
        "case {}: highWater",
        case.id
    );
    assert!(
        harness.store.close().is_ok(),
        "case {}: clean close after commit",
        case.id
    );
    // Reopen after the simulated crash succeeds unfenced; the reopened store
    // keeps a constant clock at the committed high water.
    let reopen_clock = ScriptedClock::new(&[case.expect.high_water]);
    let reopened = Arc::new(
        DurableNonceStore::open(&harness.path, &harness.options, reopen_clock.boxed())
            .expect("reopen after committed reservation"),
    );
    let harness = Harness {
        store: reopened,
        ..harness
    };
    // The same pair replays without any further write and never re-dispatches.
    let replay = drive_event(&harness, event, "/mcp");
    assert!(
        !replay.accepted && !replay.nonce_recorded && replay.code == "replayed_nonce",
        "case {}: committed pair re-dispatched after crash: {}/{}",
        case.id,
        replay.http_status,
        replay.code
    );
    assert!(
        harness.store.close().is_ok(),
        "case {}: reopen close",
        case.id
    );
    drop(harness);
}

/// Capacity refusal with the documented high-water floor deviation
/// (Go: runCapacityVector).
fn run_capacity(case: &VectorCase, plan: Plan) {
    let harness = new_harness(case, &plan);
    let event = case.event.as_ref().expect("capacity event");
    let result = drive_event(&harness, event, "/mcp");
    if let Some(status) = case.expect.status {
        assert_status(&case.id, &result, status, &case.expect.code);
    }
    assert!(
        !result.nonce_recorded,
        "case {}: capacity refusal recorded a nonce",
        case.id
    );
    assert!(
        !nonce_store_info(&harness.store).unsafe_latched,
        "case {}: fenced",
        case.id
    );
    let (auth, handler, mutation) = effect_counters(&harness);
    assert_eq!(
        (auth, handler, mutation),
        (0, 0, 0),
        "case {}: effects",
        case.id
    );
    let info = nonce_store_info(&harness.store);
    // Deviation: high-water floor (100) instead of the vector's 0.
    assert_eq!(info.high_water, 100, "case {}: high-water floor", case.id);
    if case.expect.preserve_live {
        assert_eq!(
            info.live, case.expect.live_count as usize,
            "case {}: preservedLive",
            case.id
        );
    }
    if case.expect.preserve_tombstones {
        assert_eq!(
            info.tombstones, case.expect.tombstone_count as usize,
            "case {}: preservedTombstones",
            case.id
        );
    }
    // Deviation: the Rust store fences on every 503-class refusal, including
    // capacity_exhausted (Go leaves a definite refusal unfenced).
    assert!(
        harness.store.close().is_err(),
        "case {}: capacity refusal must fence the store",
        case.id
    );
    drop(harness);
}

// ---------------------------------------------------------------------------
// Test.
// ---------------------------------------------------------------------------

#[test]
fn candidate_nonce_vectors() {
    let fixture = load_fixture();
    let exclusions = exclusions();
    let deviations = deviations();
    // Every fixture case is driven or explicitly excluded...
    for case in &fixture.cases {
        assert!(
            plan_of(&case.id).is_some() || exclusions.contains_key(case.id.as_str()),
            "case {} is neither driven nor explicitly excluded",
            case.id
        );
    }
    // ...and every plan, exclusion, and deviation id exists in the fixture,
    // so renamed or dropped fixtures cannot leave silent stale entries.
    let ids: Vec<&str> = fixture.cases.iter().map(|c| c.id.as_str()).collect();
    for id in plan_ids() {
        assert!(ids.contains(&id), "plan {id} does not exist in the fixture");
    }
    for id in exclusions.keys() {
        assert!(
            ids.contains(id),
            "exclusion {id} does not exist in the fixture"
        );
    }
    for id in deviations.keys() {
        assert!(
            ids.contains(id) || *id == "all-cases",
            "deviation {id} does not exist in the fixture"
        );
    }
    assert_eq!(fixture.cases.len(), 24, "exactly 24 candidate vectors");

    for case in &fixture.cases {
        if let Some(exclusion) = exclusions.get(case.id.as_str()) {
            println!(
                "excluded {}: {}; spec: {}",
                case.id, exclusion.reason, exclusion.spec
            );
            continue;
        }
        let plan = plan_of(&case.id).expect("planned case");
        match plan {
            Plan::Single { .. } => run_single(case, plan),
            Plan::Sequence => run_sequence(case, plan),
            Plan::StoreDirect => run_store_direct(case, plan),
            Plan::Crash => run_crash(case, plan),
            Plan::UnknownFinal => run_unknown_final(case, plan),
            Plan::UnknownIntent => run_unknown_intent(case, plan),
            Plan::Capacity => run_capacity(case, plan),
        }
    }
}

fn plan_ids() -> Vec<&'static str> {
    vec![
        "same-second-restart-replay",
        "future-ts-restart-replay",
        "concurrent-same-pair",
        "concurrent-different-request-identity",
        "expiry-equality",
        "expiry-plus-one-fresh-timestamp",
        "delayed-crypto-final-freshness",
        "delayed-final-after-confirmed-intent",
        "purge-highwater-rollback",
        "window-decrease-refused",
        "window-increase-refused",
        "key-snapshot-change-zero-commit",
        "enrollment-snapshot-change-zero-commit",
        "bad-signature-zero-writes",
        "commit-then-authorization-refusal",
        "crash-after-commit-no-dispatch",
        "unknown-final-present",
        "unknown-final-absent",
        "unknown-intent-absent",
        "capacity-live-plus-intent",
        "capacity-tombstones",
        "no-effects-without-final-commit",
    ]
}
