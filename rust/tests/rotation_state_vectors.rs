#![cfg(target_os = "linux")]

//! Conformance runner for spec/fixtures/candidate/rotation-state-vectors.json
//! (format "mcp-jack-candidate-rotation-state-v1", docs/cross-language-conformance.md G2).
//!
//! Every fixture id is either driven by a real test below or listed in EXCLUDED with a
//! verbatim spec quote; ids carrying an observable caveat are listed in DEVIATIONS.
//! The verdict table is printed with eprintln! (visible under --nocapture).

use mcp_jack::auth_header::{format_response_auth, ResponseAuth};
use mcp_jack::client::{InMemorySigner, Signer};
use mcp_jack::encoding::{decode_b64url, encode_b64url};
use mcp_jack::error::JackError;
use mcp_jack::rotation::{
    parse_record, selected_ordinal, Binding, Checkpoint, OwnedBinding, ResultCursor,
    RotationController, RotationError, RotationRefreshResult, RotationResponse, RotationServerKey,
    RotationServerProvider, RotationServerStore, RotationServerStoreOptions, RotationStoreOptions,
    RotationTrustStore, GRACE_SECONDS, MAX_RESULT_BODY_BYTES,
};
use mcp_jack::server::response_keys::{ResponseKeyAuthorization, ResponseKeyRequest, ResponseKeys};
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Fixture types (field names verified against the committed JSON).
// ---------------------------------------------------------------------------

const FIXTURE_FORMAT: &str = "mcp-jack-candidate-rotation-state-v1";
const CLIENT_CASE_COUNT: usize = 14;
const EVENT_CASE_COUNT: usize = 8;
/// docs/cross-language-conformance.md R5/R7: these are the client-local codes.
const EXPECTED_CLIENT_LOCAL_ERRORS: [&str; 10] = [
    "rotation_result_invalid",
    "rotation_record_invalid",
    "rotation_conflict",
    "rotation_gap",
    "rotation_bridge_expired",
    "rotation_state_changed",
    "rotation_state_unknown",
    "rotation_key_interval",
    "rotation_clock_unsafe",
    "rotation_clock_unavailable",
];

#[derive(Deserialize)]
struct Vectors {
    format: String,
    client_cases: Vec<ClientCase>,
    event_cases: Vec<EventCase>,
    client_local_errors: Vec<String>,
}

#[derive(Deserialize)]
struct ClientCase {
    id: String,
    input: ClientInput,
    expect: ClientExpect,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientInput {
    #[serde(rename = "callbackOutcome")]
    callback_outcome: String,
    cursor: FixtureCursor,
    #[serde(rename = "expectedId")]
    expected_id: i64,
    #[serde(rename = "finalClockGeneration")]
    final_clock_generation: u64,
    #[serde(rename = "finalNow")]
    final_now: u64,
    #[serde(rename = "preCallbackNow")]
    pre_callback_now: u64,
    response: FixtureResponse,
    snapshot: FixtureSnapshot,
    #[serde(rename = "staleSnapshot")]
    stale_snapshot: bool,
    #[serde(rename = "writerBusy")]
    writer_busy: bool,
}

#[derive(Deserialize)]
struct FixtureCursor {
    ordinal: u64,
    hash: String,
}

#[derive(Deserialize)]
struct FixtureResponse {
    #[serde(rename = "body_b64u")]
    body_b64u: String,
    kid: String,
    now: u64,
    #[serde(rename = "requestSig")]
    request_sig: String,
    signature: String,
    status: i64,
    ts: i64,
}

#[derive(Deserialize)]
struct FixtureSnapshot {
    anchor: FixtureKey,
    aud: String,
    #[serde(rename = "clockGeneration")]
    clock_generation: u64,
    endpoint: String,
    fence: bool,
    records: Vec<String>,
    revision: u64,
    window: u64,
}

#[derive(Deserialize)]
struct FixtureKey {
    kid: String,
    public_key: String,
}

#[derive(Deserialize)]
struct ClientExpect {
    #[serde(rename = "ackOrdinal")]
    ack_ordinal: u64,
    callbacks: u64,
    #[serde(rename = "carrierTrusted")]
    carrier_trusted: Option<bool>,
    committed: Option<bool>,
    error: Option<String>,
    duplicate: Option<bool>,
    fenced: Option<bool>,
}

#[derive(Deserialize)]
struct EventCase {
    id: String,
    input: EventInput,
}

#[derive(Deserialize)]
#[serde(tag = "kind")]
enum EventInput {
    #[serde(rename = "selection")]
    Selection {
        after: u64,
        at: u64,
        before: u64,
        records: Vec<String>,
    },
    #[serde(rename = "clock")]
    Clock {
        guard: ClockGuard,
        #[serde(rename = "rawNow")]
        raw_now: u64,
        latch: Option<String>,
    },
    #[serde(rename = "emission")]
    Emission {
        #[serde(rename = "clockGenerationBefore")]
        clock_generation_before: u64,
        #[serde(rename = "clockGenerationNow")]
        clock_generation_now: u64,
        #[serde(rename = "emissionTime")]
        emission_time: u64,
        records: Vec<String>,
        #[serde(rename = "selectedKid")]
        selected_kid: String,
        #[serde(rename = "selectedOrdinal")]
        selected_ordinal: u64,
        #[serde(rename = "signerReady")]
        signer_ready: Option<bool>,
        #[serde(rename = "signingTime")]
        signing_time: u64,
    },
}

#[derive(Deserialize)]
struct ClockGuard {
    binding: String,
    #[serde(rename = "highWater")]
    high_water: u64,
    revision: u64,
    window: u64,
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../spec/fixtures/candidate/rotation-state-vectors.json")
}

fn load_vectors() -> Vectors {
    let bytes = fs::read(fixture_path()).expect("committed candidate fixture");
    serde_json::from_slice(&bytes).expect("typed rotation-state vectors")
}

// ---------------------------------------------------------------------------
// Verdict tables (guarded below; printed by the tests).
// ---------------------------------------------------------------------------

/// Vector ids fully driven by a test below with every observable expectation checked.
const DRIVEN_FULL: [&str; 13] = [
    "first-bridge-before-cutoff",
    "first-bridge-at-cutoff",
    "unknown-outer-before-invalid-payload",
    "exact-duplicate-at-new-key-lower-bound",
    "new-key-lower-bound-minus-one-is-stale",
    "duplicate-prefix-then-extension",
    "late-callback-ack-retains-snapshot-but-rejects-carrier",
    "conflicting-duplicate-prefix-is-not-adopted",
    "gapped-prefix-cannot-be-claimed-by-head",
    "whole-response-body-cap-plus-one",
    "same-second-greatest-ordinal-wins",
    "clock-rollback-latches",
    "clock-advance-persists-revision",
];

/// Vector ids driven against the real code with a documented semantic caveat.
const DRIVEN_WITH_DEVIATION: [&str; 8] = [
    "clock-equal-is-noop",
    "clock-rollback-latch-unknown-is-unavailable",
    "trust-callback-unknown-fences",
    "busy-writer-stops-before-trust-callback",
    "stale-whole-snapshot-stops-before-callback",
    "server-final-eligible-single-signature",
    "server-final-cutoff-no-resign",
    "server-final-generation-fence-no-fallback",
];

/// Vector ids with no drivable production counterpart on the public Rust seam.
const EXCLUDED: [(&str, &str); 1] = [(
    "trust-callback-definite-conflict",
    "No injectable trust-CAS conflict point exists on the public Rust seam: \
     RotationController owns the store exclusively via &mut, and \
     compare_and_swap pre-checks the whole snapshot against the same single \
     file read (no interleaving window). Spec 5 quote: \"An external trust or \
     clock conflict is one definite noncommit, with no adoption, merge, or \
     retry.\" The structural counterpart (exact whole-snapshot compare \
     returning rotation_state_changed) is production code in \
     rust/src/rotation/store.rs and is asserted for real by the \
     stale-whole-snapshot deviation test below.",
)];

/// (id, caveat) pairs for driven vectors whose every expectation is not observable.
const DEVIATIONS: [(&str, &str); 7] = [
    (
        "clock-rollback-latch-unknown-is-unavailable",
        "The model writes a latch on the failed sample (writes:1); Rust maps a \
         failing clock sample to rotation_clock_unavailable and fences WITHOUT \
         writing the latch, so error/H/revision/unsafe are asserted exactly from \
         the durable file but the failed-sample latch write is a documented \
         behavioral difference.",
    ),
    (
        "trust-callback-unknown-fences",
        "The unknown CAS outcome is injected by making the sandbox directory \
         read-only during compare_and_swap (temp-file replace fails). \
         callback/write counters are unobservable on the public seam; the durable \
         fence is asserted via a refused reopen (dirty bundle on disk).",
    ),
    (
        "busy-writer-stops-before-trust-callback",
        "Rust has no in-process interleaving: the store is a single-writer \
         exclusive FileOwner, so the structural counterpart is a second \
         concurrent open being refused before any callback. The model's \
         rotation_state_changed is rotation_state_unavailable in Rust; zero \
         adoption is asserted.",
    ),
    (
        "stale-whole-snapshot-stops-before-callback",
        "Single-threaded &mut ownership makes a mid-refresh interleaving \
         impossible; the exact whole-snapshot pre-callback compare (production \
         code, returns rotation_state_changed) is driven directly with a captured \
         stale snapshot and zero adoption is asserted. Spec quote: \"If token \
         acquisition fails or the expected pre-callback snapshot is stale, reject \
         before callback with zero trust-CAS invocations.\"",
    ),
    (
        "server-final-eligible-single-signature",
        "signatures:1/resigns:0 are structural: the provider selects exactly one \
         pinned signer per authorize_response call and there is no re-sign API; \
         the selected kid literals differ from the fixture because the fixture \
         ships no private keys (asserted by ring ordinal/public-key equivalence \
         instead).",
    ),
    (
        "server-final-cutoff-no-resign",
        "emit:false asserted as a refused final gate (rotation_state_unavailable) \
         at the strict cutoff; resigns:0 is structural (no re-sign API). Fixture \
         kid literals are mapped by ring ordinal/public-key equivalence.",
    ),
    (
        "server-final-generation-fence-no-fallback",
        "Rust has no clockGeneration concept; the semantic equivalent (clock \
         rollback between signing and emission making final_gate refuse with no \
         fallback signer) is driven instead of a generation bump.",
    ),
];

// ---------------------------------------------------------------------------
// Local helpers (kept out of rust/tests/common on purpose).
// ---------------------------------------------------------------------------

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).expect("getrandom");
        let path = std::env::temp_dir().join(format!(
            "jack-rust-state-vectors-{}-{}",
            process::id(),
            encode_b64url(&random)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("sandbox dir");
        Self(path)
    }

    fn file(&self) -> PathBuf {
        self.0.join("trust")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // A deviation test may have left the directory read-only.
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Injectable clock shared with the closure: ordered overrides, current value,
/// forced failure, and a sample counter.
#[derive(Clone)]
struct SharedClock {
    inner: Rc<RefCell<SharedClockState>>,
}

struct SharedClockState {
    pending: VecDeque<u64>,
    current: u64,
    fail: bool,
    samples: u64,
}

impl SharedClock {
    fn at(current: u64) -> Self {
        Self {
            inner: Rc::new(RefCell::new(SharedClockState {
                pending: VecDeque::new(),
                current,
                fail: false,
                samples: 0,
            })),
        }
    }

    fn set(&self, current: u64) {
        self.inner.borrow_mut().current = current;
    }

    /// Ordered overrides consumed before the sticky current value.
    fn enqueue(&self, values: &[u64]) {
        self.inner
            .borrow_mut()
            .pending
            .extend(values.iter().copied());
    }

    fn fail(&self) {
        self.inner.borrow_mut().fail = true;
    }

    fn samples(&self) -> u64 {
        self.inner.borrow().samples
    }

    fn closure(&self) -> Box<dyn FnMut() -> Result<u64, RotationError>> {
        let inner = Rc::clone(&self.inner);
        Box::new(move || {
            let mut state = inner.borrow_mut();
            state.samples += 1;
            if let Some(value) = state.pending.pop_front() {
                return Ok(value);
            }
            if state.fail {
                Err(RotationError {
                    code: "rotation_clock_unavailable",
                })
            } else {
                Ok(state.current)
            }
        })
    }
}

fn trust_options(snapshot: &FixtureSnapshot) -> RotationStoreOptions {
    let public: [u8; 32] = decode_b64url(&snapshot.anchor.public_key)
        .expect("anchor public key")
        .try_into()
        .expect("32-byte anchor key");
    RotationStoreOptions {
        binding: OwnedBinding {
            endpoint: snapshot.endpoint.clone(),
            aud: snapshot.aud.clone(),
        },
        window: snapshot.window,
        checkpoint: Checkpoint {
            ordinal: 0,
            hash: "-".to_owned(),
            kid: snapshot.anchor.kid.clone(),
            public_key: public,
            published_at: 0,
        },
    }
}

type BoxClock = Box<dyn FnMut() -> Result<u64, RotationError>>;
/// `RotationServerProvider` requires `C: FnMut() -> Result<u64, RotationError> + Send + 'static`;
/// a boxed closure satisfies that bound (plain `Arc<AtomicU64>` does not).
type ServerClock = Box<dyn FnMut() -> Result<u64, RotationError> + Send>;

fn initialize_trust(path: &Path, options: &RotationStoreOptions, now: u64) {
    RotationTrustStore::initialize_unused(path, options.clone(), || Ok(now))
        .expect("initialize unused trust store");
}

fn open_trust(
    path: &Path,
    options: &RotationStoreOptions,
    clock: &SharedClock,
) -> RotationTrustStore<BoxClock> {
    RotationTrustStore::open(path, options.clone(), clock.closure()).expect("open trust store")
}

/// Rebuilds the fixture's real signed carrier response verbatim.
fn response_of(case: &ClientCase) -> RotationResponse {
    let response = &case.input.response;
    let body = decode_b64url(&response.body_b64u).expect("fixture body base64url");
    RotationResponse {
        status: response.status,
        headers: vec![format_response_auth(&ResponseAuth {
            kid: response.kid.clone(),
            ts: response.ts,
            sig: response.signature.clone(),
        })],
        request_signature: response.request_sig.clone(),
        body,
    }
}

fn cursor_of(cursor: &FixtureCursor) -> ResultCursor {
    ResultCursor {
        ordinal: cursor.ordinal,
        hash: cursor.hash.clone(),
    }
}

fn drive_refresh(
    store: &mut RotationTrustStore<BoxClock>,
    case: &ClientCase,
) -> Result<RotationRefreshResult, JackError> {
    let mut controller = RotationController::new(store).expect("controller");
    controller.accept_refresh(
        response_of(case),
        case.input.expected_id.to_string().as_bytes(),
        &cursor_of(&case.input.cursor),
    )
}

/// Seeds ordinal 1 by driving the real first-bridge response (a genuine CAS commit).
fn seed_ord1(path: &Path, options: &RotationStoreOptions, vectors: &Vectors, now: u64) {
    initialize_trust(path, options, now);
    let clock = SharedClock::at(now);
    let mut store = open_trust(path, options, &clock);
    let first = vectors
        .client_cases
        .iter()
        .find(|case| case.id == "first-bridge-before-cutoff")
        .expect("first-bridge-before-cutoff in fixture");
    let result = drive_refresh(&mut store, first).expect("seed refresh commits");
    assert!(result.committed, "seed refresh must commit");
    store.close().expect("clean close after seed");
}

/// Reads the durable clock document from the sealed store file.
fn clock_doc(path: &Path) -> (u64, u64, bool) {
    let outer: serde_json::Value =
        serde_json::from_slice(&fs::read(path).expect("store file")).expect("seal");
    let bundle: serde_json::Value =
        serde_json::from_str(outer["payload"].as_str().expect("payload")).expect("bundle");
    let clock: serde_json::Value =
        serde_json::from_str(bundle["clock"].as_str().expect("clock")).expect("clock doc");
    (
        clock["high_water"].as_u64().expect("high_water"),
        clock["clock_revision"].as_u64().expect("revision"),
        clock["unsafe_clock"].as_bool().expect("unsafe"),
    )
}

fn expect_ok(case: &ClientCase, result: RotationRefreshResult) {
    let expect = &case.expect;
    assert_eq!(expect.error, None, "{}: expected success", case.id);
    assert_eq!(
        expect.committed,
        Some(result.committed),
        "{}: committed",
        case.id
    );
    assert_eq!(expect.ack_ordinal, result.head.ordinal, "{}: ack", case.id);
    // Trust-CAS callbacks are observable via commit: exactly one iff an
    // extension was adopted (duplicates invoke zero callbacks).
    assert_eq!(
        expect.callbacks,
        u64::from(result.committed),
        "{}: callback count",
        case.id
    );
    if expect.duplicate == Some(true) {
        assert!(!result.committed, "{}: duplicate must not commit", case.id);
        assert_eq!(
            result.head.ordinal, expect.ack_ordinal,
            "{}: duplicate keeps the ack",
            case.id
        );
    }
}

fn expect_err(case: &ClientCase, error: &JackError) {
    let expected = case
        .expect
        .error
        .as_deref()
        .expect("error expectation present");
    assert_eq!(error.code, expected, "{}: error code", case.id);
}

fn find_client<'a>(vectors: &'a Vectors, id: &str) -> &'a ClientCase {
    vectors
        .client_cases
        .iter()
        .find(|case| case.id == id)
        .unwrap_or_else(|| panic!("missing client case {id}"))
}

fn find_event<'a>(vectors: &'a Vectors, id: &str) -> &'a EventCase {
    vectors
        .event_cases
        .iter()
        .find(|case| case.id == id)
        .unwrap_or_else(|| panic!("missing event case {id}"))
}

// ---------------------------------------------------------------------------
// Guards.
// ---------------------------------------------------------------------------

#[test]
fn guard_fixture_shape_and_error_table() {
    let vectors = load_vectors();
    assert_eq!(vectors.format, FIXTURE_FORMAT, "format string");
    assert_eq!(
        vectors.client_cases.len(),
        CLIENT_CASE_COUNT,
        "client cases"
    );
    assert_eq!(vectors.event_cases.len(), EVENT_CASE_COUNT, "event cases");
    let mut ids: Vec<&str> = vectors
        .client_cases
        .iter()
        .map(|case| case.id.as_str())
        .collect();
    ids.extend(vectors.event_cases.iter().map(|case| case.id.as_str()));
    ids.sort_unstable();
    assert_eq!(
        ids.len(),
        CLIENT_CASE_COUNT + EVENT_CASE_COUNT,
        "fixture ids must be unique: {ids:?}"
    );
    let mut local_errors = vectors.client_local_errors.clone();
    local_errors.sort();
    let mut expected = EXPECTED_CLIENT_LOCAL_ERRORS.to_vec();
    expected.sort_unstable();
    assert_eq!(local_errors, expected, "client_local_errors table");
    let mut stale_cases = 0;
    let mut busy_cases = 0;
    for case in &vectors.client_cases {
        assert_eq!(
            case.input.response.now, case.input.response.ts,
            "{}: response now/ts agree",
            case.id
        );
        assert!(
            !case.input.response.request_sig.is_empty()
                && !case.input.response.signature.is_empty(),
            "{}: carrier signature material present",
            case.id
        );
        assert!(!case.input.snapshot.fence, "{}: unfenced anchor", case.id);
        assert_eq!(
            case.input.snapshot.revision, 1,
            "{}: anchor revision",
            case.id
        );
        assert!(
            case.input.snapshot.records.len() <= 1,
            "{}: anchor carries at most the ordinal-1 seed record",
            case.id
        );
        if case.input.snapshot.records.len() == 1 {
            assert_eq!(
                case.input.cursor.ordinal, 1,
                "{}: seeded record implies cursor ordinal 1",
                case.id
            );
        }
        assert_eq!(
            case.input.final_clock_generation, 1,
            "{}: single clock generation (Rust has no generation concept)",
            case.id
        );
        // committed=true implies exactly one trust-CAS callback in the model.
        if case.expect.committed == Some(true) {
            assert_eq!(case.expect.callbacks, 1, "{}: commit callback", case.id);
        }
        if case.input.callback_outcome != "ack" {
            // Only the unknown-outcome and (excluded) conflict callbacks differ.
            assert!(
                case.expect.error.is_some(),
                "{}: non-ack callback must error",
                case.id
            );
        }
        if case.input.stale_snapshot {
            stale_cases += 1;
        }
        if case.input.writer_busy {
            busy_cases += 1;
        }
    }
    assert_eq!(stale_cases, 1, "exactly one stale-snapshot vector");
    assert_eq!(busy_cases, 1, "exactly one busy-writer vector");
}

#[test]
fn guard_every_vector_is_classified() {
    let vectors = load_vectors();
    let mut all: Vec<&str> = vectors
        .client_cases
        .iter()
        .map(|case| case.id.as_str())
        .collect();
    all.extend(vectors.event_cases.iter().map(|case| case.id.as_str()));
    for id in &all {
        let driven = DRIVEN_FULL.contains(id) || DRIVEN_WITH_DEVIATION.contains(id);
        let excluded = EXCLUDED.iter().any(|(excluded_id, _)| excluded_id == id);
        assert!(driven || excluded, "unclassified vector {id}");
        if DRIVEN_WITH_DEVIATION.contains(id) {
            assert!(
                DEVIATIONS
                    .iter()
                    .any(|(deviation_id, _)| deviation_id == id),
                "deviation-driven vector {id} missing from DEVIATIONS"
            );
        }
    }
    for (deviation_id, _) in DEVIATIONS {
        assert!(
            all.contains(&deviation_id),
            "DEVIATIONS names unknown vector {deviation_id}"
        );
    }
    for (excluded_id, _) in EXCLUDED {
        assert!(
            all.contains(&excluded_id),
            "EXCLUDED names unknown vector {excluded_id}"
        );
    }
    eprintln!(
        "verdict: {} driven-full, {} driven-with-deviation, {} excluded",
        DRIVEN_FULL.len(),
        DRIVEN_WITH_DEVIATION.len(),
        EXCLUDED.len()
    );
}

// ---------------------------------------------------------------------------
// Driven client_cases (refresh semantics against the real controller/store).
// ---------------------------------------------------------------------------

#[test]
fn vector_first_bridge_before_cutoff() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "first-bridge-before-cutoff");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    initialize_trust(&sandbox.file(), &options, 173_799);
    let clock = SharedClock::at(173_799);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let result = drive_refresh(&mut store, &case).expect("commits before activation");
    expect_ok(&case, result.clone());
    assert_eq!(result.revision, 2);
    assert_eq!(result.head.ordinal, 1);
    assert!(result.complete);
    assert_eq!(result.terminal.ordinal, 1);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    // carrierTrusted: the carrier key stays eligible at the final sample.
    assert_eq!(snapshot.keys[0].known_cutoff, Some(173_800));
    assert!(173_799 < snapshot.keys[0].known_cutoff.expect("cutoff"));
    eprintln!(
        "verdict {} = driven-full (Ok, committed true, revision 2, head 1, carrier trusted)",
        case.id
    );
}

#[test]
fn vector_first_bridge_at_cutoff() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "first-bridge-at-cutoff");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    initialize_trust(&sandbox.file(), &options, 173_800);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let error = drive_refresh(&mut store, &case).expect_err("bridge expires at A");
    expect_err(&case, &error);
    // committed:false, callbacks:0 => the anchor snapshot is untouched.
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 1);
    assert_eq!(snapshot.head.ordinal, 0);
    eprintln!(
        "verdict {} = driven-full (rotation_bridge_expired, committed false, zero adoption)",
        case.id
    );
}

#[test]
fn vector_unknown_outer_before_invalid_payload() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "unknown-outer-before-invalid-payload");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    initialize_trust(&sandbox.file(), &options, 1_000);
    let clock = SharedClock::at(1_000);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let error = drive_refresh(&mut store, &case).expect_err("unknown key refused");
    expect_err(&case, &error);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 1);
    eprintln!(
        "verdict {} = driven-full (unknown_server_key; key set checked before the body)",
        case.id
    );
}

#[test]
fn vector_exact_duplicate_at_new_key_lower_bound() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "exact-duplicate-at-new-key-lower-bound");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let result = drive_refresh(&mut store, &case).expect("duplicate is a no-op success");
    expect_ok(&case, result);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 2, "no trust revision increment");
    assert_eq!(snapshot.head.ordinal, 1, "head unchanged");
    // carrierTrusted: the new key is within its interval at now=173800.
    assert_eq!(snapshot.keys[1].not_before, 173_800);
    assert_eq!(snapshot.keys[1].known_cutoff, None);
    eprintln!(
        "verdict {} = driven-full (Ok duplicate no-op, callbacks 0, revision stays 2)",
        case.id
    );
}

#[test]
fn vector_new_key_lower_bound_minus_one_is_stale() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "new-key-lower-bound-minus-one-is-stale");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_769);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let error = drive_refresh(&mut store, &case).expect_err("outside the window");
    expect_err(&case, &error);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 2, "no adoption");
    eprintln!(
        "verdict {} = driven-full (timestamp_out_of_window, committed false)",
        case.id
    );
}

#[test]
fn vector_duplicate_prefix_then_extension() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "duplicate-prefix-then-extension");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let result = drive_refresh(&mut store, &case).expect("extension commits");
    expect_ok(&case, result.clone());
    assert!(result.committed);
    assert_eq!(result.revision, 3, "one trust revision increment");
    assert_eq!(result.head.ordinal, 2, "head ordinal 2");
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.keys.len(), 3);
    assert_eq!(snapshot.records.len(), 2);
    eprintln!(
        "verdict {} = driven-full (committed true, head ordinal 2, revision 3, carrier trusted)",
        case.id
    );
}

#[test]
fn vector_late_callback_ack_retains_snapshot_but_rejects_carrier() {
    let vectors = load_vectors();
    let case = find_client(
        &vectors,
        "late-callback-ack-retains-snapshot-but-rejects-carrier",
    );
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    // The model samples preCallbackNow (173799) until the callback and finalNow
    // (173800) at the final gate. The controller samples 5 times before the
    // final gate (store open advance, controller construction, raw outer
    // clock, outer ClockGuard, pre-callback ClockGuard), then once there.
    initialize_trust(&sandbox.file(), &options, 173_799);
    let clock = SharedClock::at(173_800);
    clock.enqueue(&[173_799; 5]);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let error = drive_refresh(&mut store, &case).expect_err("carrier fails the final gate");
    expect_err(&case, &error);
    assert_eq!(clock.samples(), 6, "five pre-callback samples, one final");
    store.close().expect("close after late-carrier failure");
    // committed stays true: reopen proves the ACK was retained.
    let reopen = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &reopen);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 2, "ACK retained");
    assert_eq!(snapshot.head.ordinal, 1);
    assert_eq!(snapshot.keys.len(), 2);
    // carrierTrusted:false: at equality the old key is strictly retired.
    assert_eq!(snapshot.keys[0].known_cutoff, Some(173_800));
    eprintln!(
        "verdict {} = driven-full (rotation_key_interval; commit retained, carrier untrusted)",
        case.id
    );
}

#[test]
fn vector_conflicting_duplicate_prefix_is_not_adopted() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "conflicting-duplicate-prefix-is-not-adopted");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let error = drive_refresh(&mut store, &case).expect_err("conflicting duplicate");
    expect_err(&case, &error);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 2, "conflicting record not adopted");
    assert_eq!(snapshot.records.len(), 1);
    eprintln!(
        "verdict {} = driven-full (rotation_conflict, zero adoption)",
        case.id
    );
}

#[test]
fn vector_gapped_prefix_cannot_be_claimed_by_head() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "gapped-prefix-cannot-be-claimed-by-head");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_799);
    let clock = SharedClock::at(173_799);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let error = drive_refresh(&mut store, &case).expect_err("gap refused");
    expect_err(&case, &error);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 2, "no adoption");
    assert_eq!(snapshot.records.len(), 1);
    eprintln!(
        "verdict {} = driven-full (rotation_gap, committed false)",
        case.id
    );
}

#[test]
fn vector_whole_response_body_cap_plus_one() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "whole-response-body-cap-plus-one");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    initialize_trust(&sandbox.file(), &options, 1_000);
    let clock = SharedClock::at(1_000);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    let response = response_of(&case);
    assert_eq!(
        response.body.len(),
        MAX_RESULT_BODY_BYTES + 1,
        "fixture body is exactly cap+1"
    );
    let error = drive_refresh(&mut store, &case).expect_err("over the body cap");
    expect_err(&case, &error);
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 1);
    eprintln!(
        "verdict {} = driven-full (rotation_result_invalid at 262145 bytes, committed false)",
        case.id
    );
}

// --- deviation-driven client_cases ---------------------------------------

#[test]
fn vector_trust_callback_unknown_fences() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "trust-callback-unknown-fences");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    // Inject the unknown CAS outcome: the temp-file replace inside
    // compare_and_swap fails while the directory is read-only.
    fs::set_permissions(&sandbox.0, fs::Permissions::from_mode(0o500))
        .expect("chmod sandbox read-only");
    let error = drive_refresh(&mut store, &case).expect_err("unknown outcome");
    let code = error.code.clone();
    fs::set_permissions(&sandbox.0, fs::Permissions::from_mode(0o700))
        .expect("restore sandbox permissions");
    assert_eq!(
        code, "rotation_state_unknown",
        "{}: unknown outcome",
        case.id
    );
    assert_eq!(case.expect.fenced, Some(true), "{}: model fences", case.id);
    drop(store);
    // fenced:true => a reopen is refused (the bundle stays dirty on disk).
    let reopen = SharedClock::at(173_800);
    let reopen_error = RotationTrustStore::open(&sandbox.file(), options.clone(), reopen.closure())
        .err()
        .expect("fenced store refuses reopen")
        .code;
    assert_eq!(reopen_error, "rotation_state_unavailable");
    let (high_water, revision, unsafe_clock) = clock_doc(&sandbox.file());
    assert_eq!(
        high_water, case.input.final_now,
        "clock high-water unchanged"
    );
    assert_eq!(revision, 2, "clock revision unchanged by the failed CAS");
    assert!(!unsafe_clock);
    eprintln!(
        "verdict {} = driven-with-deviation (rotation_state_unknown; fenced reopen; \
         CAS counters unobservable)",
        case.id
    );
}

#[test]
fn vector_busy_writer_stops_before_trust_callback() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "busy-writer-stops-before-trust-callback");
    assert!(case.input.writer_busy, "fixture marks the writer busy");
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    // Structural counterpart: the Rust store is a single-writer exclusive
    // FileOwner, so a second concurrent writer is refused before any callback.
    let second_clock = SharedClock::at(173_800);
    let second_error =
        RotationTrustStore::open(&sandbox.file(), options.clone(), second_clock.closure())
            .err()
            .expect("second writer refused")
            .code;
    assert_eq!(second_error, "rotation_state_unavailable");
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(
        snapshot.revision, 2,
        "zero adoption while a writer is active"
    );
    eprintln!(
        "verdict {} = driven-with-deviation (model rotation_state_changed maps to \
         rotation_state_unavailable: the exclusive single-writer file owner refuses \
         the second writer before any callback)",
        case.id
    );
}

#[test]
fn vector_stale_whole_snapshot_stops_before_callback() {
    let vectors = load_vectors();
    let case = find_client(&vectors, "stale-whole-snapshot-stops-before-callback");
    assert!(
        case.input.stale_snapshot,
        "fixture marks the snapshot stale"
    );
    let sandbox = Sandbox::new();
    let options = trust_options(&case.input.snapshot);
    seed_ord1(&sandbox.file(), &options, &vectors, 173_769);
    let clock = SharedClock::at(173_800);
    let mut store = open_trust(&sandbox.file(), &options, &clock);
    // Capture the pre-callback snapshot, advance the durable state, then drive
    // the production exact whole-snapshot compare with the stale value.
    let (stale, _) = store.snapshot().expect("pre-callback snapshot");
    let extension = find_client(&vectors, "duplicate-prefix-then-extension");
    let committed = drive_refresh(&mut store, &extension).expect("extension commits");
    assert!(committed.committed);
    let error = store
        .check_snapshot_clock(&stale)
        .err()
        .expect("stale snapshot refused");
    assert_eq!(error.code, "rotation_state_changed");
    // Zero adoption from the refused compare: durable state keeps the extension.
    let (snapshot, _) = store.snapshot().expect("snapshot");
    assert_eq!(snapshot.revision, 3, "no rollback and no double adoption");
    assert_eq!(snapshot.head.ordinal, 2);
    eprintln!(
        "verdict {} = driven-with-deviation (rotation_state_changed from the production \
         exact whole-snapshot compare with zero adoption; not a mid-refresh interleaving: \
         the controller owns the store via &mut)",
        case.id
    );
}

// ---------------------------------------------------------------------------
// Driven event_cases: selection.
// ---------------------------------------------------------------------------

#[test]
fn vector_same_second_greatest_ordinal_wins() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "same-second-greatest-ordinal-wins");
    let EventInput::Selection {
        after,
        at,
        before,
        records,
    } = &case.input
    else {
        panic!("selection input");
    };
    let snapshot = &find_client(&vectors, "first-bridge-before-cutoff")
        .input
        .snapshot;
    let binding = Binding {
        endpoint: &snapshot.endpoint,
        aud: &snapshot.aud,
    };
    let anchor: [u8; 32] = decode_b64url(&snapshot.anchor.public_key)
        .expect("anchor key")
        .try_into()
        .expect("32 bytes");
    let mut authorizers: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    authorizers.insert(snapshot.anchor.kid.clone(), anchor);
    let mut parsed = Vec::new();
    for wire in records {
        let record = parse_record(wire.as_bytes(), binding, &authorizers).expect("record");
        authorizers.insert(record.new_kid.clone(), record.public_key);
        parsed.push(record);
    }
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].ordinal, 1);
    assert_eq!(parsed[1].ordinal, 2);
    assert_eq!(selected_ordinal(&parsed, *before).expect("selection"), 0);
    assert_eq!(selected_ordinal(&parsed, *at).expect("selection"), 2);
    assert_eq!(selected_ordinal(&parsed, *after).expect("selection"), 2);
    eprintln!(
        "verdict {} = driven-full (selected ordinals 0/2/2 at 173799/173800/173801)",
        case.id
    );
}

// ---------------------------------------------------------------------------
// Driven event_cases: ClockGuard.
// ---------------------------------------------------------------------------

/// Builds the fixture guard state by driving the real store: init at H-3,
/// open at H-2, advance to H-1, advance to H => clock revision 4 at H.
fn open_guard_store(
    path: &Path,
    guard: &ClockGuard,
    clock: &SharedClock,
) -> RotationTrustStore<BoxClock> {
    assert_eq!(guard.revision, 4, "guard revision the fixture ships");
    assert_eq!(guard.window, 30);
    let snapshot = find_client(&load_vectors(), "first-bridge-before-cutoff")
        .input
        .snapshot;
    assert_eq!(
        guard.binding, snapshot.endpoint,
        "guard binding is the endpoint of the seeded snapshot"
    );
    let options = trust_options(&snapshot);
    assert!(guard.high_water >= 3);
    clock.set(guard.high_water - 2);
    initialize_trust(path, &options, guard.high_water - 3);
    let mut store = open_trust(path, &options, clock);
    clock.set(guard.high_water - 1);
    store.advance_and_check().expect("advance to H-1");
    clock.set(guard.high_water);
    store.advance_and_check().expect("advance to H");
    let (high_water, revision, unsafe_clock) = clock_doc(path);
    assert_eq!(
        (high_water, revision, unsafe_clock),
        (guard.high_water, 4, false)
    );
    store
}

#[test]
fn vector_clock_rollback_latches() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "clock-rollback-latches");
    let EventInput::Clock {
        guard,
        raw_now,
        latch,
    } = &case.input
    else {
        panic!("clock input");
    };
    assert_eq!(latch.as_deref(), None, "plain rollback latch");
    let sandbox = Sandbox::new();
    let clock = SharedClock::at(0);
    let mut store = open_guard_store(&sandbox.file(), guard, &clock);
    let baseline = clock.samples();
    clock.set(*raw_now);
    let error = store
        .advance_and_check()
        .err()
        .expect("rollback refuses")
        .code;
    assert_eq!(error, "rotation_clock_unsafe");
    assert_eq!(clock.samples() - baseline, 1, "exactly one clock callback");
    // The latch write is durable: exactly one write (revision 4 -> 5, unsafe).
    let (high_water, revision, unsafe_clock) = clock_doc(&sandbox.file());
    assert_eq!(
        (high_water, revision, unsafe_clock),
        (guard.high_water, 5, true)
    );
    // The latch persists: the next check refuses without even sampling.
    let second = store.advance_and_check().err().expect("latched").code;
    assert_eq!(second, "rotation_clock_unsafe");
    assert_eq!(
        clock.samples() - baseline,
        1,
        "no further sample once latched"
    );
    eprintln!(
        "verdict {} = driven-full (rotation_clock_unsafe, callbacks 1, durable latch rev 5 unsafe)",
        case.id
    );
}

#[test]
fn vector_clock_equal_is_noop() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "clock-equal-is-noop");
    let EventInput::Clock {
        guard,
        raw_now,
        latch,
    } = &case.input
    else {
        panic!("clock input");
    };
    assert_eq!(latch.as_deref(), None);
    let sandbox = Sandbox::new();
    let clock = SharedClock::at(0);
    let mut store = open_guard_store(&sandbox.file(), guard, &clock);
    let baseline = clock.samples();
    clock.set(*raw_now);
    let result = store.advance_and_check().expect("equal sample is a noop");
    assert_eq!(result.high_water, guard.high_water);
    assert_eq!(result.revision, guard.revision);
    assert!(!result.unsafe_clock);
    assert_eq!(clock.samples() - baseline, 1, "one sample");
    let (high_water, revision, unsafe_clock) = clock_doc(&sandbox.file());
    assert_eq!(
        (high_water, revision, unsafe_clock),
        (guard.high_water, 4, false)
    );
    eprintln!(
        "verdict {} = driven-with-deviation (error null, H/revision/unsafe exact, writes 0 via \
         durable clock doc; the model's callbacks:0 counts durable callbacks while the Rust \
         ClockGuard necessarily samples once)",
        case.id
    );
}

#[test]
fn vector_clock_rollback_latch_unknown_is_unavailable() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "clock-rollback-latch-unknown-is-unavailable");
    let EventInput::Clock {
        guard,
        raw_now,
        latch,
    } = &case.input
    else {
        panic!("clock input");
    };
    assert_eq!(latch.as_deref(), Some("unknown"));
    let sandbox = Sandbox::new();
    let clock = SharedClock::at(0);
    let mut store = open_guard_store(&sandbox.file(), guard, &clock);
    let baseline = clock.samples();
    clock.set(*raw_now);
    clock.fail();
    let error = store
        .advance_and_check()
        .err()
        .expect("failing sample refuses")
        .code;
    assert_eq!(error, "rotation_clock_unavailable");
    assert_eq!(clock.samples() - baseline, 1, "exactly one clock callback");
    // H/revision/unsafe unchanged: the model's failed sample performs no write.
    let (high_water, revision, unsafe_clock) = clock_doc(&sandbox.file());
    assert_eq!(
        (high_water, revision, unsafe_clock),
        (guard.high_water, 4, false)
    );
    eprintln!(
        "verdict {} = driven-with-deviation (rotation_clock_unavailable with H/revision/unsafe \
         exact; deviation: the model writes a latch on the failed sample while Rust fences \
         without writing the latch)",
        case.id
    );
}

#[test]
fn vector_clock_advance_persists_revision() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "clock-advance-persists-revision");
    let EventInput::Clock {
        guard,
        raw_now,
        latch,
    } = &case.input
    else {
        panic!("clock input");
    };
    assert_eq!(latch.as_deref(), None);
    let sandbox = Sandbox::new();
    let clock = SharedClock::at(0);
    let mut store = open_guard_store(&sandbox.file(), guard, &clock);
    let baseline = clock.samples();
    clock.set(*raw_now);
    let result = store.advance_and_check().expect("advance persists");
    assert_eq!(result.high_water, *raw_now);
    assert_eq!(result.revision, guard.revision + 1);
    assert!(!result.unsafe_clock);
    assert_eq!(clock.samples() - baseline, 1);
    let (high_water, revision, unsafe_clock) = clock_doc(&sandbox.file());
    assert_eq!((high_water, revision, unsafe_clock), (*raw_now, 5, false));
    eprintln!(
        "verdict {} = driven-full (H 173801, revision 5, one durable write)",
        case.id
    );
}

// ---------------------------------------------------------------------------
// Driven event_cases: server emission.
// ---------------------------------------------------------------------------

struct PinnedKey {
    reference: String,
    signer: Arc<InMemorySigner>,
}

impl PinnedKey {
    fn handle(&self) -> RotationServerKey {
        RotationServerKey {
            reference: self.reference.clone(),
            signer: Arc::clone(&self.signer) as Arc<dyn Signer>,
        }
    }
}

struct ServerRing {
    sandbox: Sandbox,
    provider: RotationServerProvider<ServerClock>,
    now: Arc<AtomicU64>,
    keys: Vec<PinnedKey>,
}

/// Builds a real three-key ring whose record arithmetic matches the fixture
/// exactly (R1 published 1000 activates 173800, R2 published 4600 activates
/// 177400). The fixture ships no private keys, so the kids are seed-derived.
fn server_ring(announces: &[(usize, u64)]) -> ServerRing {
    let sandbox = Sandbox::new();
    let keys: Vec<PinnedKey> = [51u8, 52, 53]
        .iter()
        .enumerate()
        .map(|(index, seed)| PinnedKey {
            reference: format!("k{index}"),
            signer: Arc::new(InMemorySigner::from_seed(&[*seed; 32]).expect("signer")),
        })
        .collect();
    let anchor = &keys[0];
    let options = RotationServerStoreOptions {
        binding: OwnedBinding {
            endpoint: "https://svc.example.test/mcp".to_owned(),
            aud: "https://svc.example.test".to_owned(),
        },
        window: 30,
        checkpoint: Checkpoint {
            ordinal: 0,
            hash: "-".to_owned(),
            kid: anchor.signer.kid().to_owned(),
            public_key: anchor.signer.public_key(),
            published_at: 0,
        },
        anchor_reference: anchor.reference.clone(),
    };
    let now = Arc::new(AtomicU64::new(1_000));
    let init_now = Arc::clone(&now);
    RotationServerStore::initialize_unused(&sandbox.file(), options.clone(), || {
        Ok(init_now.load(Ordering::SeqCst))
    })
    .expect("initialize server store");
    let store_now = Arc::clone(&now);
    let store = Arc::new(Mutex::new(
        RotationServerStore::open(
            &sandbox.file(),
            options,
            Box::new(move || Ok(store_now.load(Ordering::SeqCst))) as ServerClock,
        )
        .expect("open server store"),
    ));
    let handles: Vec<RotationServerKey> = keys.iter().map(PinnedKey::handle).collect();
    let provider = RotationServerProvider::new(store, handles).expect("provider");
    for (index, at) in announces {
        now.store(*at, Ordering::SeqCst);
        let publication = provider
            .announce(&keys[*index].reference, keys[*index].signer.kid())
            .expect("announce");
        assert_eq!(
            publication.record.published_at, *at,
            "publication time is the fresh sample"
        );
    }
    ServerRing {
        sandbox,
        provider,
        now,
        keys,
    }
}

/// Fixture ring-slot kid: ordinal 0 is the anchor (old kid of R1), ordinal k
/// is the new kid of record ordinal k.
fn fixture_selected_kid(records: &[String], ordinal: u64) -> String {
    let lines: Vec<&str> = records[0].split('\n').collect();
    if ordinal == 0 {
        lines[5].to_owned()
    } else {
        lines[6].to_owned()
    }
}

/// Selects the signer at signing_time and checks ring-slot equivalence with
/// the fixture's selectedOrdinal (kid literals differ; no private keys ship).
fn emission_authorized(
    ring: &ServerRing,
    ordinal: usize,
    signing_time: u64,
) -> ResponseKeyAuthorization {
    assert!(ring.sandbox.file().exists(), "server store file present");
    ring.now.store(signing_time, Ordering::SeqCst);
    let request = ResponseKeyRequest {
        status: 200,
        tool: "other/tool",
        request_signature: "candidate-event-request-signature",
        body: b"{}",
    };
    let auth = ring
        .provider
        .authorize_response(&request)
        .expect("authorized");
    assert_eq!(auth.timestamp, signing_time, "fresh signing sample");
    let selected = &ring.keys[ordinal];
    assert_eq!(
        auth.signer.public_key(),
        selected.signer.public_key(),
        "exactly one pinned signer selected (structural signatures:1)"
    );
    auth
}

#[test]
fn vector_server_final_eligible_single_signature() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "server-final-eligible-single-signature");
    let EventInput::Emission {
        clock_generation_before,
        clock_generation_now,
        emission_time,
        records,
        selected_ordinal,
        signing_time,
        selected_kid,
        ..
    } = &case.input
    else {
        panic!("emission input");
    };
    assert_eq!(clock_generation_before, clock_generation_now);
    assert_eq!(*signing_time, emission_time);
    assert_eq!(records.len(), 1, "fixture ring holds R1 only");
    assert_eq!(
        selected_kid.as_str(),
        fixture_selected_kid(records, *selected_ordinal),
        "fixture selected kid matches its ring slot"
    );
    let ring = server_ring(&[(1, 1_000)]);
    assert_eq!(
        1_000 + GRACE_SECONDS,
        173_800,
        "R1 activates at A1 like the fixture"
    );
    let auth = emission_authorized(&ring, *selected_ordinal as usize, *signing_time);
    let gate = auth.final_gate;
    assert!(gate().is_ok(), "eligible emission passes the final gate");
    auth.release();
    eprintln!(
        "verdict {} = driven-with-deviation (gate Ok; signer selected exactly once; fixture kid \
         literals mapped by ring ordinal/public-key equivalence)",
        case.id
    );
}

#[test]
fn vector_server_final_cutoff_no_resign() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "server-final-cutoff-no-resign");
    let EventInput::Emission {
        emission_time,
        records,
        selected_ordinal,
        signer_ready,
        signing_time,
        selected_kid,
        ..
    } = &case.input
    else {
        panic!("emission input");
    };
    assert_eq!(signer_ready, Some(true));
    assert_eq!(records.len(), 2, "fixture ring holds R1 and R2");
    assert_eq!(
        selected_kid.as_str(),
        fixture_selected_kid(records, *selected_ordinal),
        "fixture selected kid matches its ring slot"
    );
    let ring = server_ring(&[(1, 1_000), (2, 4_600)]);
    assert_eq!(4_600 + GRACE_SECONDS, 177_400, "R2 activates at A2");
    let auth = emission_authorized(&ring, *selected_ordinal as usize, *signing_time);
    // Emission at the exact cutoff: the signed key is strictly retired.
    ring.now.store(*emission_time, Ordering::SeqCst);
    let gate = auth.final_gate;
    let error = gate().err().expect("cutoff refuses").code;
    assert_eq!(
        error, "rotation_state_unavailable",
        "strict cutoff, no fallback"
    );
    auth.release();
    eprintln!(
        "verdict {} = driven-with-deviation (emit:false via refused final gate at emission 177400 \
         vs cutoff 177400; resigns:0 structural - there is no re-sign API)",
        case.id
    );
}

#[test]
fn vector_server_final_generation_fence_no_fallback() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "server-final-generation-fence-no-fallback");
    let EventInput::Emission {
        clock_generation_before,
        clock_generation_now,
        emission_time,
        records,
        selected_ordinal,
        signing_time,
        ..
    } = &case.input
    else {
        panic!("emission input");
    };
    assert_eq!(
        clock_generation_before + 1,
        clock_generation_now,
        "the model bumps clockGeneration between signing and emission"
    );
    assert_eq!(records.len(), 2);
    let ring = server_ring(&[(1, 1_000), (2, 4_600)]);
    let auth = emission_authorized(&ring, *selected_ordinal as usize, *signing_time);
    // Semantic equivalent of the generation fence: the clock moves backward
    // between signing and emission; the final gate must refuse, no fallback.
    ring.now.store(*emission_time - 1, Ordering::SeqCst);
    let gate = auth.final_gate;
    let error = gate().err().expect("fence refuses").code;
    assert_eq!(error, "rotation_state_unavailable");
    auth.release();
    eprintln!(
        "verdict {} = driven-with-deviation (emit:false via refused final gate after a clock \
         rollback; Rust has no clockGeneration so the rollback is the documented equivalent)",
        case.id
    );
}
