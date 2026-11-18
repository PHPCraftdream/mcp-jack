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
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
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
    #[allow(dead_code)] // schema field the runner does not need
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
    #[allow(dead_code)] // schema field the runner does not need
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
    #[allow(dead_code)] // schema field the runner does not need
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
const DEVIATIONS: [(&str, &str); 8] = [
    (
        "clock-equal-is-noop",
        "The model's callbacks:0 counts durable clock callbacks while the Rust \
         ClockGuard necessarily samples once (the equal sample is a durable \
         noop: H/revision/unsafe are asserted exactly from the clock doc).",
    ),
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
        // serde rename on ClockDocument.unsafe_clock (rust/src/rotation/trust_json_wire.rs).
        clock["unsafe"].as_bool().expect("unsafe"),
    )
}

fn expect_ok(case: &ClientCase, result: RotationRefreshResult) {
    let expect = &case.expect;
    assert_eq!(expect.error, None, "{}: expected success", case.id);
    // committed:null in the fixture expresses "no commit / zero trust-CAS".
    assert_eq!(
        result.committed,
        expect.committed.unwrap_or(false),
        "{}: committed",
        case.id
    );
    if expect.committed.is_none() {
        assert!(
            !result.committed,
            "{}: absent committed means no commit",
            case.id
        );
    }
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

#[path = "../common/mod.rs"]
mod common;

mod client_vectors;
mod server_emission;
