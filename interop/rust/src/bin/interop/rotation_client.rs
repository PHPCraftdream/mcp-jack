//! `--mode rotation-client` of interop-client: single-step client side of the
//! rotation interop matrix (interop/README.md). Prints exactly one JSON
//! result line via the shared emit() helper; startup errors go to stderr
//! with exit code 1.

use std::path::Path;

use mcp_jack::auth_header::parse_response_auth;
use mcp_jack::client::signer::InMemorySigner;
use mcp_jack::client::transport::{HttpRequest, Transport as _};
use mcp_jack::encoding::{decode_b64url_fixed, key_id};
use mcp_jack::rotation::{
    Checkpoint, OwnedBinding, RotationController, RotationError, RotationResponse,
    RotationStoreOptions, RotationTrustStore,
};

use super::net::TcpTransport;
use super::{emit, fatal, hex_decode_32, Outcome, StepResult};

/// Cap mirroring the SDK/transport 1 MiB response body bound.
const MAX_RESULT_BODY_BYTES: usize = 1024 * 1024;

/// Concrete clock-callback type unifying the store generic: one boxed closure
/// per store construction (init and open each get a fresh one).
type ClockFn = Box<dyn FnMut() -> Result<u64, RotationError> + Send>;

/// Builds one fresh store clock closure from the clock file.
fn clock_fn(clock: &ClockFile) -> ClockFn {
    let clock = clock.clone();
    Box::new(move || clock.sample())
}

/// Clock sampled from a driver-managed file, with a last-good cache (mirror
/// of the rotation-server profile).
#[derive(Clone)]
struct ClockFile {
    path: String,
    cache: std::sync::Arc<std::sync::Mutex<Option<u64>>>,
}

impl ClockFile {
    fn new(path: &str) -> Self {
        Self {
            path: path.to_owned(),
            cache: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    fn sample(&self) -> Result<u64, RotationError> {
        let err = || RotationError {
            code: "rotation_clock_unavailable",
        };
        let raw = std::fs::read_to_string(&self.path).map_err(|_| err())?;
        let parsed = raw.trim().parse::<u64>().map_err(|_| err())?;
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *cache = Some(parsed);
        Ok(parsed)
    }
}

/// Parsed command line of rotation-client mode.
struct Flags {
    step: String,
    url: String,
    aud: String,
    seed_hex: String,
    clock_file: String,
    anchor: String,
    store: String,
    cursor: String,
    tool: String,
    window: u64,
    #[allow(dead_code)] // validated (1..=30000), transport has a fixed 15 s timeout
    timeout_ms: u64,
}

/// Hand-rolled flag parsing, same style as the default interop-client mode.
fn parse_flags() -> Flags {
    let mut args = std::env::args().skip(1);
    let mut flags = Flags {
        step: String::new(),
        url: String::new(),
        aud: String::new(),
        seed_hex: String::new(),
        clock_file: String::new(),
        anchor: String::new(),
        store: String::new(),
        cursor: String::new(),
        tool: "jack.server.key".to_owned(),
        window: 30,
        timeout_ms: 10_000,
    };
    while let Some(arg) = args.next() {
        if !arg.starts_with("--") {
            fatal(format!("unexpected positional argument: {arg}"));
        }
        let (name, inline) = match arg.strip_prefix("--").and_then(|r| r.split_once('=')) {
            Some((n, v)) => (n.to_owned(), Some(v.to_owned())),
            None => (arg[2..].to_owned(), None),
        };
        let mut value = |name: &str| -> String {
            match inline.clone() {
                Some(v) => v,
                None => match args.next() {
                    Some(v) => v,
                    None => fatal(format!("missing value for --{name}")),
                },
            }
        };
        match name.as_str() {
            "step" => flags.step = value("step"),
            "url" => flags.url = value("url"),
            "aud" => flags.aud = value("aud"),
            "seed-hex" => flags.seed_hex = value("seed-hex"),
            "clock-file" => flags.clock_file = value("clock-file"),
            "anchor" => flags.anchor = value("anchor"),
            "store" => flags.store = value("store"),
            "cursor" => flags.cursor = value("cursor"),
            "tool" => flags.tool = value("tool"),
            "mode" => {
                // Consumed and already dispatched by the caller binary.
                let _ = value("mode");
            }
            "window" => {
                let raw = value("window");
                flags.window = match raw.parse::<u64>() {
                    Ok(w) => w,
                    Err(_) => fatal("--window must be an integer number of seconds"),
                };
            }
            "timeout-ms" => {
                let raw = value("timeout-ms");
                flags.timeout_ms = match raw.parse::<u64>() {
                    Ok(t) => t.clamp(1, 30_000),
                    Err(_) => fatal("--timeout-ms must be an integer"),
                };
            }
            _ => fatal(format!("unknown flag --{name}")),
        }
    }
    if flags.step.is_empty() {
        fatal("--step is required");
    }
    if !matches!(flags.step.as_str(), "call" | "refresh" | "wire" | "state") {
        fatal("--step must be one of call|refresh|wire|state");
    }
    if flags.url.is_empty() || flags.aud.is_empty() || flags.seed_hex.is_empty() {
        fatal("--url, --aud and --seed-hex are required");
    }
    if flags.clock_file.is_empty() {
        fatal("--clock-file is required");
    }
    if flags.step != "wire" && (flags.anchor.is_empty() || flags.store.is_empty()) {
        fatal("--anchor and --store are required for this step");
    }
    if !(1..=120).contains(&flags.window) {
        fatal("--window must be within 1..=120");
    }
    flags
}

/// Entry point of rotation-client mode. Never returns; exits 0 after emit()
/// (the one stdout line), 1 on any startup failure (stderr only).
pub fn run() -> ! {
    let flags = parse_flags();
    let seed = match hex_decode_32(&flags.seed_hex) {
        Ok(seed) => seed,
        Err(_) => fatal("--seed-hex must be 64 hex chars decoding to 32 bytes"),
    };
    let signer = match InMemorySigner::from_seed(&seed) {
        Ok(signer) => signer,
        Err(e) => fatal(format!("signer: {e}")),
    };
    let clock = ClockFile::new(&flags.clock_file);
    let transport = TcpTransport::new();
    match flags.step.as_str() {
        "call" => run_call(&flags, &signer, &clock, &transport),
        "refresh" => run_refresh(&flags, &signer, &clock, &transport),
        "wire" => run_wire(&flags, &signer, &clock, &transport),
        "state" => run_state(&flags, &clock),
        _ => fatal("unknown --step"), // unreachable: validated in parse_flags
    }
}

/// Opens (initializing if absent) the client trust store pinned to the
/// --anchor checkpoint. Fresh clock closure per construction.
fn open_trust_store(flags: &Flags, clock: &ClockFile) -> RotationTrustStore<ClockFn> {
    let anchor_vec = match decode_b64url_fixed(&flags.anchor, 32) {
        Ok(v) => v,
        Err(e) => fatal(format!("--anchor must decode to 32 bytes: {e}")),
    };
    let anchor_pub: [u8; 32] = anchor_vec
        .try_into()
        .expect("decode_b64url_fixed(_, 32) yields 32 bytes");
    let options = RotationStoreOptions {
        binding: OwnedBinding {
            endpoint: flags.url.clone(),
            aud: flags.aud.clone(),
        },
        window: flags.window,
        checkpoint: Checkpoint {
            ordinal: 0,
            hash: "-".to_owned(),
            kid: key_id(&anchor_pub),
            public_key: anchor_pub,
            published_at: 0,
        },
    };
    let path = Path::new(&flags.store);
    if !path.exists() {
        if let Err(e) =
            RotationTrustStore::initialize_unused(path, options.clone(), clock_fn(clock))
        {
            fatal(format!("rotation store: {}", e.code));
        }
    }
    match RotationTrustStore::open(path, options, clock_fn(clock)) {
        Ok(store) => store,
        Err(e) => fatal(format!("rotation store: {}", e.code)),
    }
}

/// Best-effort clean close, then the single stdout result line.
fn finish(store: &mut RotationTrustStore<ClockFn>, scenario: &str, result: StepResult) -> ! {
    let _ = store.close();
    emit(scenario, result)
}

/// One signed POST through the raw transport with the rotation wire guards
/// (redirect refusal, no content-encoding, 1 MiB body cap). The Ok payload is
/// exactly the SDK RotationResponse shape.
fn post_signed(
    transport: &TcpTransport,
    url: &str,
    aud: &str,
    signer: &InMemorySigner,
    body: &[u8],
    ts: i64,
) -> Result<RotationResponse, StepResult> {
    let nonce = match mcp_jack::client::random_nonce() {
        Ok(n) => n,
        Err(_) => return Err(StepResult::client_error("rotation_request_unavailable")),
    };
    let signed = match mcp_jack::client::sign_request(signer, aud, "POST", "/", body, &nonce, ts) {
        Ok(signed) => signed,
        Err(_) => return Err(StepResult::client_error("rotation_request_unavailable")),
    };
    let request = HttpRequest {
        method: "POST".to_owned(),
        url: url.to_owned(),
        headers: vec![
            ("Jack-Auth".to_owned(), signed.header_value.clone()),
            ("Content-Type".to_owned(), "application/json".to_owned()),
        ],
        body: body.to_vec(),
    };
    let response = match transport.round_trip(request) {
        Ok(response) => response,
        Err(_) => return Err(StepResult::client_error("rotation_request_unavailable")),
    };
    if (300..400).contains(&response.status) {
        return Err(StepResult::client_error("rotation_redirect_refused"));
    }
    if response.header("Content-Encoding").is_some() {
        return Err(StepResult::client_error("rotation_result_invalid"));
    }
    if response.body.len() > MAX_RESULT_BODY_BYTES {
        return Err(StepResult::client_error("rotation_result_invalid"));
    }
    Ok(RotationResponse {
        status: i64::from(response.status),
        headers: response
            .header_values("Jack-Auth")
            .into_iter()
            .map(str::to_owned)
            .collect(),
        request_signature: signed.auth.sig,
        body: response.body,
    })
}

/// Builds the boxed RawValue result payload (same pattern as the scenarios).
fn raw_data(value: &serde_json::Value) -> Box<serde_json::value::RawValue> {
    match serde_json::value::RawValue::from_string(value.to_string()) {
        Ok(data) => data,
        Err(e) => fatal(format!("marshal result: {e}")),
    }
}

/// --step call: one signed ping, fully verified through the rotation
/// controller, with the plain body released only after the final gate.
fn run_call(
    flags: &Flags,
    signer: &InMemorySigner,
    clock: &ClockFile,
    transport: &TcpTransport,
) -> ! {
    let mut store = open_trust_store(flags, clock);
    let (snapshot, _) = match store.snapshot() {
        Ok(v) => v,
        Err(e) => fatal(format!("rotation store: {}", e.code)),
    };
    let guard = match store.check_snapshot_clock(&snapshot) {
        Ok(clock) => clock,
        Err(e) => fatal(format!("rotation store: {}", e.code)),
    };
    let ts = match i64::try_from(guard.high_water) {
        Ok(ts) => ts,
        Err(_) => fatal("rotation clock out of i64 range"),
    };
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec();
    let response = match post_signed(transport, &flags.url, &flags.aud, signer, &body, ts) {
        Ok(response) => response,
        Err(step) => finish(&mut store, &flags.step, step),
    };
    let status = response.status;
    let auth_headers = response.headers.clone();
    let body = response.body.clone();

    let outcome: StepResult = match RotationController::new(&mut store) {
        Err(e) => StepResult::client_error(e.code),
        Ok(mut controller) => match controller.verify_response(response) {
            Ok(_) => {
                if status != 200 {
                    StepResult::rejected(
                        status as u16,
                        super::parse_error_code(&body).unwrap_or_default(),
                    )
                } else {
                    // kid from the verified Jack-Auth header; a parse miss is
                    // reported (never guessed) as "unknown".
                    let refs: Vec<&str> = auth_headers.iter().map(String::as_str).collect();
                    let kid = parse_response_auth(&refs)
                        .map(|auth| auth.kid)
                        .unwrap_or_else(|_| "unknown".to_owned());
                    StepResult {
                        kind: Outcome::Ok,
                        status: Some(200),
                        code: None,
                        data: Some(raw_data(&serde_json::json!({ "signed_by": kid }))),
                    }
                }
            }
            Err(e) => StepResult::client_error(e.code),
        },
    };
    finish(&mut store, &flags.step, outcome)
}

/// --step refresh: one explicit single-page jack.server.key POST through the
/// rotation controller's accept path, anchored at the ACKed head cursor.
fn run_refresh(
    flags: &Flags,
    signer: &InMemorySigner,
    clock: &ClockFile,
    transport: &TcpTransport,
) -> ! {
    let mut store = open_trust_store(flags, clock);
    let (snapshot, _) = match store.snapshot() {
        Ok(v) => v,
        Err(e) => fatal(format!("rotation store: {}", e.code)),
    };
    let cursor = snapshot.head.clone();
    let guard = match store.check_snapshot_clock(&snapshot) {
        Ok(clock) => clock,
        Err(e) => fatal(format!("rotation store: {}", e.code)),
    };
    let ts = match i64::try_from(guard.high_water) {
        Ok(ts) => ts,
        Err(_) => fatal("rotation clock out of i64 range"),
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "jack.server.key",
            "arguments": {
                "after_ordinal": cursor.ordinal,
                "after_hash": cursor.hash,
            },
        },
    })
    .to_string()
    .into_bytes();
    let response = match post_signed(transport, &flags.url, &flags.aud, signer, &body, ts) {
        Ok(response) => response,
        Err(step) => finish(&mut store, &flags.step, step),
    };

    let outcome: StepResult = match RotationController::new(&mut store) {
        Err(e) => StepResult::client_error(e.code),
        Ok(mut controller) => match controller.accept_refresh(response, b"1", &cursor) {
            Ok(r) => StepResult {
                kind: Outcome::Ok,
                status: Some(200),
                code: None,
                data: Some(raw_data(&serde_json::json!({
                    "committed": r.committed,
                    "head_ordinal": r.head.ordinal,
                    "head_hash": r.head.hash,
                    "terminal_ordinal": r.terminal.ordinal,
                    "complete": r.complete,
                    "revision": r.revision,
                }))),
            },
            Err(e) => StepResult::client_error(e.code),
        },
    };
    finish(&mut store, &flags.step, outcome)
}

/// --step wire: one signed POST with no store, no controller and no response
/// verification — raw wire behavior only.
fn run_wire(
    flags: &Flags,
    signer: &InMemorySigner,
    clock: &ClockFile,
    transport: &TcpTransport,
) -> ! {
    let sampled = match clock.sample() {
        Ok(ts) => ts,
        Err(e) => fatal(e),
    };
    let ts = match i64::try_from(sampled) {
        Ok(ts) => ts,
        Err(_) => fatal("rotation clock out of i64 range"),
    };
    let body = match flags.tool.as_str() {
        "jack.server.key" => {
            // Split at the FIRST ':' only: the hash is opaque.
            let Some((ordinal_raw, hash)) = flags.cursor.split_once(':') else {
                fatal("--cursor must be ordinal:hash for the jack.server.key tool");
            };
            let ordinal = match ordinal_raw.parse::<u64>() {
                Ok(ordinal) => ordinal,
                Err(_) => fatal("--cursor ordinal must be an integer"),
            };
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "jack.server.key",
                    "arguments": {
                        "after_ordinal": ordinal,
                        "after_hash": hash,
                    },
                },
            })
            .to_string()
            .into_bytes()
        }
        "ping" => br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec(),
        other => fatal(format!("unknown --tool {other}")),
    };
    match post_signed(transport, &flags.url, &flags.aud, signer, &body, ts) {
        Ok(response) => {
            if (200..300).contains(&response.status) {
                // StepResult::ok semantics: http_status 200, no code, null data.
                let data = raw_data(&serde_json::Value::Null);
                emit(&flags.step, StepResult::ok(data));
            }
            emit(
                &flags.step,
                StepResult::rejected(
                    response.status as u16,
                    super::parse_error_code(&response.body).unwrap_or_default(),
                ),
            )
        }
        Err(step) => emit(&flags.step, step),
    }
}

/// --step state: the committed local trust snapshot only; no network.
fn run_state(flags: &Flags, clock: &ClockFile) -> ! {
    let mut store = open_trust_store(flags, clock);
    let (snapshot, _) = match store.snapshot() {
        Ok(v) => v,
        Err(e) => fatal(format!("rotation store: {}", e.code)),
    };
    let outcome = StepResult {
        kind: Outcome::Ok,
        status: None,
        code: None,
        data: Some(raw_data(&serde_json::json!({
            "head_ordinal": snapshot.head.ordinal,
            "head_hash": snapshot.head.hash,
            "revision": snapshot.revision,
        }))),
    };
    finish(&mut store, &flags.step, outcome)
}
