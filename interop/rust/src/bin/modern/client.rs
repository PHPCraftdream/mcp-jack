//! The `modern-client` executable (interop/modern/contract.md 4.1-4.4): the
//! flag set, the SDK signing transport over the interop `TcpTransport`, the
//! fixed clock and deterministic nonces of section 2, the step record of 4.2
//! and the one result line. The request sequences themselves live in
//! [`super::scenarios`].
//!
//! Every request is hand-built and sent through `SigningTransport`
//! (contract 4.1): `Client::call_tool` assigns its own JSON-RPC ids while this
//! contract requires the `--json-id` text verbatim, so the bodies are ours
//! while signing and response verification stay inside the SDK.

use std::cell::{Cell, RefCell};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use mcp_jack::client::error::ClientError;
use mcp_jack::client::signer::InMemorySigner;
use mcp_jack::client::transport::{
    Clock, HttpRequest, HttpResponse, NonceSource, SigningTransport, Transport, TransportError,
};
use mcp_jack::encoding::decode_b64url_fixed;
use mcp_jack::modern::Era;

use crate::interop::net::TcpTransport;
use crate::interop::{hex_decode_32, is_auth_failure_code, parse_error_code};

use super::proto;
use super::scenarios;

/// Contract 4.1: the default of `--probe-version`.
const DEFAULT_PROBE_VERSION: &str = "2026-07-28";
/// Contract 4.1: the default of `--json-id`.
const DEFAULT_JSON_ID: &str = "1";
/// Contract 4.2: the response code of a 401 that may not be unsigned.
const MISSING_AUTH: &str = "missing_auth";

/// The one endpoint of the contract (4.1); `--url` is only where it lives.
const TARGET: &str = "/mcp";

/// `--era` (contract 4.1). `auto` is the C9 flow only; the other two never
/// probe and never handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraArg {
    Legacy,
    Modern,
    Auto,
}

/// Why the scenario sequence did not run to its end (contract 4.2 and 4.3).
pub enum Halt {
    /// An intermediate answer was not a 2xx where the sequence needs one;
    /// the last step decides the result line (the fakes' `StopScenario`).
    Sequence,
    /// No answer was trusted, so the run is a `client_error` whose code is
    /// the SDK's own (`bad_signature`, `missing_auth`, ...).
    ClientError(String),
    /// The client itself stopped after a verified answer, with its own code
    /// (contract 4.3 `unsupported_version_no_overlap`).
    Rejected(&'static str),
    /// A transport failure after an answer had arrived: reportable as the
    /// contract 4.2/4.3 `client_error` without a code.
    TransportFailed,
    /// The scenario cannot be run at all: exit 1, no result line.
    Fatal(String),
}

/// One request of a sequence: what the step report and the wire need.
#[derive(Clone)]
pub struct Request {
    /// The step name of contract 4.4.
    pub name: String,
    /// HTTP method; GET and HEAD go out with an empty body.
    pub method: String,
    /// Body method; `None` for GET and HEAD (contract 4.2).
    pub jsonrpc_method: Option<String>,
    /// The era this request belongs to (contract 4.2 `data.era`).
    pub era: Era,
    /// The headers this executable puts on the wire, in send order.
    pub headers: Vec<(String, String)>,
    /// The exact body bytes.
    pub body: Vec<u8>,
}

/// What one exchange handed back to the scenario layer.
pub struct Performed {
    /// HTTP status of the response that arrived.
    pub status: u16,
    /// The parsed response body, `None` when it is not JSON at all.
    pub json: Option<Value>,
    /// `Mcp-Session-Id` of the response (contract 4.3 handshake).
    pub session_id: Option<String>,
    /// Whether the response signature verified; an allowed unsigned 401 is
    /// acted on but never selects an era (contract 4.3).
    pub verified: bool,
    /// The request that produced it, resent verbatim by a replay.
    request: Request,
    nonce: [u8; 16],
    ts: i64,
    body: Vec<u8>,
}

impl Performed {
    /// The exact response bytes, for the contract 4.3 era detection.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Contract 4.2: an intermediate answer that is not a 2xx stops the sequence.
pub fn require_ok(performed: &Performed) -> Result<(), Halt> {
    if (200..300).contains(&performed.status) {
        Ok(())
    } else {
        Err(Halt::Sequence)
    }
}

/// One run of one scenario: the endpoint, the SDK transport and the steps.
pub struct Ctx {
    /// `--scenario`.
    pub scenario: String,
    /// `--json-id`, inserted verbatim into every signed body.
    pub json_id: String,
    /// `--probe-version`, the version a C9 probe asks for.
    pub probe_version: String,
    /// `--era`.
    pub era: EraArg,
    url: String,
    signing: SigningTransport<Arc<Exchange>>,
    signer: InMemorySigner,
    staged: Staged,
    exchange: Arc<Exchange>,
    clock_file: String,
    nonce_index: Cell<usize>,
    last_era: Cell<Era>,
    steps: RefCell<Vec<Step>>,
}

impl Ctx {
    /// Contract section 2: "now" always comes from the clock file, never the
    /// wall clock, and it is re-read per request so a stale sample can never
    /// leak in; a file that stopped being readable fails the run instead.
    fn now(&self) -> i64 {
        proto::clock_or_exit(&self.clock_file, "modern-client")
    }

    /// Stages the one nonce and pinned timestamp of the request about to be
    /// sent. Staging is explicit because the index must advance once per NEW
    /// request while a replay reuses its source request's nonce (section 2).
    fn stage(&self, nonce: [u8; 16], ts: i64) {
        let mut slot = self
            .staged
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *slot = Some((nonce, ts));
    }

    fn take_exchange(&self) -> Option<LastExchange> {
        self.exchange
            .last
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
    }

    /// Sends one new request: the nonce index advances exactly once here
    /// (contract section 2).
    pub fn send(&self, request: Request) -> Result<Performed, Halt> {
        let index = self.nonce_index.get();
        self.nonce_index.set(index + 1);
        let nonce = proto::derive_nonce(&self.scenario, index);
        let ts = self.now();
        self.stage(nonce, ts);
        self.perform(&request, nonce, ts)
    }

    /// Contract 4.4 (`modern-mismatch-name`) and section 2: a replay is not a
    /// new request — the same bytes, signature and nonce go out again, so the
    /// nonce index does not advance and no new nonce is derived.
    pub fn replay(&self, name: &'static str, source: &Performed) -> Result<Performed, Halt> {
        self.stage(source.nonce, source.ts);
        let request = Request {
            name: name.to_owned(),
            ..source.request.clone()
        };
        self.perform(&request, source.nonce, source.ts)
    }

    fn perform(&self, request: &Request, nonce: [u8; 16], ts: i64) -> Result<Performed, Halt> {
        let wire = HttpRequest {
            method: request.method.clone(),
            url: self.url.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
        };
        // Contract 4.2: `data.era` is the era of the LAST request sent.
        self.last_era.set(request.era);
        let outcome = self.signing.round_trip_as(&self.signer, Some(ts), wire);
        // A transport failure is only fatal while no answer exists yet
        // (contract 4.2); afterwards it is a reportable `client_error`.
        if let Err(error) = &outcome {
            if matches!(
                error,
                TransportError::Client(_)
                    | TransportError::Transport(_)
                    | TransportError::Streaming
            ) {
                return self.transport_failure(request, error);
            }
        }
        // The capture is the exchange the signing layer actually made; it
        // exists for every answer the SDK classified, verified or refused.
        let Some((sent, received)) = self.take_exchange() else {
            return Err(Halt::Fatal(
                "the signing transport returned without an exchange".to_owned(),
            ));
        };
        let response = match received {
            Ok(response) => response,
            Err(error) => return Err(Halt::Fatal(error.to_string())),
        };
        let json = parse_json(&response.body);
        let session_id = response.header("Mcp-Session-Id").map(str::to_owned);
        // The step is recorded before classification, so a client_error still
        // reports every request that actually went out (contract 4.2).
        self.steps
            .borrow_mut()
            .push(Step::new(request, &sent, &response));
        let mut performed = Performed {
            status: response.status,
            json,
            session_id,
            verified: true,
            request: request.clone(),
            nonce,
            ts,
            body: response.body.clone(),
        };
        match outcome {
            Ok(_) => Ok(performed),
            // spec 01 section 5: an unsigned answer is acted on only up to
            // its status, and only the 401 auth-failure family may lack one.
            Err(TransportError::Unauthenticated(_)) => {
                if response.status == 401 && unsigned_allowed(&response.body) {
                    // Allowed, but nothing signed it, so it must not verify an
                    // era (contract 4.3 C9 "unverified" row).
                    performed.verified = false;
                    Ok(performed)
                } else {
                    Err(Halt::ClientError(MISSING_AUTH.to_owned()))
                }
            }
            // A signed answer that did not verify is a client_error carrying
            // the SDK's code (bad_signature, timestamp_out_of_window, ...).
            Err(TransportError::Protocol(error)) => Err(Halt::ClientError(error.code)),
            Err(error) => Err(Halt::Fatal(error.to_string())),
        }
    }

    /// Contract 4.2 and the C9 row of 4.3: a transport failure after at least
    /// one answer in this run is a `client_error` whose failing step carries
    /// null response members; before the first answer there is nothing to
    /// report, so the run cannot start at all.
    fn transport_failure(
        &self,
        request: &Request,
        error: &TransportError,
    ) -> Result<Performed, Halt> {
        // The capture exists whenever the SDK reached the HTTP layer; a
        // client-side step that failed earlier (URL policy, nonce, signing)
        // leaves none, and the executable's own request is reported instead.
        let sent = self.take_exchange().map(|(sent, _)| sent);
        if self.steps.borrow().is_empty() {
            return Err(Halt::Fatal(error.to_string()));
        }
        self.steps
            .borrow_mut()
            .push(Step::unanswered(request, sent.as_ref()));
        Err(Halt::TransportFailed)
    }

    /// The recorded steps, in send order.
    fn finish_steps(&self) -> Vec<Step> {
        std::mem::take(&mut *self.steps.borrow_mut())
    }
}

/// One response plus the request that produced it: the capture the step
/// report is built from.
type LastExchange = (HttpRequest, Result<HttpResponse, TransportError>);

/// The one nonce (with its pinned timestamp) staged for the request about to
/// be sent; contract section 2 stages explicitly because a replay must reuse
/// its source request's nonce.
type Staged = Arc<Mutex<Option<([u8; 16], i64)>>>;

/// The capture wrapper of the interop `TcpTransport` (contract 4.2): it keeps
/// the exact request the SDK handed it — that clone already carries the
/// `Jack-Auth` header, and `TcpTransport` writes headers one per line in the
/// given order, so the clone IS the wire request — and the inner result, so a
/// response the SDK refuses (unsigned 401, failed verification) is still
/// reported.
struct Exchange {
    inner: TcpTransport,
    last: Mutex<Option<LastExchange>>,
}

impl Transport for Exchange {
    fn round_trip(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let result = self.inner.round_trip(request.clone());
        let mut slot = self
            .last
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *slot = Some((request, result.clone()));
        result
    }
}

/// One step of the contract 4.2 report: every member present, `null` where not
/// applicable, byte fields unpadded base64url.
#[derive(serde::Serialize)]
struct Step {
    name: String,
    http_method: String,
    http_target: &'static str,
    jsonrpc_method: Option<String>,
    http_status: Option<u16>,
    id: Value,
    request_headers: Vec<(String, String)>,
    request_body_b64u: String,
    /// Contract 4.2: null for a step that never got an answer back.
    request_sig: Option<String>,
    response_auth: Option<String>,
    response_content_type: Option<String>,
    response_allow: Option<String>,
    response_session_id: Option<String>,
    response_body_b64u: String,
    /// The exact response bytes, kept for the contract 4.2 code derivation of
    /// the result line; the report itself carries them base64url above.
    #[serde(skip)]
    response_body: Vec<u8>,
}

impl Step {
    fn new(request: &Request, sent: &HttpRequest, response: &HttpResponse) -> Self {
        let json = parse_json(&response.body);
        Self {
            name: request.name.clone(),
            http_method: request.method.clone(),
            http_target: TARGET,
            jsonrpc_method: request.jsonrpc_method.clone(),
            http_status: Some(response.status),
            // Contract 4.2: the response body's JSON-RPC id, null when absent
            // or unparsable.
            id: json
                .as_ref()
                .and_then(|json| json.get("id"))
                .cloned()
                .unwrap_or(Value::Null),
            request_headers: sent.headers.clone(),
            request_body_b64u: proto::b64u(&sent.body),
            request_sig: Some(request_sig(sent)),
            response_auth: response.header("Jack-Auth").map(str::to_owned),
            response_content_type: response.header("Content-Type").map(str::to_owned),
            response_allow: response.header("Allow").map(str::to_owned),
            response_session_id: response.header("Mcp-Session-Id").map(str::to_owned),
            response_body_b64u: proto::b64u(&response.body),
            response_body: response.body.clone(),
        }
    }

    /// Contract 4.2 and 4.3: the step of a request whose transport failed
    /// after an earlier answer, so it has no response members at all. The
    /// captured request carries the `Jack-Auth` the SDK appended; when the
    /// failure happened before the HTTP layer there is none to report.
    fn unanswered(request: &Request, sent: Option<&HttpRequest>) -> Self {
        let headers = sent.map(|sent| &sent.headers).unwrap_or(&request.headers);
        let body = sent
            .map(|sent| sent.body.as_slice())
            .unwrap_or(request.body.as_slice());
        Self {
            name: request.name.clone(),
            http_method: request.method.clone(),
            http_target: TARGET,
            jsonrpc_method: request.jsonrpc_method.clone(),
            http_status: None,
            id: Value::Null,
            request_headers: headers.clone(),
            request_body_b64u: proto::b64u(body),
            request_sig: sent.map(request_sig),
            response_auth: None,
            response_content_type: None,
            response_allow: None,
            response_session_id: None,
            response_body_b64u: String::new(),
            response_body: Vec::new(),
        }
    }
}

/// Contract 4.2: the `sig` member of the `Jack-Auth` header the SDK appended.
fn request_sig(sent: &HttpRequest) -> String {
    let values = sent.header_values("Jack-Auth");
    match mcp_jack::auth_header::parse_request_auth(&values) {
        Ok(auth) => auth.sig,
        // Unreachable: SigningTransport appends one canonical header to every
        // request it sends (rust/src/client/transport.rs), so it always parses.
        Err(_) => String::new(),
    }
}

/// The parsed response body, `None` when it is not JSON at all.
fn parse_json(body: &[u8]) -> Option<Value> {
    serde_json::from_slice(body).ok()
}

/// Contract 4.2 and spec 01 section 5: the only response family that may lack
/// `Jack-Auth` is a 401 carrying one of the auth-failure codes.
fn unsigned_allowed(body: &[u8]) -> bool {
    parse_error_code(body).is_some_and(|code| is_auth_failure_code(&code))
}

/// Contract 4.2: an integer code only from a JSON-RPC 2.0 error object, then a
/// string Jack envelope code, else null.
fn wire_code(body: &[u8]) -> Value {
    let Some(json) = parse_json(body) else {
        return Value::Null;
    };
    let Some(error) = json.get("error").filter(|error| error.is_object()) else {
        return Value::Null;
    };
    if json.get("jsonrpc").and_then(Value::as_str) == Some("2.0") {
        if let Some(code) = integer_code(error.get("code")) {
            return Value::from(code);
        }
    }
    match error.get("code") {
        Some(Value::String(code)) => Value::from(code.clone()),
        _ => Value::Null,
    }
}

/// The integer value of a JSON number, as the driver's `Number.isInteger`
/// reads it: a number with no fractional part.
fn integer_code(code: Option<&Value>) -> Option<i64> {
    let code = code?;
    if let Some(code) = code.as_i64() {
        return Some(code);
    }
    let float = code.as_f64()?;
    (float.is_finite() && float.fract() == 0.0).then_some(float as i64)
}

/// Contract 4.2: the one result line.
#[derive(serde::Serialize)]
struct Report {
    scenario: String,
    outcome: &'static str,
    http_status: Option<u16>,
    code: Value,
    data: Data,
}

/// Contract 4.2: the era the run settled on and every step in send order.
#[derive(serde::Serialize)]
struct Data {
    era: &'static str,
    steps: Vec<Step>,
}

/// Contract 4.2: outcome and code describe the last response, unless a local
/// failure decided the run.
fn build_report(
    scenario: &str,
    era: &'static str,
    halt: &Result<(), Halt>,
    steps: Vec<Step>,
) -> Report {
    let last = steps.last();
    let (outcome, http_status, code) = match halt {
        Err(Halt::ClientError(code)) => ("client_error", None, Value::from(code.clone())),
        // The failing step carries no status and no body, so nothing on the
        // wire decides it: a code-less `client_error` (contract 4.2/4.3).
        Err(Halt::TransportFailed) => ("client_error", None, Value::Null),
        Err(Halt::Rejected(code)) => (
            "rejected",
            last.and_then(|step| step.http_status),
            Value::from(*code),
        ),
        // `Fatal` exits before this point, and `Sequence` lets the last
        // verified step decide the result line.
        _ => match last {
            None => ("client_error", None, Value::Null),
            Some(step) => {
                let status = step.http_status;
                let outcome = match status {
                    Some(status) if (200..300).contains(&status) => "ok",
                    _ => "rejected",
                };
                (outcome, status, wire_code(&step.response_body))
            }
        },
    };
    Report {
        scenario: scenario.to_owned(),
        outcome,
        http_status,
        code,
        data: Data { era, steps },
    }
}

/// Contract section 2: a startup failure is one stderr line and exit 1, with
/// nothing on stdout.
fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("modern-client: {message}");
    std::process::exit(1)
}

/// Parsed command line (contract 4.1).
struct Flags {
    url: String,
    aud: String,
    seed_hex: String,
    anchor: String,
    scenario: String,
    era: EraArg,
    clock_file: String,
    probe_version: String,
    json_id: String,
}

/// Hand-rolled flag parsing like the other bins: both `--flag value` and
/// `--flag=value`; unknown flags, missing values and positional arguments are
/// startup failures. `--mode` is the dispatch selector the driver always
/// passes and is consumed but not needed here.
fn parse_flags() -> Flags {
    let mut args = std::env::args().skip(1);
    let mut url: Option<String> = None;
    let mut aud: Option<String> = None;
    let mut seed_hex: Option<String> = None;
    let mut anchor: Option<String> = None;
    let mut scenario: Option<String> = None;
    let mut era: Option<String> = None;
    let mut clock_file: Option<String> = None;
    let mut probe_version: Option<String> = None;
    let mut json_id: Option<String> = None;
    while let Some(arg) = args.next() {
        if !arg.starts_with("--") {
            fail(format!("unexpected positional argument: {arg}"));
        }
        let (name, inline) = match arg.strip_prefix("--").and_then(|rest| rest.split_once('=')) {
            Some((name, value)) => (name.to_owned(), Some(value.to_owned())),
            None => (arg[2..].to_owned(), None),
        };
        let mut value = |name: &str| -> String {
            match inline.clone() {
                Some(value) => value,
                None => match args.next() {
                    Some(value) => value,
                    None => fail(format!("missing value for --{name}")),
                },
            }
        };
        match name.as_str() {
            // Already consumed by mode_from_args before this parser runs.
            "mode" => {
                let _ = value("mode");
            }
            "url" => url = Some(value("url")),
            "aud" => aud = Some(value("aud")),
            "seed-hex" => seed_hex = Some(value("seed-hex")),
            "anchor" => anchor = Some(value("anchor")),
            "scenario" => scenario = Some(value("scenario")),
            "era" => era = Some(value("era")),
            "clock-file" => clock_file = Some(value("clock-file")),
            "probe-version" => probe_version = Some(value("probe-version")),
            "json-id" => json_id = Some(value("json-id")),
            _ => fail(format!("unknown flag --{name}")),
        }
    }
    let Some(era) = era else {
        fail("missing required --era");
    };
    let era = match era.as_str() {
        "legacy" => EraArg::Legacy,
        "modern" => EraArg::Modern,
        "auto" => EraArg::Auto,
        other => fail(format!(
            "--era must be legacy, modern or auto, not '{other}'"
        )),
    };
    Flags {
        url: url.unwrap_or_else(|| fail("missing required --url")),
        aud: aud.unwrap_or_else(|| fail("missing required --aud")),
        seed_hex: seed_hex.unwrap_or_else(|| fail("missing required --seed-hex")),
        anchor: anchor.unwrap_or_else(|| fail("missing required --anchor")),
        scenario: scenario.unwrap_or_else(|| fail("missing required --scenario")),
        era,
        clock_file: clock_file.unwrap_or_else(|| fail("missing required --clock-file")),
        probe_version: probe_version.unwrap_or_else(|| DEFAULT_PROBE_VERSION.to_owned()),
        json_id: json_id.unwrap_or_else(|| DEFAULT_JSON_ID.to_owned()),
    }
}

/// Entry point of `--mode modern-client`. Never returns.
pub fn run() -> ! {
    let flags = parse_flags();
    // Contract section 2: every startup failure happens before the first
    // request and before anything reaches stdout.
    proto::read_clock(&flags.clock_file)
        .unwrap_or_else(|error| fail(format!("--clock-file: {error}")));
    if flags.url.is_empty() {
        fail("--url must not be empty");
    }
    let seed = hex_decode_32(&flags.seed_hex)
        .unwrap_or_else(|_| fail("--seed-hex must be 64 hex characters (32 bytes)"));
    let signer = InMemorySigner::from_seed(&seed)
        .unwrap_or_else(|error| fail(format!("--seed-hex: {error}")));
    let anchor = decode_b64url_fixed(&flags.anchor, 32)
        .unwrap_or_else(|error| fail(format!("--anchor must decode to 32 bytes: {error}")));
    let server_key: [u8; 32] = anchor
        .try_into()
        .expect("decode_b64url_fixed(_, 32) yields 32 bytes");

    let exchange = Arc::new(Exchange {
        inner: TcpTransport::new(),
        last: Mutex::new(None),
    });
    let staged: Staged = Arc::new(Mutex::new(None));
    // Contract section 2: the wall clock is never consulted.
    let clock_file = flags.clock_file.clone();
    let now: Clock = Arc::new(move || proto::clock_or_exit(&clock_file, "modern-client"));
    let nonce: NonceSource = {
        let staged = Arc::clone(&staged);
        Arc::new(move || {
            let slot = staged.lock().unwrap_or_else(|poison| poison.into_inner());
            match *slot {
                Some((nonce, _)) => Ok(nonce.to_vec()),
                None => Err(ClientError::Client(
                    "jack client: no nonce staged for this request".to_owned(),
                )),
            }
        })
    };
    let signing = SigningTransport {
        transport: Arc::clone(&exchange),
        aud: flags.aud.clone(),
        signer: Arc::new(signer.clone()),
        server_key,
        now,
        nonce,
        // 0 selects the SDK's default 30 s freshness window.
        window_seconds: 0,
    };

    let url = format!("{}{TARGET}", flags.url.trim_end_matches('/'));
    // Contract 4.2: without a request the era is the one `--era` names, with
    // `auto` reading as modern like the fakes do.
    let initial_era = match flags.era {
        EraArg::Legacy => Era::Legacy,
        EraArg::Modern | EraArg::Auto => Era::Modern,
    };
    let ctx = Ctx {
        scenario: flags.scenario,
        json_id: flags.json_id,
        probe_version: flags.probe_version,
        era: flags.era,
        url,
        signing,
        signer,
        staged,
        exchange,
        clock_file: flags.clock_file,
        nonce_index: Cell::new(0),
        last_era: Cell::new(initial_era),
        steps: RefCell::new(Vec::new()),
    };

    let halt = scenarios::run(&ctx);
    if let Err(Halt::Fatal(message)) = &halt {
        fail(message);
    }
    let report = build_report(
        &ctx.scenario,
        ctx.last_era.get().as_str(),
        &halt,
        ctx.finish_steps(),
    );
    println!(
        "{}",
        serde_json::to_string(&report).expect("the report shape serializes")
    );
    std::process::exit(0)
}
