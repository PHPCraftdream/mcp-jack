//! Signed-stream interop server. Request verification and every response/frame
//! signature are supplied by the SDK's `StreamLayer`.
use super::wrapper::{wait_for_release, Controls, HandlerTask, SharedService, StreamBody};
#[cfg(target_os = "linux")]
use super::{durable, rotation};
use bytes::Bytes;
use http_body_util::{BodyExt, Channel};
use mcp_jack::server::{
    http::{StreamCancellation, StreamHeartbeat, StreamLayer, StreamLayerBuilder},
    modern::Profile,
    native::{Native, NativeOptions},
    nonce::NonceStore,
    state_file::FileState,
    verify::{Verifier, VerifierBuilder},
};
use std::{
    convert::Infallible,
    io::{BufRead, Write},
    pin::Pin,
    sync::{atomic::Ordering, Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tower_layer::Layer as _;
use tower_service::Service;

#[derive(Clone)]
pub(super) struct Args {
    pub(super) scenario: String,
    pub(super) producer: String,
    pub(super) matrix: String,
    pub(super) request_log: Option<String>,
    pub(super) clock_file: String,
    pub(super) duration_ms: u64,
    pub(super) frame_max_bytes: u64,
    pub(super) lifecycle: bool,
    successor_activation: Option<u64>,
}

#[derive(Clone)]
struct Handler {
    args: Args,
    controls: Arc<Controls>,
    tasks: Arc<Mutex<Vec<HandlerTask>>>,
}

/// The driver launches with cwd = repo root; `producer` selects the handler
/// producer exactly as the active rows do, id as fallback.
fn lookup_producer(scenario: &str) -> String {
    let Ok(text) = std::fs::read_to_string("interop/stream-scenarios.json") else {
        return scenario.to_owned();
    };
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&text) else {
        return scenario.to_owned();
    };
    for matrix in ["stream", "staged", "rotation-stream", "durable-stream"] {
        if let Some(rows) = doc
            .pointer(&format!("/matrices/{matrix}"))
            .and_then(|v| v.as_array())
        {
            for row in rows {
                if row.get("id").and_then(|v| v.as_str()) == Some(scenario) {
                    return row
                        .get("producer")
                        .and_then(|v| v.as_str())
                        .unwrap_or(scenario)
                        .to_owned();
                }
            }
        }
    }
    scenario.to_owned()
}

pub(super) fn parse_jack_auth(
    headers: &http::HeaderMap,
) -> Option<mcp_jack::auth_header::RequestAuth> {
    let auth_values: Vec<_> = headers
        .get_all("Jack-Auth")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    mcp_jack::auth_header::parse_request_auth(&auth_values).ok()
}

pub(super) fn request_row(
    method: &http::Method,
    target: &str,
    headers: &http::HeaderMap,
    body: &[u8],
    verified: bool,
) -> serde_json::Value {
    let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let params = parsed
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let request_method = parsed.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let auth = parse_jack_auth(headers);
    let request_headers: Vec<serde_json::Value> = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| serde_json::json!([name.as_str(), value]))
        })
        .collect();
    let mirror_headers: Vec<_> = request_headers
        .iter()
        .filter(|row| {
            row[0]
                .as_str()
                .is_some_and(|name| name.to_ascii_lowercase().starts_with("mcp-"))
        })
        .cloned()
        .collect();
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let protocol_version = params
        .pointer("/_meta/io.modelcontextprotocol~1protocolVersion")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "event":"request", "request_verified":verified, "request_sig":auth.as_ref().map(|v| v.sig.clone()),
        "method":method.as_str(), "target":target, "body":String::from_utf8_lossy(body),
        "request_body_b64u":mcp_jack::encoding::encode_b64url(body), "nonce":auth.as_ref().map(|v| v.nonce.clone()),
        "request_mcp_method":request_method, "request_params":params,
        "protocol_version":protocol_version, "mirror_protocol_version":header("MCP-Protocol-Version"),
        "mirror_method":header("Mcp-Method"), "mirror_name":header("Mcp-Name"),
        "mirror_headers":mirror_headers, "request_method":method.as_str(),
        "request_target":target, "request_headers":request_headers,
        "nonce_committed_before_first_byte":false
    })
}

fn append_log(args: &Args, mut row: serde_json::Value) -> Result<(), String> {
    if let Some(path) = &args.request_log {
        row["scenario"] = args.scenario.clone().into();
        row["matrix"] = args.matrix.clone().into();
        let mut bytes = serde_json::to_vec(&row).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn log_error(context: &str, error: String) {
    eprintln!("stream server: {context} log: {error}");
}

pub(super) fn append_log_visible(args: &Args, row: serde_json::Value, context: &str) {
    let _ = append_log(args, row).map_err(|error| log_error(context, error));
}

fn read_clock(path: &str) -> Result<i64, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    value
        .as_i64()
        .or_else(|| value.get("clock").and_then(serde_json::Value::as_i64))
        .or_else(|| std::str::from_utf8(&bytes).ok()?.trim().parse().ok())
        .ok_or_else(|| "invalid clock value".to_owned())
}

fn event(value: &serde_json::Value) -> Bytes {
    Bytes::from(format!("data: {value}\n\n"))
}

async fn send(
    sender: &mut http_body_util::channel::Sender<Bytes, Infallible>,
    value: serde_json::Value,
    controls: &Controls,
) -> bool {
    if controls.shutdown_requested.load(Ordering::Acquire) {
        return false;
    }
    let shutdown = controls.shutdown.notified();
    tokio::pin!(shutdown);
    shutdown.as_mut().enable();
    if controls.shutdown_requested.load(Ordering::Acquire) {
        return false;
    }
    tokio::select! {
        result = sender.send_data(event(&value)) => result.is_ok(),
        _ = &mut shutdown => false,
    }
}

impl Handler {
    async fn produce(
        &self,
        request: http::Request<http_body_util::Full<Bytes>>,
        mut sender: http_body_util::channel::Sender<Bytes, Infallible>,
    ) {
        let (parts, body) = request.into_parts();
        let body_shutdown = self.controls.shutdown.notified();
        tokio::pin!(body_shutdown);
        body_shutdown.as_mut().enable();
        if self.controls.shutdown_requested.load(Ordering::Acquire) {
            return;
        }
        let bytes = tokio::select! {
            result = body.collect() => match result {
                Ok(body) => body.to_bytes(),
                Err(_) => Bytes::new(),
            },
            _ = &mut body_shutdown => return,
        };
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        let params = parsed
            .get("params")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let _method = parsed.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let auth = parse_jack_auth(&parts.headers);
        let verified = parts
            .extensions
            .get::<mcp_jack::server::identity::VerifiedIdentity>()
            .is_some();
        let target = parts
            .uri
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or("/");
        let request_sig = auth.as_ref().map(|value| value.sig.clone());
        let nonce = auth.as_ref().map(|value| value.nonce.clone());
        if !self.args.lifecycle {
            append_log_visible(
                &self.args,
                request_row(&parts.method, target, &parts.headers, &bytes, verified),
                "request",
            );
            if verified {
                append_log_visible(
                    &self.args,
                    serde_json::json!({"event":"nonce_committed", "nonce":nonce,
                    "request_sig":request_sig, "nonce_committed_before_first_byte":true}),
                    "nonce_committed",
                );
            }
        }
        // JackLayer has already atomically admitted a verified nonce before it
        // invokes the application service. Do not describe missing auth as replay.
        let scenario = self.args.scenario.as_str();
        let producer = self.args.producer.as_str();
        let heartbeat = parts.extensions.get::<StreamHeartbeat>().copied();
        let cancellation = parts.extensions.get::<StreamCancellation>().cloned();
        if producer == "oversize" {
            let pad = "x".repeat(self.args.frame_max_bytes.max(1) as usize + 16);
            let oversized = serde_json::json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1,"pad":pad}});
            let data_bytes = serde_json::to_vec(&oversized).map(|v| v.len()).unwrap_or(0);
            append_log_visible(
                &self.args,
                serde_json::json!({"event":"frame_suppressed","data_bytes":data_bytes,"frame_max_bytes":self.args.frame_max_bytes}),
                "frame_suppressed",
            );
            let _ = send(&mut sender, oversized, &self.controls).await;
            return;
        }
        let id = parsed.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let result = serde_json::json!({"jsonrpc":"2.0","id":id,"result":{}});
        let hold_requested = match scenario {
            "durable-live-replay" => true,
            "rotation-cutoff-reopen" => self.args.successor_activation.is_some_and(|activation| {
                read_clock(&self.args.clock_file).unwrap_or(i64::MAX) < activation as i64
            }),
            _ => false,
        };
        if scenario == "durable-live-replay" || scenario == "durable-restart-replay" {
            let first = serde_json::json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1,"message":"stream:first"}});
            if !send(&mut sender, first, &self.controls).await {
                return;
            }
            if scenario == "durable-live-replay" {
                super::wrapper::register_held(&self.controls, &request_sig);
                if !wait_for_release(&self.controls).await {
                    return;
                }
                let _ = send(&mut sender, result, &self.controls).await;
                self.controls.held_done.notify_one();
                return;
            }
            let _ = send(&mut sender, result, &self.controls).await;
            return;
        }
        let mut messages = Vec::new();
        // The staged `idle` row names producer `progress-final` but its behaviour is
        // a silent hold (fake-harness parity); overridden here explicitly.
        let holds_silent = scenario == "idle";
        match producer {
            "progress-final" | "relay-drop" | "relay-edit-data" | "relay-truncate" | "relay-reorder" | "relay-splice" | "relay-replay" if !holds_silent => {
                messages.push(serde_json::json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}));
                messages.push(result.clone());
            }
            "subscriptions-listen" => {
                messages.push(serde_json::json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"subscriptionId":id}}));
                let opted_in = params.get("notifications").and_then(|v| v.as_array()).is_some_and(|values|
                    values.iter().any(|v| v == "notifications/events/list_changed"));
                if opted_in { messages.push(serde_json::json!({"jsonrpc":"2.0","method":"notifications/events/list_changed","params":{}})); }
                messages.push(result.clone());
            }
            "events-stream" => {
                let grant = heartbeat.map(|v| v.granted_ms).unwrap_or(0);
                append_log_visible(&self.args, serde_json::json!({"event":"heartbeat_granted","heartbeat_granted_ms":grant}), "heartbeat_granted");
                messages.extend([
                    serde_json::json!({"jsonrpc":"2.0","method":"notifications/events/active","params":{"state":"active"}}),
                    serde_json::json!({"jsonrpc":"2.0","method":"notifications/events/event","params":{"event":"event"}}),
                    serde_json::json!({"jsonrpc":"2.0","method":"notifications/events/heartbeat","params":{"event":"heartbeat","heartbeatMs":grant}}),
                    serde_json::json!({"jsonrpc":"2.0","method":"notifications/events/terminated","params":{"state":"terminated"}}),
                ]);
                append_log_visible(&self.args, serde_json::json!({"event":"heartbeat_frame","heartbeat_granted_ms":grant}), "heartbeat_frame");
            }
            "cancel" | "max-duration" | "concurrency-limit" => messages.push(serde_json::json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}})),
            _ if !holds_silent => { messages.push(result.clone()); }
            _ => {}
        }
        for message in messages {
            if !send(&mut sender, message, &self.controls).await {
                return;
            }
        }
        if holds_silent {
            loop {
                if self.controls.shutdown_requested.load(Ordering::Acquire) {
                    return;
                }
                let shutdown = self.controls.shutdown.notified();
                tokio::pin!(shutdown);
                shutdown.as_mut().enable();
                if self.controls.shutdown_requested.load(Ordering::Acquire) {
                    return;
                }
                tokio::select! { _ = &mut shutdown => return, _ = tokio::time::sleep(Duration::from_millis(50)) => {} }
            }
        }
        if hold_requested {
            super::wrapper::register_held(&self.controls, &request_sig);
            if !wait_for_release(&self.controls).await {
                return;
            }
            self.controls.held_done.notify_one();
        }
        if scenario == "concurrency-limit" {
            super::wrapper::register_held(&self.controls, &request_sig);
            loop {
                if self.controls.release_requested.load(Ordering::Acquire) {
                    break;
                }
                if self.controls.shutdown_requested.load(Ordering::Acquire) {
                    return;
                }
                let release = self.controls.release.notified();
                tokio::pin!(release);
                release.as_mut().enable();
                let shutdown = self.controls.shutdown.notified();
                tokio::pin!(shutdown);
                shutdown.as_mut().enable();
                if self.controls.shutdown_requested.load(Ordering::Acquire) {
                    return;
                }
                tokio::select! { _ = &mut release => break, _ = &mut shutdown => return, _ = tokio::time::sleep(Duration::from_millis(5)) => {} }
            }
            let _ = send(&mut sender, result, &self.controls).await;
            return;
        }
        if scenario == "cancel" {
            if let Some(cancellation) = cancellation {
                while !cancellation.is_cancelled()
                    && !self.controls.shutdown_requested.load(Ordering::Acquire)
                {
                    let shutdown = self.controls.shutdown.notified();
                    tokio::pin!(shutdown);
                    shutdown.as_mut().enable();
                    if self.controls.shutdown_requested.load(Ordering::Acquire) {
                        break;
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(5)) => {},
                        _ = &mut shutdown => break,
                    }
                }
                if cancellation.is_cancelled() {
                    append_log_visible(
                        &self.args,
                        serde_json::json!({"event":"handler_cancelled", "request_sig":request_sig}),
                        "handler_cancelled",
                    );
                }
            }
            return;
        }
        if scenario == "max-duration" {
            if let Some(cancellation) = cancellation {
                // StreamLayer measures this deadline with Instant from pump startup;
                // changing the injected clock file does not alter its elapsed time.
                let deadline = tokio::time::Instant::now()
                    + Duration::from_millis(self.args.duration_ms)
                    + Duration::from_secs(5);
                loop {
                    let clock_changed = self
                        .controls
                        .latest_clock
                        .lock()
                        .ok()
                        .and_then(|value| value.clone())
                        .is_some_and(|command| {
                            command.get("action").and_then(|v| v.as_str()) == Some("clock_advanced")
                        });
                    if cancellation.is_cancelled() && clock_changed {
                        append_log_visible(
                            &self.args,
                            serde_json::json!({"event":"duration_elapsed"}),
                            "duration_elapsed",
                        );
                        break;
                    }
                    if self.controls.shutdown_requested.load(Ordering::Acquire)
                        || tokio::time::Instant::now() >= deadline
                    {
                        break;
                    }
                    let clock = self.controls.clock.notified();
                    tokio::pin!(clock);
                    clock.as_mut().enable();
                    let shutdown = self.controls.shutdown.notified();
                    tokio::pin!(shutdown);
                    shutdown.as_mut().enable();
                    if self.controls.shutdown_requested.load(Ordering::Acquire) {
                        break;
                    }
                    tokio::select! {
                        _ = &mut clock => {},
                        _ = &mut shutdown => break,
                        _ = tokio::time::sleep(Duration::from_millis(5)) => {},
                    }
                }
            }
        }
    }
}

impl Service<http::Request<http_body_util::Full<Bytes>>> for Handler {
    type Response = http::Response<StreamBody>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<http_body_util::Full<Bytes>>) -> Self::Future {
        let handler = self.clone();
        let task_registry = Arc::clone(&self.tasks);
        Box::pin(async move {
            let (sender, body) = Channel::<Bytes, Infallible>::new(1);
            let task = tokio::spawn(async move {
                handler.produce(request, sender).await;
            });
            if let Ok(mut tasks) = task_registry.lock() {
                // Concurrent-stream admission belongs to the SDK StreamRegistry.
                tasks.retain(|task| !task.is_finished());
                tasks.push(task);
            }
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header(
                    http::header::CONTENT_TYPE,
                    "text/event-stream; charset=utf-8",
                )
                .body(body)
                .expect("static response headers are valid");
            Ok(response)
        })
    }
}

fn arg(args: &[String], name: &str) -> Option<String> {
    for (index, value) in args.iter().enumerate() {
        if value == name {
            return args.get(index + 1).cloned();
        }
        if let Some(value) = value.strip_prefix(&format!("{name}=")) {
            return Some(value.to_owned());
        }
    }
    None
}

fn required(args: &[String], name: &str) -> String {
    arg(args, name)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            eprintln!("stream server: missing {name}");
            std::process::exit(1)
        })
}

fn number(args: &[String], name: &str, default: u64) -> u64 {
    arg(args, name)
        .map(|value| {
            value.parse().unwrap_or_else(|_| {
                eprintln!("stream server: invalid {name}");
                std::process::exit(1)
            })
        })
        .unwrap_or(default)
}

fn build_verifier(
    audience: &str,
    state: FileState,
    clock_file: &str,
    window_seconds: i64,
) -> Verifier {
    VerifierBuilder::new(audience.to_owned(), Arc::new(state))
        .nonces(Arc::new(NonceStore::new()))
        .audit(None)
        .native_tools(Some(Arc::new(Native::new(NativeOptions::default()))))
        .window_seconds(window_seconds)
        .now({
            let clock_path = clock_file.to_owned();
            Arc::new(move || read_clock(&clock_path).unwrap_or(0))
        })
        .try_build()
        .unwrap_or_else(|error| {
            eprintln!("stream server: verifier: {error}");
            std::process::exit(1)
        })
}

fn build_stream_layer(
    verifier: Verifier,
    key: mcp_jack::user_key::ServerSigningKey,
    options: mcp_jack::server::stream::StreamOptions,
    profile: Profile,
) -> StreamLayer {
    StreamLayerBuilder::new(Arc::new(verifier), key)
        .max_body_bytes(0)
        .max_response_bytes(0)
        .streams(options)
        .profile(profile)
        .build()
}

pub fn run() -> ! {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let profile = match required(&arguments, "--profile").as_str() {
        "modern" => Profile::Modern,
        other => {
            eprintln!("stream server: unsupported profile {other}");
            std::process::exit(1)
        }
    };
    let matrix = required(&arguments, "--matrix");
    let scenario = required(&arguments, "--scenario");
    let audience = required(&arguments, "--aud");
    let state_path = required(&arguments, "--state");
    let clock_file = required(&arguments, "--clock-file");
    let successor_activation = arg(&arguments, "--successor-activation").map(|value| {
        value.parse().unwrap_or_else(|_| {
            eprintln!("stream server: invalid --successor-activation");
            std::process::exit(1)
        })
    });
    let durable_dir = arg(&arguments, "--durable-dir");
    let durable_init = arguments.iter().any(|value| value == "--durable-init");
    if durable_init && durable_dir.is_none() {
        eprintln!("stream server: --durable-init requires --durable-dir");
        std::process::exit(1)
    }
    if let Err(error) = read_clock(&clock_file) {
        eprintln!("stream server: clock: {error}");
        std::process::exit(1);
    }
    let seed = match crate::interop::hex_decode_32(&required(&arguments, "--server-seed-hex")) {
        Ok(seed) => seed,
        Err(_) => {
            eprintln!("stream server: invalid server seed");
            std::process::exit(1)
        }
    };
    #[cfg(target_os = "linux")]
    durable::initialize_if_requested(durable_dir.as_deref(), durable_init, &audience, &clock_file);
    #[cfg(not(target_os = "linux"))]
    if durable_dir.is_some() || durable_init {
        eprintln!("durable-stream requires linux (durable nonce stores)");
        std::process::exit(1)
    }
    #[cfg(target_os = "linux")]
    let durable_setup = durable::open_optional(durable_dir.as_deref(), &audience, &clock_file);
    #[cfg(target_os = "linux")]
    let rotation = rotation::setup(&arguments, &seed, &clock_file);
    #[cfg(not(target_os = "linux"))]
    {
        if arg(&arguments, "--rotation-store").is_some()
            || arg(&arguments, "--ring-seed").is_some()
            || arg(&arguments, "--successor-activation").is_some()
        {
            eprintln!("stream server: rotation-stream requires linux (SDK rotation stores)");
            std::process::exit(1)
        }
    }
    #[cfg(not(target_os = "linux"))]
    #[allow(unused_variables)]
    let rotation: Option<()> = None;
    let state = FileState::open(state_path).unwrap_or_else(|error| {
        eprintln!("stream server: state: {error}");
        std::process::exit(1)
    });
    #[cfg(target_os = "linux")]
    let verifier = Arc::new(if let Some((store, provider, _)) = &rotation {
        let clock_path = clock_file.clone();
        VerifierBuilder::new(audience.clone(), Arc::new(state))
            .nonces(Arc::new(NonceStore::new()))
            .audit(None)
            .native_tools(Some(Arc::new(Native::new(NativeOptions::default()))))
            .window_seconds(0)
            .now(Arc::new(move || read_clock(&clock_path).unwrap_or(0)))
            .server_keys(Arc::new(rotation::server_key_tool(
                Arc::clone(store),
                Arc::clone(provider),
            )))
            .try_build()
            .unwrap_or_else(|error| {
                eprintln!("stream server: verifier: {error}");
                std::process::exit(1)
            })
    } else if let Some(setup) = &durable_setup {
        let clock_path = clock_file.clone();
        VerifierBuilder::new(audience.clone(), Arc::new(state))
            .nonces(Arc::new(NonceStore::new()))
            .audit(None)
            .native_tools(Some(Arc::new(Native::new(NativeOptions::default()))))
            .window_seconds(setup.window)
            .now(Arc::new(move || read_clock(&clock_path).unwrap_or(0)))
            .durable_nonces(Arc::clone(&setup.store))
            .try_build()
            .unwrap_or_else(|error| {
                eprintln!("stream server: verifier: {error}");
                std::process::exit(1)
            })
    } else {
        build_verifier(&audience, state, &clock_file, 0)
    });
    #[cfg(not(target_os = "linux"))]
    let verifier = Arc::new(build_verifier(&audience, state, &clock_file, 0));
    let _idle_timeout_ms = number(&arguments, "--idle-timeout-ms", 90_000);
    // The SDK's StreamOptions does not currently consume a server idle timeout.
    let options = mcp_jack::server::stream::StreamOptions {
        frame_max_bytes: number(&arguments, "--frame-max-bytes", 1_048_576) as usize,
        max_concurrent_streams: number(&arguments, "--max-concurrent-streams", 4) as usize,
        max_stream_duration_ms: number(&arguments, "--max-stream-duration-ms", 3_600_000),
        heartbeat_ms: arg(&arguments, "--heartbeat-ms").and_then(|value| value.parse().ok()),
    };
    let lifecycle = matrix == "rotation-stream" || matrix == "durable-stream";
    let args = Args {
        producer: lookup_producer(&scenario),
        scenario,
        matrix,
        request_log: Some(required(&arguments, "--request-log")),
        clock_file,
        duration_ms: number(&arguments, "--max-stream-duration-ms", 3_600_000),
        frame_max_bytes: number(&arguments, "--frame-max-bytes", 1_048_576),
        lifecycle,
        successor_activation,
    };
    let controls = Arc::new(Controls::default());
    let tasks = Arc::new(Mutex::new(Vec::new()));
    let handler = Handler {
        args: args.clone(),
        controls: controls.clone(),
        tasks: tasks.clone(),
    };
    let key = mcp_jack::user_key::ServerSigningKey::from_bytes(&seed);
    let public_key = mcp_jack::encoding::encode_b64url(key.verifying_key().as_bytes());
    let server_kid = mcp_jack::encoding::key_id(key.verifying_key().as_bytes());
    #[cfg(target_os = "linux")]
    let layer = Arc::new(if let Some((_, provider, _)) = &rotation {
        StreamLayerBuilder::rotating(verifier.clone(), provider.clone())
            .max_body_bytes(0)
            .max_response_bytes(0)
            .streams(options)
            .profile(profile)
            .build()
    } else {
        build_stream_layer(
            Arc::try_unwrap(verifier).unwrap_or_else(|_| unreachable!()),
            key,
            options,
            profile,
        )
    });
    #[cfg(not(target_os = "linux"))]
    let layer = Arc::new(build_stream_layer(
        Arc::try_unwrap(verifier).unwrap_or_else(|_| unreachable!()),
        key,
        options,
        profile,
    ));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| {
            eprintln!("stream server: runtime: {error}");
            std::process::exit(1)
        });
    let result = runtime.block_on(async move {
        let port: u16 = required(&arguments, "--port").parse()
            .map_err(|error| format!("invalid --port: {error}"))?;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        println!("{}", serde_json::json!({"ready":true,"port":port,"server_public_key":public_key,"server_kid":server_kid}));
        let _ = std::io::stdout().flush();

        let (control_tx, mut control_rx) = tokio::sync::mpsc::channel::<String>(8);
        // The reader exits on stdin EOF; the owned join below waits for that documented shutdown path.
        let stdin_task = std::thread::spawn(move || {
            for line in std::io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                if control_tx.blocking_send(line).is_err() { break; }
            }
        });
        #[cfg(target_os = "linux")]
        let rotation_provider = rotation.as_ref().map(|(_, provider, _)| Arc::clone(provider));
        #[cfg(target_os = "linux")]
        #[allow(unused_variables)]
        let rotation_activation = rotation.as_ref().map(|(_, _, activation)| *activation);
        let mut connections = Vec::new();
        loop {
            tokio::select! {
                command = control_rx.recv() => match command {
                    Some(line) => {
                        let value: serde_json::Value = serde_json::from_str(&line).unwrap_or(serde_json::Value::Null);
                        match value.get("op").and_then(|v| v.as_str()) {
                            #[cfg(target_os = "linux")]
                            Some("announce") => {
                                let reference = value.get("reference").and_then(|v| v.as_str()).unwrap_or("");
                                let kid = value.get("kid").and_then(|v| v.as_str()).unwrap_or("");
                                let Some(provider) = rotation_provider.as_ref() else { continue; };
                                if !rotation::announce(provider, reference, kid, |row| append_log(&args, row)) { continue; }
                            }
                            _ => match value.get("action").and_then(|v| v.as_str()) {
                            Some("clock_advanced") => {
                                let requested = value.get("clock").and_then(serde_json::Value::as_i64);
                                match (read_clock(&args.clock_file), requested) {
                                    (Ok(file_clock), Some(command_clock)) if file_clock == command_clock => {
                                        let logged = append_log(&args, serde_json::json!({"event":"clock_changed","clock":file_clock,
                                            "start":value.get("start"),"duration_ms":value.get("duration_ms")}));
                                        if let Err(error) = logged {
                                            eprintln!("stream server: clock log: {error}");
                                            continue;
                                        }
                                        let mut ack = match serde_json::to_vec(&serde_json::json!({"control":"clock_advanced","clock":file_clock})) {
                                            Ok(ack) => ack,
                                            Err(error) => {
                                                eprintln!("stream server: clock acknowledgement: {error}");
                                                continue;
                                            }
                                        };
                                        ack.push(b'\n');
                                        if let Err(error) = std::io::stdout().write_all(&ack).and_then(|_| std::io::stdout().flush()) {
                                            eprintln!("stream server: clock acknowledgement: {error}");
                                            continue;
                                        }
                                        if let Ok(mut latest) = controls.latest_clock.lock() { *latest = Some(value.clone()); }
                                        controls.clock.notify_waiters();
                                    }
                                    (Ok(file_clock), Some(command_clock)) => eprintln!("stream server: clock control mismatch (file {file_clock}, command {command_clock})"),
                                    (Err(error), _) => eprintln!("stream server: clock control: {error}"),
                                    (_, None) => eprintln!("stream server: clock control missing integer clock"),
                                }
                            }
                            Some("release") => {
                                let lifecycle_hold = args.matrix == "rotation-stream"
                                    || args.matrix == "durable-stream";
                                // Arm the completion waiter before releasing so a fast producer cannot signal first.
                                let done = controls.held_done.notified();
                                tokio::pin!(done);
                                done.as_mut().enable();
                                controls.release_requested.store(true, Ordering::Release);
                                controls.release.notify_waiters();
                                if lifecycle_hold
                                    && tokio::time::timeout(Duration::from_secs(2), done).await.is_err()
                                {
                                    eprintln!("stream server: held stream did not complete; no release acknowledgement");
                                    continue;
                                }
                                let lookup_sid = || {
                                    let key = controls.held.lock().ok().and_then(|held| held.clone());
                                    key.and_then(|sig| controls.sid_by_request_sig.lock().ok().and_then(|m| m.get(&sig).cloned()))
                                };
                                let mut sid = lookup_sid();
                                if sid.is_none() {
                                    for _ in 0..50 {
                                        tokio::time::sleep(Duration::from_millis(10)).await;
                                        sid = lookup_sid();
                                        if sid.is_some() { break; }
                                    }
                                }
                                let ack_value = match &sid {
                                    Some(sid) => serde_json::json!({"control":"released","sid":sid}),
                                    None => {
                                        if lifecycle_hold {
                                            eprintln!("stream server: held stream sid unknown; no release acknowledgement");
                                            continue;
                                        }
                                        serde_json::json!({"control":"released"})
                                    }
                                };
                                let mut ack = match serde_json::to_vec(&ack_value) {
                                    Ok(ack) => ack,
                                    Err(error) => { eprintln!("stream server: release acknowledgement: {error}"); continue; }
                                };
                                ack.push(b'\n');
                                if let Err(error) = std::io::stdout().write_all(&ack).and_then(|_| std::io::stdout().flush()) {
                                    eprintln!("stream server: release acknowledgement: {error}");
                                }
                            }
                            _ => continue,
                        }
                        }
                        let _ = std::io::stdout().flush();
                    }
                    None => {
                        controls.shutdown_requested.store(true, Ordering::Release);
                        controls.shutdown.notify_waiters();
                        break;
                    },
                },
                accepted = listener.accept() => {
                    let (socket, _) = accepted.map_err(|e| e.to_string())?;
                    let layer = Arc::clone(&layer);
                    let handler = handler.clone();
                    let controls = controls.clone();
                    let args = args.clone();
                    connections.push(tokio::spawn(async move {
                        let service = hyper_util::service::TowerToHyperService::new(
                            SharedService::new(layer.layer(handler), controls.clone(), args.clone()),
                        );
                        // Half-close: the raw replay client shuts its write side right after the request.
                        let _ = hyper::server::conn::http1::Builder::new()
                            .half_close(true)
                            .serve_connection(hyper_util::rt::TokioIo::new(socket), service).await;
                    }));
                }
            }
        }
        drop(listener);
        controls.shutdown_requested.store(true, Ordering::Release);
        controls.shutdown.notify_waiters();
        let grace = Duration::from_secs(2);
        // A JoinHandle must not be awaited again once it completed: after the grace period the
        // leftovers are only aborted, never joined a second time.
        let joined = tokio::time::timeout(grace, async {
            for connection in &mut connections {
                let _ = connection.await;
            }
        })
        .await;
        if joined.is_err() {
            for connection in &connections { connection.abort(); }
        }
        // Handlers register producers until their connection ended: snapshot after the join.
        let mut producers = {
            let mut tasks = tasks.lock().map_err(|_| "task registry poisoned".to_owned())?;
            std::mem::take(&mut *tasks)
        };
        let joined = tokio::time::timeout(grace, async {
            for producer in &mut producers { let _ = producer.await; }
        })
        .await;
        if joined.is_err() {
            for producer in &producers { producer.abort(); }
        }
        let _ = tokio::time::timeout(grace, async move {
            let _ = tokio::task::spawn_blocking(move || stdin_task.join()).await;
        }).await;
        Ok::<(), String>(())
    });
    if let Err(error) = result {
        eprintln!("stream server: {error}");
        std::process::exit(1);
    }
    #[cfg(target_os = "linux")]
    durable::close_optional(durable_setup.as_ref());
    std::process::exit(0)
}
