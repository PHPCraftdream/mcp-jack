//! Signed-stream interop server. Request verification and every response/frame
//! signature are supplied by the SDK's `StreamLayer`.
use std::{
    convert::Infallible,
    future::Future,
    io::{BufRead, Write},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Channel};
use mcp_jack::server::{
    http::{StreamCancellation, StreamConfig, StreamHeartbeat, StreamLayer},
    modern::Profile,
    native::{Native, NativeOptions},
    nonce::NonceStore,
    state_file::FileState,
    verify::{Clock, Config, Verifier},
};
use tower_layer::Layer as _;
use tower_service::Service;

#[derive(Clone)]
struct Args {
    scenario: String,
    matrix: String,
    request_log: Option<String>,
    clock_file: String,
    duration_ms: u64,
}

#[derive(Default)]
struct Controls {
    clock: tokio::sync::Notify,
    shutdown: tokio::sync::Notify,
    shutdown_requested: AtomicBool,
    latest_clock: Mutex<Option<serde_json::Value>>,
}

type StreamBody = Channel<Bytes, Infallible>;
type HandlerTask = tokio::task::JoinHandle<()>;

/// Hyper requires its service adapter to be cloneable. The SDK's stream
/// service is intentionally not Clone, so clones share one Tower service.
struct SharedService<S>(Arc<Mutex<S>>);

impl<S> Clone for SharedService<S> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<S> SharedService<S> {
    fn new(service: S) -> Self {
        Self(Arc::new(Mutex::new(service)))
    }
}

impl<S, B> Service<http::Request<B>> for SharedService<S>
where
    S: Service<http::Request<B>> + Send + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let future = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .call(request);
        Box::pin(future)
    }
}

#[derive(Clone)]
struct Handler {
    args: Args,
    controls: Arc<Controls>,
    tasks: Arc<Mutex<Vec<HandlerTask>>>,
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

fn append_log_visible(args: &Args, row: serde_json::Value, context: &str) {
    if let Err(error) = append_log(args, row) {
        log_error(context, error);
    }
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
        let method = parsed.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let auth_values: Vec<_> = parts
            .headers
            .get_all("Jack-Auth")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        let auth = mcp_jack::auth_header::parse_request_auth(&auth_values).ok();
        let verified = parts
            .extensions
            .get::<mcp_jack::server::identity::VerifiedIdentity>()
            .is_some();
        let request_headers: Vec<serde_json::Value> = parts
            .headers
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
        let protocol_version = params
            .pointer("/_meta/io.modelcontextprotocol~1protocolVersion")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let header = |name: &str| {
            parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let target = parts
            .uri
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or("/");
        let request_sig = auth.as_ref().map(|value| value.sig.clone());
        let nonce = auth.as_ref().map(|value| value.nonce.clone());
        append_log_visible(
            &self.args,
            serde_json::json!({
                "event":"request", "request_verified":verified, "request_sig":request_sig,
                "method":parts.method.as_str(), "target":target, "body":String::from_utf8_lossy(&bytes),
                "request_body_b64u":mcp_jack::encoding::encode_b64url(&bytes), "nonce":nonce,
                "request_mcp_method":method, "request_params":params,
                "protocol_version":protocol_version, "mirror_protocol_version":header("MCP-Protocol-Version"),
                "mirror_method":header("Mcp-Method"), "mirror_name":header("Mcp-Name"),
                "mirror_headers":mirror_headers, "request_method":parts.method.as_str(),
                "request_target":target, "request_headers":request_headers,
                "nonce_committed_before_first_byte":false
            }),
            "request",
        );

        // JackLayer has already atomically admitted a verified nonce before it
        // invokes the application service. Do not describe missing auth as replay.
        if verified {
            append_log_visible(
                &self.args,
                serde_json::json!({"event":"nonce_committed", "nonce":nonce,
                "request_sig":request_sig, "nonce_committed_before_first_byte":true}),
                "nonce_committed",
            );
        }

        let heartbeat = parts.extensions.get::<StreamHeartbeat>().copied();
        let cancellation = parts.extensions.get::<StreamCancellation>().cloned();
        if let Some(grant) = heartbeat {
            append_log_visible(
                &self.args,
                serde_json::json!({"event":"stream_open", "heartbeat_granted_ms":grant.granted_ms,
                "nonce_committed_before_first_byte":verified, "request_sig":request_sig, "nonce":nonce}),
                "stream_open",
            );
        }
        let id = parsed.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let scenario = self.args.scenario.as_str();
        let result = serde_json::json!({"jsonrpc":"2.0","id":id,"result":{}});
        let mut messages = Vec::new();
        match scenario {
            "progress-final" | "relay-drop" | "relay-edit-data" | "relay-truncate" => {
                messages.push(serde_json::json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}));
                messages.push(result.clone());
            }
            "list-changed" => {
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
            "cancel" | "max-duration" => messages.push(serde_json::json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}})),
            _ => { messages.push(result.clone()); }
        }
        for message in messages {
            if !send(&mut sender, message, &self.controls).await {
                return;
            }
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
            // StreamLayer measures this deadline with Instant from pump startup;
            // changing the injected clock file does not alter its elapsed time.
            if let Some(cancellation) = cancellation {
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
                // Keep only active producers; the semaphore bounds those by max_streams.
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
    let state = FileState::open(state_path).unwrap_or_else(|error| {
        eprintln!("stream server: state: {error}");
        std::process::exit(1)
    });
    let clock_path = clock_file.clone();
    let now: Clock = Arc::new(move || read_clock(&clock_path).unwrap_or(0));
    let verifier = Arc::new(
        Verifier::new(Config {
            aud: audience,
            state: Arc::new(state),
            nonces: Arc::new(NonceStore::new()),
            audit: None,
            native: Some(Arc::new(Native::new(NativeOptions::default()))),
            window_seconds: 0,
            now,
        })
        .unwrap_or_else(|error| {
            eprintln!("stream server: verifier: {error}");
            std::process::exit(1)
        }),
    );

    let _idle_timeout_ms = number(&arguments, "--idle-timeout-ms", 90_000);
    // The SDK's StreamOptions does not currently consume a server idle timeout.
    let options = mcp_jack::server::stream::StreamOptions {
        frame_max_bytes: number(&arguments, "--frame-max-bytes", 1_048_576) as usize,
        max_concurrent_streams: number(&arguments, "--max-concurrent-streams", 4) as usize,
        max_stream_duration_ms: number(&arguments, "--max-stream-duration-ms", 3_600_000),
        heartbeat_ms: arg(&arguments, "--heartbeat-ms").and_then(|value| value.parse().ok()),
    };
    let max_streams = number(&arguments, "--max-concurrent-streams", 4).max(1) as usize;
    let args = Args {
        scenario,
        matrix,
        request_log: Some(required(&arguments, "--request-log")),
        clock_file,
        duration_ms: number(&arguments, "--max-stream-duration-ms", 3_600_000),
    };
    let controls = Arc::new(Controls::default());
    let tasks = Arc::new(Mutex::new(Vec::new()));
    let handler = Handler {
        args: args.clone(),
        controls: controls.clone(),
        tasks: tasks.clone(),
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public_key = mcp_jack::encoding::encode_b64url(key.verifying_key().as_bytes());
    let server_kid = mcp_jack::encoding::key_id(key.verifying_key().as_bytes());
    let layer = Arc::new(
        StreamLayer::new(StreamConfig {
            verifier,
            server_key: key,
            max_body_bytes: 0,
            max_response_bytes: 0,
            streams: options,
        })
        .with_profile(profile),
    );

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
        let permits = Arc::new(tokio::sync::Semaphore::new(max_streams));
        let mut connections = Vec::new();
        loop {
            tokio::select! {
                command = control_rx.recv() => match command {
                    Some(line) => {
                        let value: serde_json::Value = serde_json::from_str(&line).unwrap_or(serde_json::Value::Null);
                        match value.get("action").and_then(|v| v.as_str()) {
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
                                eprintln!("stream server: release not acknowledged; SDK stream SID is unavailable to the application handler");
                            }
                            _ => continue,
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
                    let permit = match permits.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            drop(socket);
                            continue;
                        }
                    };
                    let layer = Arc::clone(&layer);
                    let handler = handler.clone();
                    connections.push(tokio::spawn(async move {
                        let _permit = permit;
                        let service = hyper_util::service::TowerToHyperService::new(
                            SharedService::new(layer.layer(handler)),
                        );
                        let _ = hyper::server::conn::http1::Builder::new()
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
    std::process::exit(0)
}
