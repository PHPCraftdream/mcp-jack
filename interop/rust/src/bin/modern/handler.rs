//! The wrapped handler of interop/modern/contract.md 3.4 as a tower service,
//! shaped like src/bin/interop/mcp.rs: it only ever sees requests the SDK
//! wrapper authenticated, decided to forward and stripped of the modern
//! session headers, and it never inspects the per-request era (contract 3.6).

use std::convert::Infallible;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http_body_util::Full;
use serde_json::value::RawValue;
use serde_json::{json, Value};
use tower_service::Service;

use mcp_jack::server::modern::Profile;

/// Fixed identity of contract 3.4 (a) and (f).
const SERVER_NAME: &str = "mcp-jack-interop-modern";
const SERVER_VERSION: &str = "1.0.0";
/// Contract 3.4 (f): the negotiated version when the request is not supported.
const DEFAULT_VERSION: &str = "2025-11-25";
/// spec 04 section 1: the `_meta` member mirroring the protocol version.
const PROTOCOL_VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";

/// Contract 3.5: when a `server/discover` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverMode {
    Supported,
    RefuseFirst,
    RefuseAlways,
}

impl DiscoverMode {
    /// Parses the `--discover-version-mode` value.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "supported" => Some(Self::Supported),
            "refuse-first" => Some(Self::RefuseFirst),
            "refuse-always" => Some(Self::RefuseAlways),
            _ => None,
        }
    }
}

/// The wrapped handler. Cloning shares the process-wide discover counter and
/// the request-log path, which is what the per-connection clones must do.
#[derive(Clone)]
pub struct ModernHandler {
    profile: Profile,
    supported_versions: Vec<String>,
    discover_mode: DiscoverMode,
    discover_count: Arc<AtomicUsize>,
    request_log: Option<Arc<PathBuf>>,
}

impl ModernHandler {
    /// Builds the handler; the discover counter starts at zero per process.
    pub fn new(
        profile: Profile,
        supported_versions: Vec<String>,
        discover_mode: DiscoverMode,
        request_log: Option<Arc<PathBuf>>,
    ) -> Self {
        Self {
            profile,
            supported_versions,
            discover_mode,
            discover_count: Arc::new(AtomicUsize::new(0)),
            request_log,
        }
    }

    /// Whether `version` is in the configured `--supported-versions` list.
    fn supports(&self, version: &str) -> bool {
        self.supported_versions
            .iter()
            .any(|supported| supported == version)
    }

    /// Contract 3.4 (a) and (c): the discover result, or its `-32022` refusal.
    /// Contract 3.5: `refuse-first` refuses the first discover of the process
    /// whatever the version, and every later one follows the `supported` rule.
    fn discover(&self, body: Option<&Body>, id: Option<&RawValue>) -> Answer {
        // Contract 3.4 (b): the legacy profile answers the 0.1.x envelope, so
        // a C9 client reads it as a legacy signal and falls back.
        if self.profile == Profile::Legacy {
            return Answer::json(
                405,
                json_bytes(&json!({
                    "error": {
                        "code": "method_not_allowed",
                        "message": "server/discover is not available in the legacy profile",
                    },
                })),
            );
        }
        let requested = body
            .and_then(|body| body.param("_meta"))
            .and_then(|meta| meta.get(PROTOCOL_VERSION_META))
            .and_then(Value::as_str);
        let supported_now = matches!(requested, Some(version) if self.supports(version));
        // fetch_add yields the count BEFORE this discover and counts every
        // discover whether refused or not: refuse-first refuses exactly the
        // first one of the process (contract 3.5).
        let index = self.discover_count.fetch_add(1, Ordering::SeqCst);
        let refused = match self.discover_mode {
            DiscoverMode::RefuseAlways => true,
            DiscoverMode::RefuseFirst if index == 0 => true,
            _ => !supported_now,
        };
        if refused {
            return Answer::json(
                400,
                rpc_error(
                    id,
                    -32022,
                    "Unsupported protocol version",
                    Some(json!({
                        "supported": &self.supported_versions,
                        "requested": requested,
                    })),
                ),
            );
        }
        Answer::json(
            200,
            rpc_result(
                id,
                json!({
                    "resultType": "complete",
                    "supportedVersions": &self.supported_versions,
                    "capabilities": {},
                    "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                }),
            ),
        )
    }

    /// Contract 3.4 (f): the negotiated version plus the single session id.
    fn initialize(&self, body: Option<&Body>, id: Option<&RawValue>) -> Answer {
        let requested = body
            .and_then(|body| body.param("protocolVersion"))
            .and_then(Value::as_str);
        let negotiated = match requested {
            Some(version) if self.supports(version) => version,
            _ => DEFAULT_VERSION,
        };
        let mut answer = Answer::json(
            200,
            rpc_result(
                id,
                json!({
                    "protocolVersion": negotiated,
                    "capabilities": {},
                    "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                }),
            ),
        );
        // Contract 3.4 (f): the server never mints any other session id.
        answer.session_id = Some("sess-1");
        answer
    }

    /// Contract 3.4 (d): the single annotated tool.
    fn tools_list(id: Option<&RawValue>) -> Answer {
        Answer::json(
            200,
            rpc_result(
                id,
                json!({
                    "tools": [{
                        "name": "region.echo",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "region": { "type": "string", "x-mcp-header": "Region" },
                            },
                            "required": ["region"],
                        },
                    }],
                }),
            ),
        )
    }

    /// Dispatches one forwarded request by body method (contract 3.4).
    fn answer(&self, body: Option<&Body>, headers: &http::HeaderMap) -> Answer {
        let id = body.and_then(Body::id);
        match body.and_then(Body::method) {
            Some("server/discover") => self.discover(body, id),
            Some("tools/list") => Self::tools_list(id),
            Some("tools/call") => {
                match body
                    .and_then(|body| body.param("name"))
                    .and_then(Value::as_str)
                {
                    Some("region.echo") => Answer::json(
                        200,
                        rpc_result(
                            id,
                            json!({
                                "content": [{ "type": "text", "text": header_echo(headers) }],
                            }),
                        ),
                    ),
                    _ => Answer::json(200, rpc_error(id, -32601, "method not found", None)),
                }
            }
            Some("initialize") => self.initialize(body, id),
            Some("notifications/initialized") => Answer::empty(202),
            // Contract 3.4 (h): any other method, including a non-JSON body
            // (a legacy-era response object or a non-POST forward).
            _ => Answer::json(200, rpc_error(id, -32601, "method not found", None)),
        }
    }

    /// Contract 3.3: appends one line per request this handler answered and
    /// flushes it before the response leaves. A log failure is a stderr line:
    /// it must never change the answer.
    fn log_request(&self, method: Option<&str>, status: u16) {
        let Some(path) = self.request_log.as_deref() else {
            return;
        };
        #[derive(serde::Serialize)]
        struct Entry<'a> {
            method: Option<&'a str>,
            http_status: u16,
        }
        let Ok(mut line) = serde_json::to_string(&Entry {
            method,
            http_status: status,
        }) else {
            // Unreachable: the shape is a string option and an integer.
            eprintln!("modern-server: request log: cannot serialize the entry");
            return;
        };
        line.push('\n');
        let written = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .and_then(|mut file| {
                file.write_all(line.as_bytes())?;
                file.flush()
            });
        if let Err(e) = written {
            eprintln!("modern-server: request log {}: {e}", path.display());
        }
    }

    fn handle(&self, req: http::Request<Full<Bytes>>) -> http::Response<Full<Bytes>> {
        let (parts, body) = req.into_parts();
        // into_inner yields None only when the body was already polled; the
        // wrapper always hands this service a fresh, unpolled Full.
        let bytes = body.into_inner().unwrap_or_default();
        // A body that is not a JSON object has no method and no id; that is
        // the contract 3.4 (h) catch-all, never an error.
        let body = serde_json::from_slice::<Body>(&bytes).ok();
        let method = body.as_ref().and_then(Body::method);
        let answer = self.answer(body.as_ref(), &parts.headers);
        self.log_request(method, answer.status);
        answer.into_response()
    }
}

impl Service<http::Request<Full<Bytes>>> for ModernHandler {
    type Response = http::Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<http::Response<Full<Bytes>>, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Full<Bytes>>) -> Self::Future {
        std::future::ready(Ok(self.handle(req)))
    }
}

/// One handler answer before the wrapper signs it.
struct Answer {
    status: u16,
    body: Bytes,
    session_id: Option<&'static str>,
}

impl Answer {
    fn json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body: body.into(),
            session_id: None,
        }
    }

    fn empty(status: u16) -> Self {
        Self {
            status,
            body: Bytes::new(),
            session_id: None,
        }
    }

    fn into_response(self) -> http::Response<Full<Bytes>> {
        let mut builder = http::Response::builder().status(self.status);
        // Contract 3.4: every non-empty answer is JSON; a 202 carries none.
        if !self.body.is_empty() {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        if let Some(session_id) = self.session_id {
            builder = builder.header("Mcp-Session-Id", session_id);
        }
        // Contract 3.4 (b): the fake sets Allow on every 405 answer.
        if self.status == 405 {
            builder = builder.header(http::header::ALLOW, "POST");
        }
        builder
            .body(Full::new(self.body))
            .expect("static status and header values cannot fail")
    }
}

/// The verified body, parsed once: the id stays raw so its echo is verbatim
/// (contract 3.4), while method and params only need their JSON values.
#[derive(serde::Deserialize)]
struct Body {
    #[serde(default)]
    id: Option<Box<RawValue>>,
    #[serde(default)]
    method: Value,
    #[serde(default)]
    params: Value,
}

impl Body {
    fn id(&self) -> Option<&RawValue> {
        self.id.as_deref()
    }

    fn method(&self) -> Option<&str> {
        self.method.as_str()
    }

    /// `params.<member>`; a non-object `params` has no members.
    fn param(&self, member: &str) -> Option<&Value> {
        self.params.get(member)
    }
}

/// Contract 3.4 (e): one `name: value` line per header instance the handler
/// received, in the order the map renders them, joined with LF and no trailing
/// LF. Names arrive lowercased and grouped by name, which contract 3.4 (e)
/// explicitly allows.
fn header_echo(headers: &http::HeaderMap) -> String {
    headers
        .iter()
        .map(|(name, value)| {
            format!(
                "{}: {}",
                name.as_str(),
                String::from_utf8_lossy(value.as_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The `result` envelope of contract 3.4; `id` serializes from its raw text,
/// so the echo is verbatim.
fn rpc_result(id: Option<&RawValue>, result: Value) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Envelope<'a> {
        jsonrpc: &'static str,
        id: Option<&'a RawValue>,
        result: Value,
    }
    serde_json::to_vec(&Envelope {
        jsonrpc: "2.0",
        id,
        result,
    })
    .expect("static JSON-RPC shape serializes")
}

/// The `error` envelope of contract 3.4 (c) and (h); `data` is omitted when
/// absent.
fn rpc_error(
    id: Option<&RawValue>,
    code: i64,
    message: &'static str,
    data: Option<Value>,
) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Detail<'a> {
        code: i64,
        message: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<Value>,
    }
    #[derive(serde::Serialize)]
    struct Envelope<'a> {
        jsonrpc: &'static str,
        id: Option<&'a RawValue>,
        error: Detail<'a>,
    }
    serde_json::to_vec(&Envelope {
        jsonrpc: "2.0",
        id,
        error: Detail {
            code,
            message,
            data,
        },
    })
    .expect("static JSON-RPC shape serializes")
}

fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("static body shape serializes")
}
