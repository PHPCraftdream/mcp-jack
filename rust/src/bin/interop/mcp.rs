//! The fixed trivial MCP handler of interop/README.md section 4, as a tower
//! service to be wrapped by the SDK's JackLayer (Go: mcpHandler in
//! interop/go/server/main.go). It only ever sees authorized requests.

use std::convert::Infallible;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::Full;
use serde_json::value::RawValue;
use tower_service::Service;

/// Wire types of the fixed trivial MCP handler; declaration order mirrors
/// Go's field-order marshaling.
#[derive(serde::Deserialize)]
struct TrivialParams {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<Box<RawValue>>,
}

#[derive(serde::Deserialize)]
struct TrivialRequest {
    /// None (absent id) serializes as null, like Go's len-0 RawMessage.
    #[serde(default)]
    id: Option<Box<RawValue>>,
    #[serde(default)]
    method: String,
    #[serde(default)]
    params: Option<TrivialParams>,
}

#[derive(serde::Serialize)]
struct RpcError {
    code: i64,
    message: &'static str,
}

#[derive(serde::Serialize)]
struct Envelope<'a> {
    jsonrpc: &'static str,
    id: Option<&'a RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'a RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(serde::Serialize)]
struct EmptyResult {}

#[derive(serde::Serialize)]
struct ToolEntry {
    name: &'static str,
}

#[derive(serde::Serialize)]
struct ToolsResult {
    tools: [ToolEntry; 1],
}

#[derive(serde::Serialize)]
struct TextContent {
    r#type: &'static str,
    text: String,
}

#[derive(serde::Serialize)]
struct ContentResult {
    content: [TextContent; 1],
}

/// The trivial service. Clone + Send + 'static with Infallible errors and a
/// Send future: satisfies JackService's bounds; Full<Bytes>'s Error is
/// Infallible so it satisfies ResBody's bounds.
#[derive(Clone, Default)]
pub struct TrivialService;

impl Service<http::Request<Full<Bytes>>> for TrivialService {
    type Response = http::Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<http::Response<Full<Bytes>>, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Full<Bytes>>) -> Self::Future {
        std::future::ready(Ok(handle(req)))
    }
}

/// Answers one request exactly as Go mcpHandler does.
fn handle(req: http::Request<Full<Bytes>>) -> http::Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    match parts.method.as_str() {
        "GET" => {
            if parts.uri.path() == "/sse" {
                // Finite SSE answer; the wrapper buffers it and replies with
                // the signed 501 streaming_unsupported itself.
                return respond(
                    200,
                    "text/event-stream",
                    Bytes::from_static(b"data: hello\n\n"),
                );
            }
            return respond(
                200,
                "application/json",
                Bytes::from_static(br#"{"jsonrpc":"2.0","id":null,"result":{}}"#),
            );
        }
        // Unreachable: the wrapper rejects other methods first.
        "POST" => {}
        _ => {
            return respond(
                405,
                "application/json",
                Bytes::from_static(
                    br#"{"error":{"code":"method_not_allowed","message":"only GET and POST are defined"}}"#,
                ),
            );
        }
    }

    // into_inner yields None only when the body was already polled; the
    // wrapper always hands this service a fresh, unpolled Full. An empty
    // body then takes the same not-found path as Go's read-error branch.
    let bytes = body.into_inner().unwrap_or_default();
    // Unreachable: the verifier rejects unparseable bodies earlier; kept
    // mirroring Go.
    let Ok(in_msg) = serde_json::from_slice::<TrivialRequest>(&bytes) else {
        return json_response(not_found(None));
    };

    let id = in_msg.id.as_deref();
    let params = in_msg.params.as_ref();
    match in_msg.method.as_str() {
        "ping" => result_envelope(id, &EmptyResult {}),
        "tools/list" => result_envelope(
            id,
            &ToolsResult {
                tools: [ToolEntry { name: "echo" }],
            },
        ),
        "tools/call" => match params.and_then(|p| p.name.as_deref()) {
            Some("echo") => match echo_text(params.and_then(|p| p.arguments.as_deref())) {
                Some(text) => result_envelope(
                    id,
                    &ContentResult {
                        content: [TextContent {
                            r#type: "text",
                            text,
                        }],
                    },
                ),
                None => json_response(not_found(id)),
            },
            // Ordinary non-native calls are forwarded by the verifier; these
            // canned responses are only application behavior if they arrive.
            Some("logs.tail" | "config.set") => result_envelope(
                id,
                &ContentResult {
                    content: [TextContent {
                        r#type: "text",
                        text: "ok".to_owned(),
                    }],
                },
            ),
            _ => json_response(not_found(id)),
        },
        _ => json_response(not_found(id)),
    }
}

/// Extracts arguments.text, decoded as a JSON string; any failure is the
/// -32601 path (Go unmarshal error), so None means not-found.
fn echo_text(arguments: Option<&RawValue>) -> Option<String> {
    let args: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(arguments?.get()).ok()?;
    args.get("text")?.as_str().map(str::to_owned)
}

fn not_found(id: Option<&RawValue>) -> Envelope<'_> {
    Envelope {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcError {
            code: -32601,
            message: "method not found",
        }),
    }
}

fn result_envelope<'a, T: serde::Serialize>(
    id: Option<&'a RawValue>,
    res: &'a T,
) -> http::Response<Full<Bytes>> {
    // Unreachable failure: the result shapes above are static JSON.
    let raw = serde_json::value::to_raw_value(res).expect("static result shape serializes");
    let body = serde_json::to_vec(&Envelope {
        jsonrpc: "2.0",
        id,
        result: Some(&raw),
        error: None,
    })
    .expect("static JSON-RPC shape serializes");
    respond(200, "application/json", body.into())
}

fn json_response(envelope: Envelope<'_>) -> http::Response<Full<Bytes>> {
    let body = serde_json::to_vec(&envelope).expect("static JSON-RPC shape serializes");
    respond(200, "application/json", body.into())
}

fn respond(status: u16, content_type: &'static str, body: Bytes) -> http::Response<Full<Bytes>> {
    // Statuses here are protocol constants: construction cannot fail.
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .body(Full::new(body))
        .expect("static status and header values cannot fail")
}
