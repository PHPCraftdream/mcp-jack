//! The 6.3 server-initiated close shapes: whether a message completes the
//! opening request and the exact `events/stream` final result.

use serde::Deserialize;
use serde_json::value::RawValue;

/// A member whose presence matters even when its value is `null` (6.3 counts
/// `"result":null` as a `result` member).
#[derive(Default)]
struct Present(Option<serde_json::Value>);

impl<'de> Deserialize<'de> for Present {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde_json::Value::deserialize(deserializer).map(|value| Present(Some(value)))
    }
}

/// The 6.3 response object; `id` is kept as its raw JSON lexeme so the exact
/// bytes of the request's id are compared.
#[derive(Deserialize)]
struct ResponseObject<'a> {
    #[serde(default)]
    jsonrpc: Option<String>,
    #[serde(default, borrow)]
    id: Option<&'a RawValue>,
    #[serde(default)]
    result: Present,
    #[serde(default)]
    error: Present,
    #[serde(default)]
    method: Present,
}

/// 6.3: `data` is a JSON-RPC response object for `request_id` (`jsonrpc`:
/// "2.0", that exact id lexeme, exactly one of result/error, no method).
pub fn is_final_response(data: &str, request_id: &str) -> bool {
    // 6.3 describes a response OBJECT; a derived struct would also accept a
    // JSON array of its fields.
    if !data.trim_start().starts_with('{') {
        return false;
    }
    let Ok(response) = serde_json::from_str::<ResponseObject<'_>>(data) else {
        return false;
    };
    response.jsonrpc.as_deref() == Some("2.0")
        && response.id.is_some_and(|id| id.get() == request_id)
        && (response.result.0.is_some() != response.error.0.is_some())
        && response.method.0.is_none()
}

/// 6.3 for `events/stream`: the exact final result of the request, `<id>` in
/// the same lexeme.
pub fn events_stream_result(request_id: &str) -> String {
    let mut out = String::with_capacity(request_id.len() * 2 + 120);
    out.push_str("{\"jsonrpc\":\"2.0\",\"id\":");
    out.push_str(request_id);
    out.push_str(
        ",\"result\":{\"resultType\":\"complete\",\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":",
    );
    out.push_str(request_id);
    out.push_str("}}}");
    out
}
