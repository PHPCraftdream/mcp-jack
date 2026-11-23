//! The `C10` `tools/list` and `C12` `events/list` resync flows (spec 04
//! section 6): after a `-32020` header-mismatch refusal the catalog is fetched
//! again, the `Mcp-Param-*` headers are re-projected and the call is retried
//! exactly once.

use std::collections::VecDeque;
use std::sync::Mutex;

use serde_json::{json, Value};

use mcp_jack::client::error::ClientError;
use mcp_jack::client::modern::{ExchangeResponse, ModernExchange, Resync};

/// One recorded exchange: the method, the params and the projected headers.
#[derive(Debug, Clone, PartialEq)]
struct Call {
    method: String,
    params: Value,
    extra_headers: Vec<(String, String)>,
}

/// A private exchange over canned replies, recording every call.
struct FakeExchange {
    replies: Mutex<VecDeque<Result<ExchangeResponse, ClientError>>>,
    calls: Mutex<Vec<Call>>,
}

impl FakeExchange {
    /// An exchange answering `replies` in order.
    fn new(replies: Vec<Result<ExchangeResponse, ClientError>>) -> Self {
        FakeExchange {
            replies: Mutex::new(replies.into()),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// The next canned reply; panics when none is left.
    fn next_reply(&self) -> Result<ExchangeResponse, ClientError> {
        self.replies
            .lock()
            .expect("replies mutex")
            .pop_front()
            .expect("fake exchange replies exhausted")
    }

    /// The calls recorded so far, in exchange order.
    fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("calls mutex").clone()
    }
}

impl ModernExchange for FakeExchange {
    fn exchange(
        &self,
        method: &str,
        params: &Value,
        extra_headers: &[(String, String)],
    ) -> Result<ExchangeResponse, ClientError> {
        self.calls.lock().expect("calls mutex").push(Call {
            method: method.to_owned(),
            params: params.clone(),
            extra_headers: extra_headers.to_vec(),
        });
        self.next_reply()
    }
}

/// A verified 2xx response with `json` as its body.
fn ok(id: u64, result: Value) -> Result<ExchangeResponse, ClientError> {
    Ok(ExchangeResponse {
        status: 200,
        json: json!({"jsonrpc": "2.0", "id": id, "result": result}),
    })
}

/// A verified `400` header-mismatch refusal (JSON-RPC `-32020`).
fn header_mismatch(id: u64) -> Result<ExchangeResponse, ClientError> {
    Ok(ExchangeResponse {
        status: 400,
        json: json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32020, "message": "Header mismatch"},
        }),
    })
}

/// A `tools/list` result carrying one tool whose `region` property is
/// annotated with `header`.
fn tools_list(header: &str) -> Value {
    json!({"tools": [{
        "name": "weather",
        "inputSchema": {"properties": {"region": {"type": "string", "x-mcp-header": header}}},
    }]})
}

/// An `events/list` result carrying one event type whose `region` property is
/// annotated with `header`.
fn events_list(header: &str) -> Value {
    json!({"events": [{
        "name": "incident.created",
        "inputSchema": {"properties": {"region": {"type": "string", "x-mcp-header": header}}},
    }]})
}

/// The `(name, value)` header pairs of one recorded call, as `&str` pairs.
fn header_pairs(call: &Call) -> Vec<(&str, &str)> {
    call.extra_headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

/// The methods of the recorded calls, in exchange order.
fn methods(calls: &[Call]) -> Vec<&str> {
    calls.iter().map(|call| call.method.as_str()).collect()
}

#[test]
fn client_header_resync() {
    let exchange = FakeExchange::new(vec![
        ok(1, tools_list("Region")),
        header_mismatch(2),
        ok(4, tools_list("Zone")),
        ok(3, json!({"resultType": "complete"})),
    ]);

    let mut resync = Resync::new(&exchange);
    resync.refresh_tools().expect("first tools/list");
    let result = resync
        .call_tool("weather", &json!({"region": "eu"}))
        .expect("retried tools/call");
    assert_eq!(result, json!({"resultType": "complete"}));

    let calls = exchange.calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        methods(&calls),
        ["tools/list", "tools/call", "tools/list", "tools/call"]
    );

    // The first call projects the first catalog, the retry the refreshed one.
    assert_eq!(header_pairs(&calls[1]), [("Mcp-Param-Region", "eu")]);
    assert_eq!(header_pairs(&calls[3]), [("Mcp-Param-Zone", "eu")]);

    // Both `tools/call` params carry the target name and its arguments.
    for call in [&calls[1], &calls[3]] {
        assert_eq!(call.method, "tools/call");
        assert_eq!(call.params["name"], json!("weather"));
        assert_eq!(call.params["arguments"], json!({"region": "eu"}));
    }

    // A second scenario: the retried `tools/call` refuses again, so the call
    // fails and the retry is never repeated a third time.
    let exchange = FakeExchange::new(vec![
        ok(1, tools_list("Region")),
        header_mismatch(2),
        ok(4, tools_list("Zone")),
        header_mismatch(3),
    ]);

    let mut resync = Resync::new(&exchange);
    resync.refresh_tools().expect("first tools/list");
    assert!(resync
        .call_tool("weather", &json!({"region": "eu"}))
        .is_err());

    let calls = exchange.calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        methods(&calls),
        ["tools/list", "tools/call", "tools/list", "tools/call"]
    );
}

#[test]
fn client_events_resync() {
    let exchange = FakeExchange::new(vec![
        ok(1, events_list("Region")),
        header_mismatch(2),
        ok(4, events_list("Region2")),
        ok(3, json!({"events": [], "resultType": "complete"})),
    ]);

    let mut resync = Resync::new(&exchange);
    resync.refresh_events().expect("first events/list");
    let result = resync
        .event_call("events/poll", "incident.created", &json!({"region": "eu"}))
        .expect("retried events/poll");
    assert_eq!(result, json!({"events": [], "resultType": "complete"}));

    let calls = exchange.calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        methods(&calls),
        ["events/list", "events/poll", "events/list", "events/poll"]
    );

    assert_eq!(header_pairs(&calls[1]), [("Mcp-Param-Region", "eu")]);
    assert_eq!(header_pairs(&calls[3]), [("Mcp-Param-Region2", "eu")]);

    // Both event calls carry the target name and its arguments.
    for call in [&calls[1], &calls[3]] {
        assert_eq!(call.method, "events/poll");
        assert_eq!(call.params["name"], json!("incident.created"));
        assert_eq!(call.params["arguments"], json!({"region": "eu"}));
    }
}
