//! Private-only result caching (spec 04 section 6, `C8`) and the `C10`/`C12`
//! resync flows.
//!
//! [`PrivateResultCache`] binds a verified result to the exact request it
//! answers, because a Jack response is signed over one request's signature and
//! therefore cannot answer another. [`Resync`] drives one call over
//! [`ModernExchange`]: fetch the catalog, project the `Mcp-Param-*` headers,
//! call, and — on a `-32020` header-mismatch refusal — fetch the catalog again,
//! re-project and retry exactly once.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use serde_json::{json, Map, Value};

use super::projection::{EventCatalog, ProjectionError, ToolCatalog};
use crate::client::error::{ClientError, HttpError};
use crate::modern::Era;

/// The JSON-RPC code of a header-mismatch refusal (spec 04 `C10`/`C12`).
const HEADER_MISMATCH: i64 = -32020;

/// The client-side failure of a response that carries no result.
const NO_RESULT: &str = "jack client: json-rpc response has neither result nor error";

/// One verified JSON-RPC response of an exchange.
#[derive(Debug, Clone, PartialEq)]
pub struct ExchangeResponse {
    /// HTTP status as received and verified.
    pub status: u16,
    /// The verified JSON-RPC object.
    pub json: Value,
}

/// Performs one signed, verified MCP exchange (spec 01 sections 4 and 5). The
/// client implements it; the resync flows of `C10`/`C12` only use this trait, so
/// they are testable without a socket.
pub trait ModernExchange: Send + Sync {
    /// Sends one modern-era request. `extra_headers` carries the projected
    /// `Mcp-Param-*` headers of `C6`, already ordered, and is appended after the
    /// mirror headers of `C2`. The implementation signs the body and verifies
    /// the response; a verified non-2xx response is returned, not an error.
    fn exchange(
        &self,
        method: &str,
        params: &Value,
        extra_headers: &[(String, String)],
    ) -> Result<ExchangeResponse, ClientError>;
}

/// The exact request a cached result belongs to (spec 04 `C8`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheKey {
    /// The request method.
    pub method: String,
    /// The exact request `params` JSON text.
    pub params: String,
    /// The era of the request.
    pub era: Era,
}

// `Era` carries no `Hash`, so the derive-equivalent hash is written out; it
// mirrors `Eq` because `Era::as_str` is injective.
impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.method.hash(state);
        self.params.hash(state);
        self.era.as_str().hash(state);
    }
}

impl CacheKey {
    /// Builds a key from the method, the exact request `params` JSON text and
    /// the era.
    pub fn new(method: impl Into<String>, params: impl Into<String>, era: Era) -> Self {
        CacheKey {
            method: method.into(),
            params: params.into(),
            era,
        }
    }
}

/// A private result cache (spec 04 `C8`): keyed by the exact request and bounded
/// by the server's `ttlMs` hint. It is never shared and never an HTTP cache,
/// because a Jack response is signed over one request's signature and therefore
/// answers exactly that request.
#[derive(Debug, Default)]
pub struct PrivateResultCache {
    /// The stored results with their expiry instant.
    entries: HashMap<CacheKey, (Value, u64)>,
}

impl PrivateResultCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores a verified result for exactly `key`. A `ttl_ms` of zero stores
    /// nothing: the result MUST NOT be reused.
    pub fn insert(&mut self, key: CacheKey, result: Value, ttl_ms: u64, now_ms: u64) {
        if ttl_ms == 0 {
            return;
        }
        self.entries
            .insert(key, (result, now_ms.saturating_add(ttl_ms)));
    }

    /// Returns the stored result for exactly `key` when it has not expired.
    pub fn get(&self, key: &CacheKey, now_ms: u64) -> Option<&Value> {
        self.entries
            .get(key)
            .filter(|(_, expiry)| now_ms < *expiry)
            .map(|(result, _)| result)
    }

    /// The number of stored results, expired ones included.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache stores no result at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The `C10`/`C12` flows: fetch the catalog, project, call, and on a `-32020`
/// refusal fetch the catalog again, re-project and retry exactly once.
pub struct Resync<'a> {
    /// The one exchange every request of the flow goes through.
    exchange: &'a dyn ModernExchange,
    /// The `tools/list` catalog as last received (`C5`).
    tools: ToolCatalog,
    /// The `events/list` catalog as last received (`C11`).
    events: EventCatalog,
}

impl<'a> Resync<'a> {
    /// A resync flow over one exchange; both catalogs start empty.
    pub fn new(exchange: &'a dyn ModernExchange) -> Self {
        Resync {
            exchange,
            tools: ToolCatalog::default(),
            events: EventCatalog::default(),
        }
    }

    /// The current tool catalog.
    pub fn tools(&self) -> &ToolCatalog {
        &self.tools
    }

    /// The current event catalog.
    pub fn events(&self) -> &EventCatalog {
        &self.events
    }

    /// Clears both catalogs (`C10`/`C12` resync). Callers that keep a private
    /// result cache must drop the live entry for a target before re-listing, so
    /// the next call is not answered from a catalog that is being replaced.
    pub fn invalidate(&mut self) {
        self.tools = ToolCatalog::default();
        self.events = EventCatalog::default();
    }

    /// Fetches `tools/list` and rebuilds the tool catalog (`C5` filtering).
    pub fn refresh_tools(&mut self) -> Result<(), ClientError> {
        self.invalidate();
        let response = self.exchange.exchange("tools/list", &json!({}), &[])?;
        let result = listed(success_body(response)?);
        self.tools = ToolCatalog::from_tools_list(&result);
        Ok(())
    }

    /// Fetches `events/list` and rebuilds the event catalog (`C11` filtering).
    pub fn refresh_events(&mut self) -> Result<(), ClientError> {
        self.invalidate();
        let response = self.exchange.exchange("events/list", &json!({}), &[])?;
        let result = listed(success_body(response)?);
        self.events = EventCatalog::from_events_list(&result);
        Ok(())
    }

    /// Calls `tools/call` for `tool` with `arguments` (`C10`): project, call, and
    /// after a `-32020` refusal refresh `tools/list`, re-project and retry once.
    pub fn call_tool(&mut self, tool: &str, arguments: &Value) -> Result<Value, ClientError> {
        let headers = self.tools.project(tool, arguments).map_err(projection)?;
        let params = call_params(tool, arguments);
        let first = self.exchange.exchange("tools/call", &params, &headers)?;
        if !is_header_mismatch(&first) {
            return result_of(first);
        }
        self.refresh_tools()?;
        let headers = self.tools.project(tool, arguments).map_err(projection)?;
        result_of(self.exchange.exchange("tools/call", &params, &headers)?)
    }

    /// Calls one of `events/poll`, `events/stream`, `events/subscribe`,
    /// `events/unsubscribe` for `event` with `arguments` (`C12`): same flow over
    /// `events/list`.
    pub fn event_call(
        &mut self,
        method: &str,
        event: &str,
        arguments: &Value,
    ) -> Result<Value, ClientError> {
        let headers = self.events.project(event, arguments).map_err(projection)?;
        let params = call_params(event, arguments);
        let first = self.exchange.exchange(method, &params, &headers)?;
        if !is_header_mismatch(&first) {
            return result_of(first);
        }
        self.refresh_events()?;
        let headers = self.events.project(event, arguments).map_err(projection)?;
        result_of(self.exchange.exchange(method, &params, &headers)?)
    }
}

/// The body of a successful exchange; a non-2xx response is a protocol error
/// carrying the JSON-RPC `error` object of the verified body.
fn success_body(response: ExchangeResponse) -> Result<Value, ClientError> {
    if !(200..300).contains(&response.status) {
        return Err(http_error(response.status, &response.json));
    }
    Ok(response.json)
}

/// The result member of a successful body, or a client-side error.
fn result_of(response: ExchangeResponse) -> Result<Value, ClientError> {
    match success_body(response)? {
        Value::Object(members) => members
            .get("result")
            .cloned()
            .ok_or_else(|| ClientError::Client(NO_RESULT.to_owned())),
        _ => Err(ClientError::Client(NO_RESULT.to_owned())),
    }
}

/// A `tools/list` or `events/list` body: its `result` member when present, the
/// whole body otherwise.
fn listed(body: Value) -> Value {
    match body {
        Value::Object(members) => match members.get("result") {
            Some(result) => result.clone(),
            None => Value::Object(members),
        },
        other => other,
    }
}

/// A refused projection (spec 04 `C6`) as a client-side error.
fn projection(error: ProjectionError) -> ClientError {
    ClientError::Client(format!("jack client: {}", error.as_str()))
}

/// The `params` of a `tools/call` or event call: the target name and its
/// arguments.
fn call_params(name: &str, arguments: &Value) -> Value {
    let mut params = Map::new();
    params.insert("name".to_owned(), Value::String(name.to_owned()));
    params.insert("arguments".to_owned(), arguments.clone());
    Value::Object(params)
}

/// Whether a verified response is a `-32020` header-mismatch refusal
/// (spec 04 `C10`/`C12`): a `400` whose JSON-RPC `error.code` is that integer.
fn is_header_mismatch(response: &ExchangeResponse) -> bool {
    if response.status != 400 {
        return false;
    }
    response
        .json
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_i64)
        == Some(HEADER_MISMATCH)
}

/// A non-2xx verified response as a protocol error: the code is the string
/// form, the decimal text of an integer or the empty string when absent; the
/// message is the string form or the empty string when absent.
fn http_error(status: u16, body: &Value) -> ClientError {
    let error = body.get("error");
    let code = match error.and_then(|error| error.get("code")) {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => match number.as_i64() {
            Some(code) => code.to_string(),
            None => String::new(),
        },
        _ => String::new(),
    };
    let message = error
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    ClientError::Http(HttpError {
        status,
        code,
        message,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn cache_binds_to_the_exact_request_and_the_ttl() {
        let mut cache = PrivateResultCache::new();
        assert!(cache.is_empty());

        let key = CacheKey::new("tools/call", "{\"name\":\"a\"}", Era::Modern);
        cache.insert(key.clone(), json!({"ok": true}), 1000, 10);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&key, 10), Some(&json!({"ok": true})));

        for other in [
            CacheKey::new("tools/call", "{\"name\":\"b\"}", Era::Modern),
            CacheKey::new("events/poll", "{\"name\":\"a\"}", Era::Modern),
            CacheKey::new("tools/call", "{\"name\":\"a\"}", Era::Legacy),
        ] {
            assert!(cache.get(&other, 10).is_none(), "{other:?}");
        }

        // The expiry instant is `now_ms + ttl_ms`: gone at and after it.
        assert!(cache.get(&key, 1009).is_some());
        assert!(cache.get(&key, 1010).is_none());
        assert!(cache.get(&key, 1011).is_none());

        // `ttl_ms: 0` stores nothing.
        cache.insert(
            CacheKey::new("tools/call", "{\"name\":\"c\"}", Era::Modern),
            json!({"ok": true}),
            0,
            10,
        );
        assert_eq!(cache.len(), 1);
    }

    /// One recorded exchange call: the method and the extra headers.
    type RecordedCall = (String, Vec<(String, String)>);

    /// One canned exchange: recorded calls and a reply per request.
    struct FakeExchange {
        calls: Mutex<Vec<RecordedCall>>,
        replies: Mutex<VecDeque<ExchangeResponse>>,
    }

    impl FakeExchange {
        fn new(replies: Vec<ExchangeResponse>) -> Self {
            FakeExchange {
                calls: Mutex::new(Vec::new()),
                replies: Mutex::new(replies.into()),
            }
        }
    }

    impl ModernExchange for FakeExchange {
        fn exchange(
            &self,
            method: &str,
            _params: &Value,
            extra_headers: &[(String, String)],
        ) -> Result<ExchangeResponse, ClientError> {
            self.calls
                .lock()
                .expect("calls mutex")
                .push((method.to_owned(), extra_headers.to_vec()));
            self.replies
                .lock()
                .expect("replies mutex")
                .pop_front()
                .ok_or_else(|| {
                    ClientError::Client("jack client: fake replies exhausted".to_owned())
                })
        }
    }

    /// A `tools/list` body carrying one tool whose `region` property is
    /// annotated with `header`.
    fn tools_list(header: &str) -> Value {
        json!({"tools": [{
            "name": "greet",
            "inputSchema": {
                "type": "object",
                "properties": {"region": {"type": "string", "x-mcp-header": header}},
            },
        }]})
    }

    /// A verified response with `status` and body.
    fn response(status: u16, json: Value) -> ExchangeResponse {
        ExchangeResponse { status, json }
    }

    #[test]
    fn retries_once_after_a_header_mismatch_with_the_new_projection() {
        let exchange = FakeExchange::new(vec![
            response(
                200,
                json!({"jsonrpc": "2.0", "id": 1, "result": tools_list("Region")}),
            ),
            response(
                400,
                json!({"jsonrpc": "2.0", "id": 2, "error": {"code": -32020, "message": "mismatch"}}),
            ),
            response(
                200,
                json!({"jsonrpc": "2.0", "id": 3, "result": tools_list("Region-New")}),
            ),
            response(
                200,
                json!({"jsonrpc": "2.0", "id": 4, "result": {"content": []}}),
            ),
        ]);

        let mut resync = Resync::new(&exchange);
        resync.refresh_tools().expect("first catalog");
        assert_eq!(resync.tools().entries().len(), 1);

        let result = resync.call_tool("greet", &json!({"region": "eu"}));
        assert_eq!(result, Ok(json!({"content": []})));

        let calls = exchange.calls.lock().expect("calls mutex");
        let methods: Vec<&str> = calls.iter().map(|(method, _)| method.as_str()).collect();
        assert_eq!(
            methods,
            ["tools/list", "tools/call", "tools/list", "tools/call"]
        );
        assert_eq!(
            calls[1].1,
            [("Mcp-Param-Region".to_owned(), "eu".to_owned())]
        );
        assert_eq!(
            calls[3].1,
            [("Mcp-Param-Region-New".to_owned(), "eu".to_owned())]
        );
    }
}
