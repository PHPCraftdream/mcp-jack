//! The client era flow (spec 04 section 6, `C9`; `docs/design/mcp-compatibility.md`
//! rows Lifecycle and Session).
//!
//! One client speaks one resolved era at a time, and only an explicitly
//! [`ClientEra::Auto`] client resolves anything: it probes once with a modern
//! `server/discover` and follows the *verified* verdict, caching the decision
//! and re-probing when a later reply contradicts it. A probed legacy verdict
//! then runs the `2025-11-25` handshake (`initialize` → negotiated version →
//! `notifications/initialized`) and carries the negotiated version and the
//! `Mcp-Session-Id` on every later request.
//!
//! The two fixed eras issue no extra request at all: [`ClientEra::Legacy`]
//! (the default) is the one-shot 0.1.x request — no probe, no `initialize`, no
//! `notifications/initialized`, byte-identical bytes and headers — and
//! [`ClientEra::Modern`] builds the modern request with no probe and no
//! handshake.
//!
//! Every request is built by [`send_rpc`], signed and verified by
//! `SigningTransport::round_trip_as`, and every era decision reads a verified
//! response only. The one `-32022` version retry, the single-flight handshake
//! and the legacy `404` recovery live here too.

use std::sync::atomic::Ordering;
use std::sync::MutexGuard;

use serde_json::{json, Map, Value};

use super::era::{detect_era, EraAction, EraDetection, EraReason, VerifiedResponse};
use super::{add_client_info, build_mirrors, ClientEra};
use crate::client::error::{parse_error_body, ClientError, HttpError, ReplyError, RpcError};
use crate::client::rpc::Client;
use crate::client::signer::Signer;
use crate::client::transport::{HttpRequest, HttpResponse};
use crate::modern::{Era, IMPLEMENTATION_NAME, IMPLEMENTATION_VERSION, MODERN_MIN};

/// The legacy protocol version this client implements (spec 04 section 2).
pub(crate) const LEGACY_VERSION: &str = "2025-11-25";

/// Every legacy protocol version this client implements. `initialize` may
/// negotiate only one of them, and a `-32022` `supported` list may name only
/// one of them as the retry candidate (the retry additionally skips the
/// version just attempted).
const IMPLEMENTED_VERSIONS: [&str; 1] = [LEGACY_VERSION];

/// The JSON-RPC code of a version mismatch (spec 04 section 5.2).
const VERSION_MISMATCH: i64 = -32022;

/// The era flow state of one client (spec 04 `C9`).
///
/// Held behind a [`std::sync::Mutex`]: the resolved era, the version modern
/// requests carry, the one `-32022` retry budget and the legacy negotiated
/// version plus session.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct FlowState {
    /// The era a verified response proved; `None` means unresolved, so the
    /// next call of an `Auto` client probes.
    pub(crate) era: Option<Era>,
    /// The protocol version modern requests carry: [`MODERN_MIN`], or the
    /// version a `-32022` retry adopted.
    pub(crate) modern_version: Option<String>,
    /// Whether the one `-32022` retry budget has been spent.
    pub(crate) retried: bool,
    /// The legacy version negotiated by `initialize`.
    pub(crate) version: Option<String>,
    /// The `Mcp-Session-Id` response header of a successful `initialize`.
    pub(crate) session: Option<String>,
}

impl FlowState {
    /// Forgets the resolved era, both versions and the session, so the next
    /// call of an `Auto` client probes again.
    fn clear(&mut self) {
        *self = FlowState::default();
    }
}

/// One signed, verified `tools/call` in the era the client is configured for
/// (spec 04 `C9`).
///
/// Only [`ClientEra::Auto`] resolves an era, and only it may add requests: the
/// probe, the `initialize` handshake and the `notifications/initialized` all
/// belong to that flow. [`ClientEra::Legacy`] (the default) stays the 0.1.x
/// one-shot request, and [`ClientEra::Modern`] stays one modern request.
///
/// A per-request signer override (`enroll` signs the whole request with the new
/// key, `rotate_key` pins the clock) is a self-authenticating one-off: it never
/// probes and never handshakes, because the override key may not be registered
/// yet and the 0.1.x bytes of those requests are part of the protocol. An
/// explicitly modern client still mirrors `_meta` for it.
pub(crate) fn tool_call(
    client: &Client,
    signer: Option<&dyn Signer>,
    pinned_ts: Option<i64>,
    tool: &str,
    args_json: Option<&str>,
) -> Result<Value, ClientError> {
    if signer.is_some() {
        return map_tool_reply(match client.era {
            ClientEra::Modern => modern_tool_call(client, signer, pinned_ts, tool, args_json)?,
            ClientEra::Legacy | ClientEra::Auto => {
                direct_legacy_call(client, signer, pinned_ts, tool, args_json)?
            }
        });
    }
    match client.era {
        // The default era: exactly one 0.1.x request, nothing else on the wire.
        ClientEra::Legacy => map_tool_reply(direct_legacy_call(
            client, signer, pinned_ts, tool, args_json,
        )?),
        ClientEra::Modern => map_tool_reply(modern_tool_call(
            client, signer, pinned_ts, tool, args_json,
        )?),
        ClientEra::Auto => match resolve_auto_era(client, signer, pinned_ts)? {
            Era::Modern => map_tool_reply(modern_tool_call(
                client, signer, pinned_ts, tool, args_json,
            )?),
            Era::Legacy => map_tool_reply(legacy_tool_call(
                client, signer, pinned_ts, tool, args_json,
            )?),
        },
    }
}

/// One legacy `tools/call` with the 0.1.x bytes and no lifecycle headers, for
/// the self-authenticating per-request signer override.
fn direct_legacy_call(
    client: &Client,
    signer: Option<&dyn Signer>,
    pinned_ts: Option<i64>,
    tool: &str,
    args_json: Option<&str>,
) -> Result<HttpResponse, ClientError> {
    let id = next_id(client);
    let body = Client::build_request_body(id, tool, args_json);
    send_body(client, signer, pinned_ts, body, &[])
}

/// Forgets the resolved era, the negotiated version and the session.
pub(crate) fn reset_era(client: &Client) {
    clear(client);
}

/// The era the next request of an `Auto` client is built in: the cached
/// decision, or the one probe of `C9`. Only `Auto` reaches this function.
fn resolve_auto_era(
    client: &Client,
    signer: Option<&dyn Signer>,
    pinned_ts: Option<i64>,
) -> Result<Era, ClientError> {
    if let Some(era) = cached_era(client) {
        return Ok(era);
    }
    probe(client, signer, pinned_ts)
}

/// The `C9` auto probe: send `server/discover` (never the caller's operation)
/// as a modern request and act on the verified verdict.
fn probe(
    client: &Client,
    signer: Option<&dyn Signer>,
    pinned_ts: Option<i64>,
) -> Result<Era, ClientError> {
    let _guard = lock_era(client);
    // A concurrent caller may have resolved the era while this one waited.
    if let Some(era) = cached_era(client) {
        return Ok(era);
    }
    let mut version = current_modern_version(client);
    loop {
        let resp = send_modern(
            client,
            signer,
            pinned_ts,
            "server/discover",
            &json!({}),
            &version,
        )?;
        let detection = detect(&resp);
        match detection.action {
            EraAction::StayModern => {
                cache_modern(client, &version);
                return Ok(Era::Modern);
            }
            EraAction::FallbackInitialize => {
                let negotiated = handshake(client, signer, pinned_ts)?;
                store_legacy(client, negotiated);
                return Ok(Era::Legacy);
            }
            EraAction::RetryWithSupported | EraAction::Abort => {
                if detection.action == EraAction::Abort
                    && detection.reason != Some(EraReason::UnsupportedVersionNoOverlap)
                {
                    return Err(no_signal_error(detection.reason));
                }
                match adopt_retry(client, &resp, &version)? {
                    Some(next) => version = next,
                    None => return Err(no_overlap_error()),
                }
            }
        }
    }
}

/// One `tools/call` in the modern era, with the one `-32022` retry.
fn modern_tool_call(
    client: &Client,
    signer: Option<&dyn Signer>,
    pinned_ts: Option<i64>,
    tool: &str,
    args_json: Option<&str>,
) -> Result<HttpResponse, ClientError> {
    let params = call_params(tool, args_json);
    let mut version = current_modern_version(client);
    let resp = send_modern(client, signer, pinned_ts, "tools/call", &params, &version)?;
    let resp = match adopt_retry(client, &resp, &version)? {
        Some(next) => {
            version = next;
            let retried = send_modern(client, signer, pinned_ts, "tools/call", &params, &version)?;
            // A second retry verdict aborts (`adopt_retry` spends the budget
            // once); anything else is the reply.
            match adopt_retry(client, &retried, &version) {
                Ok(_) => retried,
                Err(e) => return Err(e),
            }
        }
        None => resp,
    };
    check_era(client, &resp, Era::Modern);
    Ok(resp)
}

/// One `tools/call` in the legacy era an `Auto` probe resolved: the negotiated
/// version and the session ride on every request, and a `404` built over that
/// session triggers one re-handshake. A `tools/call` is never replayed.
fn legacy_tool_call(
    client: &Client,
    signer: Option<&dyn Signer>,
    pinned_ts: Option<i64>,
    tool: &str,
    args_json: Option<&str>,
) -> Result<HttpResponse, ClientError> {
    legacy_exchange(client, signer, pinned_ts, |version, session| {
        let id = next_id(client);
        let body = Client::build_request_body(id, tool, args_json);
        let mut headers = vec![("MCP-Protocol-Version".to_owned(), version.to_owned())];
        if let Some(session) = session {
            headers.push(("Mcp-Session-Id".to_owned(), session.to_owned()));
        }
        send_body(client, signer, pinned_ts, body, &headers)
    })
}

/// Sends one legacy request and applies the two recovery rules of `C9`: a
/// modern verdict for a legacy request clears the state (so the next call
/// probes again), and a `404` on a request built with a session re-handshakes
/// once. A `tools/call` may have had an effect and is never replayed, so the
/// new session serves the next call only. Both rules apply to a session an
/// `Auto` probe established; an explicitly legacy client has neither.
fn legacy_exchange<F>(
    client: &Client,
    signer: Option<&dyn Signer>,
    pinned_ts: Option<i64>,
    send: F,
) -> Result<HttpResponse, ClientError>
where
    F: Fn(&str, Option<&str>) -> Result<HttpResponse, ClientError>,
{
    let Some((version, session)) = legacy_state(client) else {
        return Err(ClientError::Client(
            "jack client: era: the legacy era was not negotiated".to_owned(),
        ));
    };
    let resp = send(&version, session.as_deref())?;
    if !is_success(resp.status) && detect(&resp).era == Some(Era::Modern) {
        // A modern error for a legacy request: the cached decision is wrong.
        clear(client);
        return Ok(resp);
    }
    if resp.status != 404 {
        return Ok(resp);
    }
    let Some(captured) = session else {
        return Ok(resp);
    };
    recover_session(client, signer, pinned_ts, &captured)?;
    Ok(resp)
}

/// Re-handshakes ONCE after a `404` answered a request built with `captured`,
/// behind the single-flight guard. The cached session is replaced (or cleared)
/// only when it still equals the captured id, so a late result never touches a
/// newer session.
fn recover_session(
    client: &Client,
    signer: Option<&dyn Signer>,
    pinned_ts: Option<i64>,
    captured: &str,
) -> Result<(), ClientError> {
    let _guard = lock_era(client);
    if cached_session(client).as_deref() != Some(captured) {
        // Another caller already recovered the session.
        return Ok(());
    }
    match handshake(client, signer, pinned_ts) {
        Ok(negotiated) => {
            let mut flow = lock_flow(client);
            if flow.session.as_deref() == Some(captured) {
                flow.era = Some(Era::Legacy);
                flow.version = Some(negotiated.version);
                flow.session = negotiated.session;
                flow.modern_version = None;
            }
            Ok(())
        }
        Err(e) => {
            // The server no longer accepts the session and the re-handshake
            // failed: drop the state so the next call probes again.
            let mut flow = lock_flow(client);
            if flow.session.as_deref() == Some(captured) {
                flow.clear();
            }
            Err(e)
        }
    }
}

/// The result of one accepted `initialize`.
struct Negotiated {
    version: String,
    session: Option<String>,
}

/// Runs the legacy handshake: `initialize` with no `MCP-Protocol-Version`
/// header, then `notifications/initialized` carrying the negotiated version and
/// the session id. Nothing is cached here; the caller stores the result
/// atomically after the notification was sent.
fn handshake(
    client: &Client,
    signer: Option<&dyn Signer>,
    pinned_ts: Option<i64>,
) -> Result<Negotiated, ClientError> {
    let id = next_id(client);
    let params = format!(
        "{{\"protocolVersion\":{},\"capabilities\":{{}},\"clientInfo\":{{\"name\":{},\"version\":{}}}}}",
        json_string(LEGACY_VERSION),
        json_string(IMPLEMENTATION_NAME),
        json_string(IMPLEMENTATION_VERSION)
    );
    let resp = send_rpc(
        client,
        signer,
        pinned_ts,
        Some(id),
        "initialize",
        &params,
        &[],
    )?;
    let negotiated = accept_initialize(&resp, id)?;

    let mut headers = vec![(
        "MCP-Protocol-Version".to_owned(),
        negotiated.version.clone(),
    )];
    if let Some(session) = &negotiated.session {
        headers.push(("Mcp-Session-Id".to_owned(), session.clone()));
    }
    send_rpc(
        client,
        signer,
        pinned_ts,
        None,
        "notifications/initialized",
        "{}",
        &headers,
    )?;
    Ok(negotiated)
}

/// Accepts an `initialize` reply only when it is the exact JSON-RPC answer this
/// client asked for: an object with `jsonrpc` exactly `"2.0"`, the sent `id`,
/// `result` and no `error`, and a `result.protocolVersion` this client
/// implements.
fn accept_initialize(resp: &HttpResponse, id: i64) -> Result<Negotiated, ClientError> {
    if !is_success(resp.status) {
        return Err(handshake_error(format!(
            "the initialize reply has HTTP status {}",
            resp.status
        )));
    }
    let parsed: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| handshake_error(format!("the reply is not JSON: {e}")))?;
    let Some(members) = parsed.as_object() else {
        return Err(handshake_error("the reply is not a JSON object".to_owned()));
    };
    if members.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(handshake_error(
            "the reply does not carry jsonrpc \"2.0\"".to_owned(),
        ));
    }
    if members.get("id").and_then(Value::as_i64) != Some(id) {
        return Err(handshake_error(
            "the reply id is not the id sent".to_owned(),
        ));
    }
    let result = match (members.get("result"), members.get("error")) {
        (Some(result), None) => result,
        (_, Some(_)) => {
            return Err(handshake_error(
                "the reply carries an error instead of a result".to_owned(),
            ))
        }
        _ => {
            return Err(handshake_error(
                "the reply has neither result nor error".to_owned(),
            ))
        }
    };
    let Some(result) = result.as_object() else {
        return Err(handshake_error("result is not a JSON object".to_owned()));
    };
    let Some(version) = result.get("protocolVersion").and_then(Value::as_str) else {
        return Err(handshake_error(
            "result.protocolVersion is not a string".to_owned(),
        ));
    };
    if !IMPLEMENTED_VERSIONS.contains(&version) {
        return Err(handshake_error(format!(
            "result.protocolVersion {version} is not an implemented version"
        )));
    }
    Ok(Negotiated {
        version: version.to_owned(),
        session: resp.header("Mcp-Session-Id").map(str::to_owned),
    })
}

/// Builds a modern request's `params` text (with `_meta` and the client info)
/// and its mirror headers in `C2` order. Works for any method, not only
/// `tools/call`.
pub(crate) fn build_modern_parts(
    method: &str,
    params: &Value,
    version: &str,
) -> Result<(String, Vec<(String, String)>), ClientError> {
    let mirrors = build_mirrors(version, method, params)
        .map_err(|e| ClientError::Client(format!("jack client: {e}")))?;
    let mut meta = mirrors.meta;
    add_client_info(&mut meta, IMPLEMENTATION_NAME, IMPLEMENTATION_VERSION);
    let mut members = match params {
        Value::Object(members) => members.clone(),
        _ => Map::new(),
    };
    members.insert("_meta".to_owned(), meta);
    let text = serde_json::to_string(&Value::Object(members))
        .map_err(|e| ClientError::Client(format!("jack client: marshal params: {e}")))?;
    Ok((text, mirrors.headers))
}

/// The one internal request sender: builds
/// `{"jsonrpc":"2.0","id":N,"method":M,"params":P}` (a notification variant
/// carries no `id`), appends `extra_headers` after `Content-Type`, signs and
/// verifies the round trip and returns the verified response. `Ok` covers a
/// verified non-2xx answer; `Err` means the answer was not verified.
#[allow(clippy::too_many_arguments)]
fn send_rpc(
    client: &Client,
    signer: Option<&dyn Signer>,
    pinned_ts: Option<i64>,
    id: Option<i64>,
    method: &str,
    params_json: &str,
    extra_headers: &[(String, String)],
) -> Result<HttpResponse, ClientError> {
    let method = json_string(method);
    let body = match id {
        Some(id) => format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":{method},\"params\":{params_json}}}"
        ),
        None => format!("{{\"jsonrpc\":\"2.0\",\"method\":{method},\"params\":{params_json}}}"),
    };
    send_body(client, signer, pinned_ts, body, extra_headers)
}

/// Puts one already-built body on the wire: `Content-Type` first, then
/// `extra_headers`, signed and verified.
fn send_body(
    client: &Client,
    signer: Option<&dyn Signer>,
    pinned_ts: Option<i64>,
    body: String,
    extra_headers: &[(String, String)],
) -> Result<HttpResponse, ClientError> {
    let mut headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
    headers.extend(extra_headers.iter().cloned());
    let req = HttpRequest {
        method: "POST".to_owned(),
        url: client.base_url.clone(),
        headers,
        body: body.into_bytes(),
    };
    Ok(client
        .transport
        .round_trip_as(signer.unwrap_or(client.signer.as_ref()), pinned_ts, req)?)
}

/// Sends one modern request for any method: `_meta` plus the mirror headers.
fn send_modern(
    client: &Client,
    signer: Option<&dyn Signer>,
    pinned_ts: Option<i64>,
    method: &str,
    params: &Value,
    version: &str,
) -> Result<HttpResponse, ClientError> {
    let (params_text, headers) = build_modern_parts(method, params, version)?;
    let id = next_id(client);
    send_rpc(
        client,
        signer,
        pinned_ts,
        Some(id),
        method,
        &params_text,
        &headers,
    )
}

/// The `params` of a `tools/call`: the target name and its arguments.
fn call_params(tool: &str, args_json: Option<&str>) -> Value {
    let args: Value = serde_json::from_str(args_json.unwrap_or("{}"))
        .unwrap_or_else(|_| Value::Object(Map::new()));
    let mut params = Map::new();
    params.insert("name".to_owned(), Value::String(tool.to_owned()));
    params.insert("arguments".to_owned(), args);
    Value::Object(params)
}

/// Maps a verified reply: a non-2xx JSON-RPC error object with a numeric code
/// becomes [`ClientError::Rpc`] carrying that code ([`ClientError::reply_error`]
/// reconstructs the typed [`ReplyError`] view), Jack's legacy string-code
/// envelope the [`ClientError::Http`] fallback, and a 2xx `tools/call` result
/// its structuredContent.
fn map_tool_reply(resp: HttpResponse) -> Result<Value, ClientError> {
    if !is_success(resp.status) {
        if let Some(reply) = ReplyError::parse(resp.status, &resp.body) {
            return Err(ClientError::Rpc(RpcError {
                code: reply.code,
                message: reply.message,
                data: reply.data,
            }));
        }
        let (code, message) = parse_error_body(&resp.body);
        return Err(ClientError::Http(HttpError {
            status: resp.status,
            code,
            message,
        }));
    }
    crate::client::rpc::decode_tool_result(&resp.body)
}

/// The era detection of one verified response (`C9`), against the versions
/// this client implements.
fn detect(resp: &HttpResponse) -> EraDetection {
    detect_era(
        &VerifiedResponse {
            verified: true,
            status: resp.status,
            body: &resp.body,
        },
        &[MODERN_MIN],
    )
}

/// Applies the one `-32022` retry budget to a verified reply. `Ok(Some(v))`
/// adopted `v` (the caller resends with it), `Ok(None)` means the reply is not
/// a `-32022` with a usable supported list, and `Err` means the budget is
/// spent (the version is never adopted).
fn adopt_retry(
    client: &Client,
    resp: &HttpResponse,
    attempted: &str,
) -> Result<Option<String>, ClientError> {
    let Some(supported) = supported_versions(resp) else {
        return Ok(None);
    };
    let mut flow = lock_flow(client);
    if flow.retried {
        return Err(budget_spent_error());
    }
    let Some(next) = first_implemented(&supported, attempted) else {
        return Ok(None);
    };
    // Budget checked and spent BEFORE the version is adopted.
    flow.retried = true;
    flow.modern_version = Some(next.clone());
    Ok(Some(next))
}

/// The `error.data.supported` list of a verified `-32022` reply: usable only
/// when every element is a string (spec 04 `C9`).
fn supported_versions(resp: &HttpResponse) -> Option<Vec<String>> {
    let reply = ReplyError::parse(resp.status, &resp.body)?;
    if reply.code != VERSION_MISMATCH {
        return None;
    }
    let versions = reply.data.as_ref()?.get("supported")?.as_array()?;
    if !versions.iter().all(Value::is_string) {
        return None;
    }
    Some(
        versions
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
    )
}

/// The first version of a `supported` list that this client implements and
/// that differs from the version just attempted, in the server's order.
fn first_implemented(supported: &[String], attempted: &str) -> Option<String> {
    supported
        .iter()
        .find(|version| {
            version.as_str() != attempted && IMPLEMENTED_VERSIONS.contains(&version.as_str())
        })
        .cloned()
}

/// Clears the cached era when a reply of `expected` era proves the other one
/// (spec 04 `C9`: the cached assumption failed, so the next call probes).
fn check_era(client: &Client, resp: &HttpResponse, expected: Era) {
    if is_success(resp.status) {
        return;
    }
    if let Some(era) = detect(resp).era {
        if era != expected {
            clear(client);
        }
    }
}

/// Caches the modern decision with the version that proved it.
fn cache_modern(client: &Client, version: &str) {
    let mut flow = lock_flow(client);
    flow.era = Some(Era::Modern);
    flow.modern_version = Some(version.to_owned());
}

/// Caches the legacy decision, its negotiated version and session atomically.
fn store_legacy(client: &Client, negotiated: Negotiated) {
    let mut flow = lock_flow(client);
    flow.era = Some(Era::Legacy);
    flow.version = Some(negotiated.version);
    flow.session = negotiated.session;
    flow.modern_version = None;
}

/// Drops the whole flow state.
fn clear(client: &Client) {
    lock_flow(client).clear();
}

/// The cached era, if one was proved.
fn cached_era(client: &Client) -> Option<Era> {
    lock_flow(client).era
}

/// The cached legacy session, if any.
fn cached_session(client: &Client) -> Option<String> {
    lock_flow(client).session.clone()
}

/// The negotiated legacy version and session, when the legacy era is resolved.
fn legacy_state(client: &Client) -> Option<(String, Option<String>)> {
    let flow = lock_flow(client);
    match (flow.era, flow.version.clone()) {
        (Some(Era::Legacy), Some(version)) => Some((version, flow.session.clone())),
        _ => None,
    }
}

/// The version modern requests carry.
fn current_modern_version(client: &Client) -> String {
    lock_flow(client)
        .modern_version
        .clone()
        .unwrap_or_else(|| MODERN_MIN.to_owned())
}

/// The next JSON-RPC request id (starting at 1).
fn next_id(client: &Client) -> i64 {
    client.next_id.fetch_add(1, Ordering::Relaxed) + 1
}

/// The flow-state lock, recovering from a poisoned mutex: every write is an
/// assignment of plain values with no cross-invariant.
fn lock_flow(client: &Client) -> MutexGuard<'_, FlowState> {
    client
        .flow
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The single-flight guard, recovering from a poisoned mutex; the guard holds
/// no data.
fn lock_era(client: &Client) -> MutexGuard<'_, ()> {
    client
        .era_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Reports whether `status` is a 2xx.
fn is_success(status: u16) -> bool {
    (200..=299).contains(&status)
}

/// A JSON string literal; serialization of a `&str` cannot fail.
fn json_string(text: &str) -> String {
    serde_json::to_string(text).expect("string serialization is infallible")
}

/// The clear failure of a `-32022` reply the client cannot answer.
fn no_overlap_error() -> ClientError {
    ClientError::Client(
        "jack client: era: unsupported_version_no_overlap (the server implements no protocol version this client can use)".to_owned(),
    )
}

/// The clear failure of a second `-32022` verdict: the budget is one.
fn budget_spent_error() -> ClientError {
    ClientError::Client(
        "jack client: era: unsupported_version_no_overlap (the single -32022 version retry is already spent)".to_owned(),
    )
}

/// The clear failure of a verified probe reply that proves no era.
fn no_signal_error(reason: Option<EraReason>) -> ClientError {
    let reason = reason
        .map(|reason| reason.as_str())
        .unwrap_or("no_era_signal");
    ClientError::Client(format!(
        "jack client: era: the probe response proves no era ({reason})"
    ))
}

/// A rejected `initialize` reply.
fn handshake_error(detail: String) -> ClientError {
    ClientError::Client(format!(
        "jack client: initialize handshake failed: {detail}"
    ))
}

#[cfg(test)]
mod tests;
