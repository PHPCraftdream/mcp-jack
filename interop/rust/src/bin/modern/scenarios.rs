//! The request sequences of interop/modern/contract.md 4.4 and the C9 era
//! flow of 4.3, with exactly the requests and the step names the matrix pins:
//! nothing more, nothing less.

use std::cmp::Ordering;

use serde_json::{json, Value};

use mcp_jack::client::modern::{
    add_client_info, build_mirrors, detect_era, project_arguments, EraAction, EraDetection,
    EraReason, MirrorError, ProjectionError, ToolCatalog, VerifiedResponse,
};
use mcp_jack::modern::{compare_versions, Era, MODERN_MIN};

use super::client::{require_ok, Ctx, EraArg, Halt, Performed, Request};

/// The modern era this client speaks (contract 4.1).
const MODERN_VERSION: &str = "2026-07-28";
/// The legacy version a C9 fallback handshakes at (contract 4.3).
const LEGACY_VERSION: &str = "2025-11-25";
/// Contract 4.3: the versions this client implements, in the order the retry
/// rule falls back through. ISO dates compare correctly as strings.
const IMPLEMENTED_VERSIONS: [&str; 3] = ["2026-07-28", "2025-11-25", "2025-06-18"];
/// Contract 5: the client identity every `_meta` and handshake carries.
const CLIENT_NAME: &str = "mcp-jack-interop-modern-client";
const CLIENT_VERSION: &str = "1.0.0";
/// Contract 4.3: the client's own code when no version overlaps, and the one
/// for a probe that proved no era at all.
const NO_OVERLAP: &str = "unsupported_version_no_overlap";
const UNSUPPORTED_VERSION: &str = "unsupported_version";
/// Contract 4.4: the one application tool of the matrix, and the argument
/// every one of its calls sends.
const TOOL: &str = "region.echo";
const REGION_ARGUMENT: &str = "us-west1";
/// spec 04 C7: the protocol-native identity tool, answered by the SDK before
/// the wrapped handler (`native-era-shape`).
const TOOL_WHOAMI: &str = "jack.whoami";
/// Contract 4.4 (`refusal-id-forms`): the mirror S6 needs and these requests
/// deliberately omit.
const NAME_HEADER: &str = "Mcp-Name";
/// Contract 5: the `params` member carrying the request metadata.
const META_MEMBER: &str = "_meta";
/// Contract 5: `notifications/initialized` has no id (contract 4.3).
const INITIALIZED_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#;

/// Contract 4.4: the complete request sequence of `--scenario`, in order.
pub fn run(ctx: &Ctx) -> Result<(), Halt> {
    match ctx.scenario.as_str() {
        "modern-discover" => {
            discover(ctx, "discover", MODERN_VERSION)?;
            Ok(())
        }
        "modern-call-projection" => call_projection(ctx),
        "modern-mismatch-name" => mismatch_name(ctx),
        "modern-repeated-version" => single_call(ctx),
        "modern-session-stripped" => single_call(ctx),
        "modern-get-405" => refusal(ctx, "get", "GET"),
        "modern-head-405" => refusal(ctx, "head", "HEAD"),
        "era-auto-modern" => auto(ctx),
        "era-auto-legacy" => auto(ctx),
        "era-retry-version" => auto(ctx),
        "legacy-both-parity" => {
            legacy_tool_call(ctx, "call", TOOL, json!({"region": REGION_ARGUMENT}), &[])?;
            Ok(())
        }
        "native-era-shape" => whoami(ctx),
        "refusal-id-forms" => id_forms(ctx),
        other => Err(Halt::Fatal(format!("unsupported scenario '{other}'"))),
    }
}

/// `modern-call-projection`: `tools/list`, then the projected `tools/call`
/// whose schema comes from the LIVE list (contract 4.4).
fn call_projection(ctx: &Ctx) -> Result<(), Halt> {
    let list = tools_list(ctx)?;
    require_ok(&list)?;
    // `ToolCatalog` reads the `tools` array of a `result` object, so it is
    // handed the envelope's `result` member, not the whole envelope.
    let result = list
        .json
        .as_ref()
        .and_then(|json| json.get("result"))
        .cloned()
        .unwrap_or(Value::Null);
    let catalog = ToolCatalog::from_tools_list(&result);
    let arguments = json!({"region": REGION_ARGUMENT});
    let projection = catalog.project(TOOL, &arguments).map_err(projection_halt)?;
    let params = json!({"name": TOOL, "arguments": arguments});
    let request = modern_request(
        ctx,
        "call",
        MODERN_VERSION,
        "tools/call",
        params,
        projection,
    )?;
    ctx.send(request)?;
    Ok(())
}

/// `modern-mismatch-name`: the projected call at nonce index 0, then its exact
/// bytes, signature and nonce again as a separate step (contract 4.4).
fn mismatch_name(ctx: &Ctx) -> Result<(), Halt> {
    let first = modern_region_call(ctx, "call", MODERN_VERSION)?;
    ctx.replay("replay", &first)?;
    Ok(())
}

/// The single modern `tools/call` of `modern-repeated-version` and
/// `modern-session-stripped` (contract 4.4).
fn single_call(ctx: &Ctx) -> Result<(), Halt> {
    modern_region_call(ctx, "call", MODERN_VERSION)?;
    Ok(())
}

/// `modern-get-405` and `modern-head-405`: an empty, signed body whose only
/// header is `MCP-Protocol-Version` (contract 4.4).
fn refusal(ctx: &Ctx, name: &'static str, method: &'static str) -> Result<(), Halt> {
    let headers = vec![("MCP-Protocol-Version".to_owned(), MODERN_VERSION.to_owned())];
    ctx.send(request(
        name,
        method,
        None,
        Era::Modern,
        headers,
        Vec::new(),
    ))?;
    Ok(())
}

/// `native-era-shape`: `jack.whoami` in the era `--era` passes; `auto` reads
/// as modern, the only era with a shaped native result (contract 4.4).
fn whoami(ctx: &Ctx) -> Result<(), Halt> {
    if ctx.era == EraArg::Legacy {
        legacy_tool_call(ctx, "whoami", TOOL_WHOAMI, json!({}), &[])?;
        return Ok(());
    }
    // `jack.whoami` declares no annotated argument, so nothing projects.
    let params = json!({"name": TOOL_WHOAMI, "arguments": {}});
    let request = modern_request(
        ctx,
        "whoami",
        MODERN_VERSION,
        "tools/call",
        params,
        Vec::new(),
    )?;
    ctx.send(request)?;
    Ok(())
}

/// `refusal-id-forms`: four modern `tools/call` requests whose ids go out
/// verbatim, each carrying the modern mirrors MINUS `Mcp-Name` and no
/// projection, so S6 refuses every one of them (contract 4.4).
fn id_forms(ctx: &Ctx) -> Result<(), Halt> {
    for (name, id_text) in [
        ("id-string", "\"abc\""),
        ("id-integer", "7"),
        ("id-null", "null"),
        ("id-fractional", "1.5"),
    ] {
        unnamed_call(ctx, name, id_text)?;
    }
    Ok(())
}

/// One `refusal-id-forms` request (contract 4.4).
fn unnamed_call(ctx: &Ctx, name: &'static str, id_text: &str) -> Result<(), Halt> {
    let params = json!({"name": TOOL, "arguments": {"region": REGION_ARGUMENT}});
    let mut built = build_mirrors(MODERN_VERSION, "tools/call", &params).map_err(mirror_halt)?;
    built.headers.retain(|(header, _)| header != NAME_HEADER);
    add_client_info(&mut built.meta, CLIENT_NAME, CLIENT_VERSION);
    let mut params = params;
    let Some(members) = params.as_object_mut() else {
        return Err(Halt::Fatal(
            "a modern params member must be a JSON object".to_owned(),
        ));
    };
    members.insert(META_MEMBER.to_owned(), built.meta);
    ctx.send(request(
        name,
        "POST",
        Some("tools/call"),
        Era::Modern,
        post_headers(&built.headers),
        request_body(id_text, "tools/call", Some(&params)),
    ))?;
    Ok(())
}

/// Contract 4.3 (C9): one probe decides the era, then the operation runs in
/// it. Every `--era auto` scenario takes the identical path, so the retry rule
/// below is complete for all three of them.
fn auto(ctx: &Ctx) -> Result<(), Halt> {
    let probe = discover(ctx, "probe", &ctx.probe_version)?;
    let detection = detect(&probe);
    match detection.action {
        EraAction::StayModern => settle(ctx, Some(Era::Modern), MODERN_VERSION),
        EraAction::FallbackInitialize => settle(ctx, Some(Era::Legacy), LEGACY_VERSION),
        EraAction::RetryWithSupported => retry_flow(ctx, &detection),
        // The detection's era must not carry an abort into an operation.
        EraAction::Abort => abort(&detection),
    }
}

/// Contract 4.3: the single retry, with the first mutually implemented
/// version that differs from the one just attempted.
fn retry_flow(ctx: &Ctx, detection: &EraDetection) -> Result<(), Halt> {
    let Some(picked) = detection
        .supported
        .iter()
        .find(|version| version.as_str() != ctx.probe_version)
        .cloned()
    else {
        // No mutual version means no overlap, with no further request.
        return Err(Halt::Rejected(NO_OVERLAP));
    };
    if compare_versions(&picked, MODERN_MIN) == Ordering::Less {
        // A legacy pick runs the handshake at that version, then the operation.
        return settle(ctx, Some(Era::Legacy), &picked);
    }
    // A modern pick is retried with a NEW `server/discover` at that version.
    let retried = discover(ctx, "probe-retry", &picked)?;
    let again = detect(&retried);
    match again.action {
        EraAction::StayModern => settle(ctx, Some(Era::Modern), &picked),
        EraAction::FallbackInitialize => settle(ctx, Some(Era::Legacy), LEGACY_VERSION),
        // A second `-32022` is the end: there is never a second retry.
        EraAction::RetryWithSupported => Err(Halt::Rejected(NO_OVERLAP)),
        EraAction::Abort => abort(&again),
    }
}

/// Contract 4.3: an abort ends the run without any further request, in
/// whatever era the detection carries. Only a `-32022` without a mutual
/// version is this client's own no-overlap code; the unverified, unsigned and
/// malformed families are a plain unsupported version.
fn abort(detection: &EraDetection) -> Result<(), Halt> {
    match detection.reason {
        Some(EraReason::UnsupportedVersionNoOverlap) => Err(Halt::Rejected(NO_OVERLAP)),
        _ => Err(Halt::ClientError(UNSUPPORTED_VERSION.to_owned())),
    }
}

/// Contract 4.3: run the operation in the era the probe settled on, at
/// `version` for a modern request and for a handshake alike.
fn settle(ctx: &Ctx, era: Option<Era>, version: &str) -> Result<(), Halt> {
    match era {
        Some(Era::Modern) => {
            modern_region_call(ctx, "call", version)?;
            Ok(())
        }
        Some(Era::Legacy) => legacy_operation(ctx, version),
        // No era was proven, which contract 4.3 makes a client failure.
        None => Err(Halt::ClientError(UNSUPPORTED_VERSION.to_owned())),
    }
}

/// Contract 4.3: the era decision uses the VERIFIED response only. A refused
/// response never reaches this layer, but an allowed unsigned 401 does, and it
/// still arrives unverified — `detect_era` then yields `Abort(Unverified)` and
/// `abort` reports the `client_error` result line.
fn detect(performed: &Performed) -> EraDetection {
    detect_era(
        &VerifiedResponse {
            verified: performed.verified,
            status: performed.status,
            body: performed.body(),
        },
        &IMPLEMENTED_VERSIONS,
    )
}

/// Contract 4.4 and 5: `server/discover` posts `params` that carry only
/// `_meta`, in both the probe and the retry.
fn discover(ctx: &Ctx, name: &'static str, version: &str) -> Result<Performed, Halt> {
    let request = modern_request(ctx, name, version, "server/discover", json!({}), Vec::new())?;
    ctx.send(request)
}

/// Contract 4.4: the modern `tools/call` of `region.echo` with
/// `{"region":"us-west1"}` and its `Mcp-Param-Region` projection.
fn modern_region_call(ctx: &Ctx, name: &'static str, version: &str) -> Result<Performed, Halt> {
    let arguments = json!({"region": REGION_ARGUMENT});
    let served = served_tools_list();
    let projection = project_arguments(&served["tools"][0]["inputSchema"], &arguments)
        .map_err(projection_halt)?;
    let params = json!({"name": TOOL, "arguments": arguments});
    let request = modern_request(ctx, name, version, "tools/call", params, projection)?;
    ctx.send(request)
}

/// `modern-call-projection` step 1 (contract 4.4).
fn tools_list(ctx: &Ctx) -> Result<Performed, Halt> {
    let request = modern_request(
        ctx,
        "list",
        MODERN_VERSION,
        "tools/list",
        json!({}),
        Vec::new(),
    )?;
    ctx.send(request)
}

/// Builds one modern request (contract 4.1 and 5): the body with
/// `params._meta` (protocol version, empty client capabilities, client info)
/// and the `--json-id` text verbatim, and the headers `Content-Type`, then the
/// `build_mirrors` set in the SDK's order, then the `C6` projection.
fn modern_request(
    ctx: &Ctx,
    name: &'static str,
    version: &str,
    method: &'static str,
    params: Value,
    projection: Vec<(String, String)>,
) -> Result<Request, Halt> {
    // The mirrors read the caller's params, so `_meta` is inserted after them.
    let mut built = build_mirrors(version, method, &params).map_err(mirror_halt)?;
    add_client_info(&mut built.meta, CLIENT_NAME, CLIENT_VERSION);
    let mut params = params;
    let Some(members) = params.as_object_mut() else {
        return Err(Halt::Fatal(
            "a modern params member must be a JSON object".to_owned(),
        ));
    };
    members.insert(META_MEMBER.to_owned(), built.meta);
    let mut extra = built.headers;
    extra.extend(projection);
    Ok(request(
        name,
        "POST",
        Some(method),
        Era::Modern,
        post_headers(&extra),
        request_body(&ctx.json_id, method, Some(&params)),
    ))
}

/// Contract 5: the legacy `tools/call`, with no `_meta` and — after a
/// handshake — only the negotiated version and the session id.
fn legacy_tool_call(
    ctx: &Ctx,
    name: &'static str,
    tool: &str,
    arguments: Value,
    session: &[(String, String)],
) -> Result<Performed, Halt> {
    let params = json!({"name": tool, "arguments": arguments});
    let request = request(
        name,
        "POST",
        Some("tools/call"),
        Era::Legacy,
        post_headers(session),
        request_body(&ctx.json_id, "tools/call", Some(&params)),
    );
    ctx.send(request)
}

/// Contract 4.3: the handshake at `version`, then the legacy operation.
fn legacy_operation(ctx: &Ctx, version: &str) -> Result<(), Halt> {
    let session = legacy_handshake(ctx, version)?;
    legacy_tool_call(
        ctx,
        "call",
        TOOL,
        json!({"region": REGION_ARGUMENT}),
        &session,
    )?;
    Ok(())
}

/// Contract 4.3 legacy fallback: `initialize` with no mirror header at all,
/// then `notifications/initialized` carrying the negotiated version and the
/// session id; returns those two headers for the operation that follows.
fn legacy_handshake(ctx: &Ctx, version: &str) -> Result<Vec<(String, String)>, Halt> {
    let params = json!({
        "protocolVersion": version,
        "capabilities": {},
        "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
    });
    let initialize = ctx.send(request(
        "initialize",
        "POST",
        Some("initialize"),
        Era::Legacy,
        post_headers(&[]),
        request_body(&ctx.json_id, "initialize", Some(&params)),
    ))?;
    require_ok(&initialize)?;
    let negotiated = initialize
        .json
        .as_ref()
        .and_then(|json| json.get("result"))
        .and_then(|result| result.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(version)
        .to_owned();
    let mut session = vec![("MCP-Protocol-Version".to_owned(), negotiated)];
    if let Some(id) = &initialize.session_id {
        session.push(("Mcp-Session-Id".to_owned(), id.clone()));
    }
    let initialized = ctx.send(request(
        "initialized",
        "POST",
        Some("notifications/initialized"),
        Era::Legacy,
        post_headers(&session),
        INITIALIZED_BODY.to_vec(),
    ))?;
    require_ok(&initialized)?;
    Ok(session)
}

/// One request of a sequence, as the report and the wire need it.
fn request(
    name: &'static str,
    method: &'static str,
    jsonrpc_method: Option<&'static str>,
    era: Era,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Request {
    Request {
        name: name.to_owned(),
        method: method.to_owned(),
        jsonrpc_method: jsonrpc_method.map(str::to_owned),
        era,
        headers,
        body,
    }
}

/// Contract 5: a POST carries `Content-Type: application/json` first, then
/// the mirror, projection or session headers in the order given.
fn post_headers(extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
    headers.extend_from_slice(extra);
    headers
}

/// Contract 5: the body with the `--json-id` text inserted verbatim, so `1`,
/// `"abc"`, `7`, `null` and `1.5` all go out exactly as given. Member order is
/// free; the id text is not, so the body is rendered as text.
fn request_body(id_text: &str, method: &str, params: Option<&Value>) -> Vec<u8> {
    let method = serde_json::to_string(method).expect("a string always serializes");
    match params {
        Some(params) => format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id_text},\"method\":{method},\"params\":{}}}",
            serde_json::to_string(params).expect("a JSON value always serializes")
        ),
        None => format!("{{\"jsonrpc\":\"2.0\",\"id\":{id_text},\"method\":{method}}}"),
    }
    .into_bytes()
}

/// Contract 3.4 (d): the `tools/list` result the executable itself serves.
/// A scenario whose sequence has no `tools/list` projects its `region.echo`
/// arguments with this application knowledge instead of a live catalog
/// (contract 4.4).
fn served_tools_list() -> Value {
    json!({
        "tools": [{
            "name": TOOL,
            "inputSchema": {
                "type": "object",
                "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
                "required": ["region"],
            },
        }],
    })
}

/// A body whose mirrors cannot be built cannot be sent at all; unreachable for
/// the fixed bodies of contract 4.4, which all carry a string `params.name`.
fn mirror_halt(error: MirrorError) -> Halt {
    Halt::Fatal(format!("cannot build the modern mirrors: {error}"))
}

/// A refused projection means the request MUST NOT be sent (spec 04 C6);
/// unreachable for the fixed `{"region":"us-west1"}` argument.
fn projection_halt(error: ProjectionError) -> Halt {
    Halt::Fatal(format!("cannot project the call arguments: {error}"))
}
