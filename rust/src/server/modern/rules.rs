//! Server rules `S1`-`S12` of the modern profile (spec 04 section 5): the
//! classification of one already authenticated request.
//!
//! [`classify_request`] mirrors `classifyRequest` of
//! `spec/tools/modern/headers/reference/server.mjs` step for step. The era
//! decision (`S3`) runs first; a legacy-era request is forwarded untouched, no
//! rule of section 5 (`S1` included) may refuse it; every other rule then runs
//! only in the modern era, in table order, and the first failure decides.

use serde_json::{Map, Value};

use super::{
    decide_era, Era, HeaderField, ModernOutcome, ModernRequest, Profile, Refusal, RefusalReason,
    INVALID_BODY_MESSAGE,
};
use crate::modern::{
    decode_header_value, is_field_value, is_session_header, is_version, name_source, NameSource,
    META_VERSION_KEY, TOOLS_CALL_NAME_MESSAGE,
};

/// The three mirror headers `S1` recognises, in lowercase for comparison with
/// a lowercased received name.
const MIRROR_NAMES: [&str; 3] = ["mcp-protocol-version", "mcp-method", "mcp-name"];

/// Prefix of a mirrored argument header `Mcp-Param-{Name}` (spec 04 section 5,
/// `S1` and `S7`); the bare prefix alone is not a recognised header.
const PARAM_PREFIX: &str = "mcp-param-";

/// Which of the three body shapes of spec 02 section 2 the verified bytes
/// hold. A body exists only for a `POST` whose bytes decode to a JSON object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    /// A JSON-RPC request: a string `method` and an `id` member, whatever its
    /// type.
    Request,
    /// A JSON-RPC notification: a string `method` and no `id` member at all.
    Notification,
    /// A client-sent response object: no string `method` member.
    Response,
}

/// The parsed body, borrowed from the parsed JSON object for the call.
struct Body<'v> {
    /// The JSON object the verified bytes decoded to.
    root: &'v Map<String, Value>,
    /// Which body shape it is, decided once.
    kind: BodyKind,
}

impl<'v> Body<'v> {
    /// Classifies a parsed JSON object once (spec 02 section 2): no string
    /// `method` makes it a response object, a string `method` plus an `id`
    /// member makes it a request, and a string `method` without one makes it a
    /// notification.
    fn new(root: &'v Map<String, Value>) -> Self {
        let kind = match root.get("method").and_then(Value::as_str) {
            None => BodyKind::Response,
            Some(_) if has_id_member(root) => BodyKind::Request,
            Some(_) => BodyKind::Notification,
        };
        Self { root, kind }
    }

    /// The body `method` when it is a JSON string.
    fn method(&self) -> Option<&'v str> {
        self.root.get("method").and_then(Value::as_str)
    }

    /// The body `params` when it is a JSON object.
    fn params(&self) -> Option<&'v Map<String, Value>> {
        self.root.get("params").and_then(Value::as_object)
    }

    /// The raw JSON text of the request id (the quoted literal for a string),
    /// and only for a request: a notification or response has no id to echo.
    fn id_text(&self) -> Option<String> {
        if self.kind == BodyKind::Request {
            request_id(self.root)
        } else {
            None
        }
    }

    /// The `_meta` protocol version `M` of a request or notification: the
    /// string `params["_meta"]["io.modelcontextprotocol/protocolVersion"]`. A
    /// root-level `_meta` and a response object never carry a mirror.
    fn meta_version(&self) -> Option<&'v str> {
        if !matches!(self.kind, BodyKind::Request | BodyKind::Notification) {
            return None;
        }
        self.params()?
            .get("_meta")?
            .as_object()?
            .get(META_VERSION_KEY)?
            .as_str()
    }
}

/// Whether the body carries an `id` member at all, which is what makes it a
/// request rather than a notification (spec 04 `S11`: "body with `method`,
/// no `id`"). A `null` or fractional `id` is still a member; `S10` only
/// stops echoing it.
fn has_id_member(root: &Map<String, Value>) -> bool {
    root.contains_key("id")
}

/// The raw JSON text of an acceptable JSON-RPC request `id`: a string or an
/// integer, otherwise `None` (`S10` echoes `null` for every other id).
fn request_id(root: &Map<String, Value>) -> Option<String> {
    let id = root.get("id")?;
    let acceptable = id.is_string() || id.as_i64().is_some() || id.as_u64().is_some();
    acceptable.then(|| id.to_string())
}

/// Parses the verified body bytes once. A body exists only for a `POST` whose
/// bytes decode to a JSON object; a `POST` with any other body has no body
/// here and is refused below, and a non-`POST` request has none at all.
fn parse_body(request: &ModernRequest<'_>) -> Option<Map<String, Value>> {
    if request.method != "POST" {
        return None;
    }
    match serde_json::from_slice::<Value>(request.body) {
        Ok(Value::Object(object)) => Some(object),
        _ => None,
    }
}

/// Builds a signed refusal (`S10`) and keeps the id rule in one place: the raw
/// body id for a request, `null` (rendered by the caller) otherwise.
fn refusal(reason: RefusalReason, id: Option<&str>) -> ModernOutcome {
    ModernOutcome::Refuse(Refusal {
        reason,
        id: id.map(str::to_owned),
    })
}

/// The values of every header named `name` (name compared ASCII
/// case-insensitively), in received order.
fn header_values<'a>(headers: &'a [HeaderField], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
        .collect()
}

/// `S3` for one already authenticated request: the era the engine decides for
/// it, with the `_meta` protocol version of its body when it is a request or
/// notification.
///
/// [`classify_request`] runs the body classification before `S3`, so its era-
/// neutral [`ModernOutcome::ClassificationRefusal`] carries no era. A caller
/// that has to interpret such a refusal (to pick the 0.1.x bytes or the fixed
/// modern message) asks this function with the same request; it is `S3` and
/// nothing else, so it cannot disagree with the era `classify_request` used
/// for a request it forwards.
#[cfg(feature = "http")]
pub(crate) fn request_era(profile: Profile, request: &ModernRequest<'_>) -> Era {
    let parsed = parse_body(request);
    let meta_version = parsed
        .as_ref()
        .map(Body::new)
        .as_ref()
        .and_then(Body::meta_version);
    decide_era(profile, request.headers, meta_version)
}

/// `S3`-`S12` of spec 04 section 5: classifies one already authenticated
/// request and says how the wrapped handler must receive it.
///
/// The caller has authenticated the request (spec 01 section 4 steps 1-8) and
/// classified its body (spec 02 section 2), so the body of a `POST` is an
/// acceptable JSON-RPC object here: the [`INVALID_BODY_MESSAGE`] outcome is
/// unreachable through that caller and is kept only for parity with the
/// reference implementation.
pub fn classify_request(profile: Profile, request: &ModernRequest<'_>) -> ModernOutcome {
    let parsed = parse_body(request);
    let body = parsed.as_ref().map(Body::new);

    // A `tools/call` request or notification without a string `params.name` is
    // refused at body classification, era-neutral and before `S3`, so it never
    // reaches the era decision.
    if let Some(body) = body.as_ref() {
        let is_rpc = matches!(body.kind, BodyKind::Request | BodyKind::Notification);
        let name_is_string = body
            .params()
            .and_then(|params| params.get("name"))
            .is_some_and(Value::is_string);
        if is_rpc && body.method() == Some("tools/call") && !name_is_string {
            return ModernOutcome::ClassificationRefusal {
                message: TOOLS_CALL_NAME_MESSAGE,
            };
        }
    }

    // `S3` runs first and never refuses: `meta_version` is the request or
    // notification mirror `M`, never a root-level `_meta` version.
    let meta_version = body.as_ref().and_then(|body| body.meta_version());
    let era = decide_era(profile, request.headers, meta_version);

    // Legacy era: spec 01 and 02 apply byte-identically and no rule of section
    // 5 runs, `S1` included, so the header list is forwarded unfiltered.
    if era == Era::Legacy {
        return ModernOutcome::Forward {
            era: Era::Legacy,
            headers: request.headers.to_vec(),
        };
    }

    // A `POST` always has a body after spec 02 section 2, which refuses an
    // unacceptable one first: unreachable through the caller.
    if body.is_none() && request.method == "POST" {
        return ModernOutcome::ClassificationRefusal {
            message: INVALID_BODY_MESSAGE,
        };
    }

    let id = body.as_ref().and_then(Body::id_text);
    let refuse = |reason: RefusalReason| refusal(reason, id.as_deref());

    // S1, first half: at most one instance of each mirror header, the second
    // one being `header_repeated` however its name is cased.
    for name in MIRROR_NAMES {
        let count = request
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .count();
        if count > 1 {
            return refuse(RefusalReason::HeaderRepeated);
        }
    }

    // S1, second half: the three mirrors and every recognised
    // `Mcp-Param-{Name}` carry a field-value-syntax value. A header named
    // exactly `Mcp-Param-` has an empty `{Name}` and is not recognised, so it
    // is forwarded like any unknown header.
    for header in request.headers {
        let name = header.name.to_ascii_lowercase();
        let recognised_param = name.starts_with(PARAM_PREFIX) && name.len() > PARAM_PREFIX.len();
        if !MIRROR_NAMES.contains(&name.as_str()) && !recognised_param {
            continue;
        }
        if !is_field_value(&header.value) {
            return refuse(RefusalReason::HeaderValueInvalid);
        }
    }

    // S2: the modern era defines `POST` only, and a non-`POST` request carries
    // no JSON-RPC id.
    if request.method != "POST" {
        return refusal(RefusalReason::MethodNotAllowed, None);
    }

    // S12: a client-sent response object has no mirror obligation; `S1` and
    // `S8` still apply to it.
    if let Some(body) = body.as_ref() {
        if body.kind != BodyKind::Response {
            if let Some(outcome) = check_mirrors(request, body, id.as_deref()) {
                return outcome;
            }
        }
    }

    // S8: every session and resume header is removed before the handler sees
    // the request. S7 and S9 add, rewrite and reorder nothing else: `Mcp-Param-*`
    // and every unknown header keep their name casing, value bytes, order and
    // repetition.
    let headers: Vec<HeaderField> = request
        .headers
        .iter()
        .filter(|h| !is_session_header(&h.name))
        .cloned()
        .collect();
    ModernOutcome::Forward {
        era: Era::Modern,
        headers,
    }
}

/// `S4`-`S6` for a request or notification body, in table order, first failure
/// first: returns the refusal, or `None` when every present mirror agrees.
fn check_mirrors(
    request: &ModernRequest<'_>,
    body: &Body<'_>,
    id: Option<&str>,
) -> Option<ModernOutcome> {
    let is_request = body.kind == BodyKind::Request;
    // A request or notification body always carries a string `method`.
    let method = body.method()?;

    // S4: the `MCP-Protocol-Version` mirror; only the first value is compared.
    let versions = header_values(request.headers, "MCP-Protocol-Version");
    if let Some(header) = versions.first() {
        if !is_version(header) {
            return Some(refusal(RefusalReason::VersionHeaderMalformed, id));
        }
        let Some(meta) = body.meta_version() else {
            return Some(refusal(RefusalReason::VersionMetaMissing, id));
        };
        if *header != meta {
            return Some(refusal(RefusalReason::VersionMismatch, id));
        }
    } else if is_request {
        return Some(refusal(RefusalReason::VersionHeaderMissing, id));
    }

    // S5: the `Mcp-Method` mirror, byte-equal to the body method, so `Tools/Call`
    // is a mismatch.
    let methods = header_values(request.headers, "Mcp-Method");
    if let Some(header) = methods.first() {
        if *header != method {
            return Some(refusal(RefusalReason::MethodHeaderMismatch, id));
        }
    } else if is_request {
        return Some(refusal(RefusalReason::MethodHeaderMissing, id));
    }

    // S6: the `Mcp-Name` mirror of the closed source table; a method without a
    // row must not carry the header.
    let names = header_values(request.headers, "Mcp-Name");
    let Some(source) = name_source(method) else {
        if !names.is_empty() {
            return Some(refusal(RefusalReason::NameHeaderNotApplicable, id));
        }
        return None;
    };
    let field = match source {
        NameSource::Name => "name",
        NameSource::Uri => "uri",
    };
    let Some(value) = body
        .params()
        .and_then(|params| params.get(field))
        .and_then(Value::as_str)
    else {
        return Some(refusal(RefusalReason::NameSourceMissing, id));
    };
    match names.first() {
        None if is_request => Some(refusal(RefusalReason::NameHeaderMissing, id)),
        None => None,
        Some(header) => {
            let Ok(decoded) = decode_header_value(header) else {
                return Some(refusal(RefusalReason::NameHeaderBadEncoding, id));
            };
            if decoded == value {
                None
            } else {
                Some(refusal(RefusalReason::NameHeaderMismatch, id))
            }
        }
    }
}
