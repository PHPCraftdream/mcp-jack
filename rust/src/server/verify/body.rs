//! Body classification (spec 02 section 2, spec 04 section 4): the JSON-RPC
//! shape rules the verifier applies to a `POST` body.
//!
//! [`classify_body`] is a rejection-first scan: [`unacceptable_body`] reads the
//! raw bytes once (string escapes, nesting depth, duplicate object member
//! names) and the member decisions run on the parsed map afterwards.

use std::collections::HashSet;

use serde_json::value::RawValue;

/// Request or client answer (Go: kindRequest / kindResponse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MessageKind {
    /// A request or a notification.
    Request,
    /// A client answer to a server-initiated request.
    Response,
}

/// The part of a JSON-RPC object the verifier needs (Go: rpcMessage).
#[derive(Debug, Clone)]
pub(super) struct RpcMessage {
    /// Request or client answer.
    pub(super) kind: MessageKind,
    /// id member as sent (exact raw text); None when absent.
    pub(super) id: Option<String>,
    /// method name; empty for responses.
    pub(super) method: String,
    /// tools/call tool name; None when absent or not a string.
    pub(super) tool: Option<String>,
    /// params.arguments as sent; None only when the member is absent.
    pub(super) arguments: Option<Box<RawValue>>,
}

/// Body members as sent: a map type only accepts a JSON object (spec 02
/// section 4: the body "MUST be a single UTF-8 JSON-RPC 2.0 object"; arrays,
/// including batch arrays and positional representations, and scalars are
/// invalid). Duplicate names never reach it: `unacceptable_body` rejects them
/// first. A derived struct would also deserialize from arrays positionally.
pub(super) type RawMembers = std::collections::HashMap<String, Box<RawValue>>;

/// Returns Some only when the raw JSON text parses to a JSON string
/// (mirrors Go jsonString: null, numbers, bools are all None).
pub(super) fn raw_as_string(value: &RawValue) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(value.get())
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_owned()))
}

/// The maximum nesting depth of arrays and objects the body may reach
/// (spec 02 section 4 step 2).
const MAX_BODY_DEPTH: usize = 128;

/// Reports whether the body text is unacceptable before parsing (spec 02
/// section 4 step 2): a \uXXXX string escape that does not form a Unicode
/// scalar value (a lone or unpaired surrogate), or nesting deeper than
/// MAX_BODY_DEPTH levels of arrays and objects, or an object with two members
/// of the same name (compared after unescaping, exact). One byte pass, no
/// recursion, memory bounded by the names of the open objects, so the verdict
/// never depends on the JSON library's own limits (RawValue capture scanning
/// bypasses serde_json's recursion limit and a lone surrogate would otherwise
/// only fail where serde_json materializes a value).
fn unacceptable_body(body: &[u8]) -> bool {
    // One frame per open container; Some(names) for an object.
    let mut stack: Vec<Option<HashSet<String>>> = Vec::new();
    let mut expect_key = false;
    let mut i = 0;
    while i < body.len() {
        match body[i] {
            b'"' => {
                let collect = expect_key && matches!(stack.last(), Some(Some(_)));
                let Some((end, name)) = scan_string(body, i + 1, collect) else {
                    return true;
                };
                i = end;
                if collect {
                    expect_key = false;
                    if let Some(Some(names)) = stack.last_mut() {
                        if !names.insert(name) {
                            return true; // duplicate member name
                        }
                    }
                }
                continue;
            }
            b'{' | b'[' => {
                if stack.len() >= MAX_BODY_DEPTH {
                    return true;
                }
                let is_object = body[i] == b'{';
                stack.push(is_object.then(HashSet::new));
                expect_key = is_object;
            }
            b'}' | b']' => {
                stack.pop();
                expect_key = false;
            }
            b',' => expect_key = matches!(stack.last(), Some(Some(_))),
            _ => {}
        }
        i += 1;
    }
    false
}

/// Scans one string body starting after its opening quote. Returns the index
/// after the closing quote and, when `collect` is set, the unescaped text;
/// None when a \uXXXX escape is not a Unicode scalar value (lone surrogate)
/// or the text ends inside an escape.
fn scan_string(body: &[u8], start: usize, collect: bool) -> Option<(usize, String)> {
    let mut out: Vec<u8> = Vec::new();
    let mut i = start;
    while i < body.len() {
        let c = body[i];
        match c {
            b'"' => return Some((i + 1, String::from_utf8_lossy(&out).into_owned())),
            b'\\' => {
                let esc = *body.get(i + 1)?;
                if esc != b'u' {
                    if collect {
                        out.push(simple_escape(esc));
                    }
                    i += 2; // two-byte escape; an escaped backslash keeps the string going
                    continue;
                }
                if i + 6 > body.len() {
                    return None;
                }
                let Some(v) = hex4(&body[i + 2..i + 6]) else {
                    i += 2; // not a \uXXXX escape: invalid JSON, the parser rejects it
                    continue;
                };
                if (0xDC00..=0xDFFF).contains(&v) {
                    return None; // lone low surrogate
                }
                if !(0xD800..=0xDBFF).contains(&v) {
                    push_scalar(&mut out, collect, v);
                    i += 6; // ordinary \uXXXX escape
                    continue;
                }
                // A high surrogate must be followed immediately by \uDC00..\uDFFF.
                let low = low_surrogate_at(body, i + 6)?;
                push_scalar(
                    &mut out,
                    collect,
                    0x10000 + ((v - 0xD800) << 10) + (low - 0xDC00),
                );
                i += 12;
            }
            _ => {
                if collect {
                    out.push(c);
                }
                i += 1;
            }
        }
    }
    None // unterminated string: invalid JSON, the parser rejects it anyway
}

/// Reads a `\uDC00..\uDFFF` escape starting exactly at `at`, or None.
fn low_surrogate_at(body: &[u8], at: usize) -> Option<u32> {
    let escape = body.get(at..at + 6)?;
    if escape[0] != b'\\' || escape[1] != b'u' {
        return None;
    }
    hex4(&escape[2..]).filter(|low| (0xDC00..=0xDFFF).contains(low))
}

/// Maps the character after a backslash to the byte it stands for; an
/// invalid escape is kept as is (the parser rejects the body later).
fn simple_escape(esc: u8) -> u8 {
    match esc {
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        b'b' => 0x08,
        b'f' => 0x0C,
        other => other,
    }
}

/// Appends the UTF-8 form of a scalar value when names are being collected.
fn push_scalar(out: &mut Vec<u8>, collect: bool, scalar: u32) {
    if !collect {
        return;
    }
    if let Some(ch) = char::from_u32(scalar) {
        let mut buf = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    }
}

/// Parses exactly four ASCII hex digits, or None.
fn hex4(b: &[u8]) -> Option<u32> {
    if b.len() != 4 {
        return None;
    }
    let mut v: u32 = 0;
    for &c in b {
        let d = match c {
            b'0'..=b'9' => u32::from(c - b'0'),
            b'a'..=b'f' => u32::from(c - b'a') + 10,
            b'A'..=b'F' => u32::from(c - b'A') + 10,
            _ => return None,
        };
        v = v << 4 | d;
    }
    Some(v)
}

/// Implements the body rules of spec 02 section 4: the body must be a single
/// UTF-8 JSON-RPC 2.0 OBJECT. UTF-8 is validated before any parse. Member
/// decisions, each tied to the spec text:
/// - `jsonrpc` absent, null, or not exactly "2.0" -> None: section 4 makes "a
///   missing or wrong `jsonrpc` member" a 400 invalid_request; a null member
///   is a wrong one (Go `jsonString` and the JS `msg.jsonrpc !== '2.0'` agree).
/// - `id`, `result`, `error` are judged by PRESENCE: `"id": null` and a null
///   result/error count as present (Go `_, has := m[k]`, JS `'k' in msg`;
///   section 4 defines a response as "no `method`, an `id`, and exactly one of
///   `result` or `error"").
/// - a PRESENT `method` must be a string (section 4: "a string `method`");
///   null is present-but-wrong and never falls back to the response shape
///   (Go `jsonString(rawMethod)` fails before the response branch is reached).
/// - for tools/call, `params` must be an object carrying a string `name`
///   (section 4: "`params.name` MUST be a string, otherwise 400
///   invalid_request"); absent, null, array and scalar params all fail.
/// - `arguments` is carried as exact raw text when present (a null stays
///   Some("null")), None only when absent, so native handlers can judge
///   integer arguments on their JSON text (spec 03 section 3).
pub(super) fn classify_body(body: &[u8]) -> Option<RpcMessage> {
    let text = std::str::from_utf8(body).ok()?;
    if unacceptable_body(body) {
        return None;
    }
    let members: RawMembers = serde_json::from_str(text).ok()?;
    if members
        .get("jsonrpc")
        .and_then(|v| raw_as_string(v))
        .as_deref()
        != Some("2.0")
    {
        return None;
    }

    // id: exact raw text when present (null stays "null").
    let id = members.get("id").map(|v| v.get().to_owned());

    // Method absent -> only a response shape can match. A PRESENT-but-null
    // method does NOT take this branch (the map keeps Some).
    let Some(method_raw) = members.get("method") else {
        let is_response =
            id.is_some() && members.contains_key("result") != members.contains_key("error");
        return is_response.then(|| RpcMessage {
            kind: MessageKind::Response,
            id,
            method: String::new(),
            tool: None,
            arguments: None,
        });
    };
    let method = raw_as_string(method_raw)?;

    let mut msg = RpcMessage {
        kind: MessageKind::Request,
        id,
        method: method.clone(),
        tool: None,
        arguments: None,
    };
    if method == "tools/call" {
        let params_raw = members.get("params")?;
        let params: RawMembers = serde_json::from_str(params_raw.get()).ok()?;
        msg.tool = Some(params.get("name").and_then(|v| raw_as_string(v))?);
        msg.arguments = params.get("arguments").cloned();
    }
    Some(msg)
}
