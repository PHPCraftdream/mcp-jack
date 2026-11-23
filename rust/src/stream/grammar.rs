//! Header and frame grammar of spec 05 sections 1.1, 1.4 and 2.1-2.18: the
//! `Jack-Auth` open value, both signing strings, the frame fields, the
//! transport-signal template and the `Jack-Accept` opt-in.
//!
//! Everything here is pure. The key, window, cutoff and signature checks of
//! 4.2 steps 4-7 belong to the verifier; this module stops after the grammar
//! of 4.2 steps 1-3. A violation is reported as the [`StreamCode`] the client
//! would terminate with, never as an HTTP status (spec 05 section 4.6).

use super::sse::SseField;
use super::{StreamCode, FRAME_DOMAIN, MAX_SAFE_INTEGER, OPEN_DOMAIN, SIGNAL_METHOD};
use crate::encoding::{body_hash, decode_b64url_fixed};

// Fixed decoded byte lengths of the base64url parameters (spec 05 section 2.2).
const KID_LEN: usize = 32;
const SID_LEN: usize = 16;
const SIG_LEN: usize = 64;

// 2.18: the signalled set is currently exactly `stream_frame_too_large`.
const SIGNALLED_CODES: [StreamCode; 1] = [StreamCode::FrameTooLarge];
const SIGNAL_SUFFIX: &str = "}}";

/// Parsed `Jack-Auth` open value (spec 05 section 2.2); values as sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAuth {
    pub kid: String,
    pub ts: i64,
    pub sid: String,
    pub sig: String,
}

/// Parses the `Jack-Auth` headers of a stream response (4.2 steps 1-3 and
/// 2.2/2.3 only; steps 4-7 belong to the verifier). Missing header is
/// [`StreamCode::MissingAuth`]; more than one value or any grammar/encoding
/// violation is [`StreamCode::MalformedAuth`]; a scheme that is `s` or `v`
/// plus digits other than `s1` is [`StreamCode::UnsupportedVersion`], and that
/// check runs on the raw value before the parameter rules (2.3); any other
/// scheme is [`StreamCode::MalformedAuth`].
pub fn parse_open_auth(values: &[&str]) -> Result<OpenAuth, StreamCode> {
    let Some(value) = exactly_one(values)? else {
        return Err(StreamCode::MissingAuth);
    };
    // 2.3: the scheme is the raw value up to the first SP, examined before
    // every parameter and character check.
    let sp = value.find(' ');
    let scheme = match sp {
        Some(i) => &value[..i],
        None => value,
    };
    if scheme != "s1" {
        return Err(if is_version_scheme(scheme) {
            StreamCode::UnsupportedVersion
        } else {
            StreamCode::MalformedAuth
        });
    }
    let Some(sp) = sp else {
        return Err(StreamCode::MalformedAuth);
    };
    let rest = &value[sp + 1..];
    let Some(params) = parse_params(rest, &["kid", "ts", "sid", "sig"]) else {
        return Err(StreamCode::MalformedAuth);
    };
    let ts_raw = param(&params, "ts");
    if !canonical_decimal(ts_raw, 12) {
        return Err(StreamCode::MalformedAuth);
    }
    // canonical_decimal bounds ts at 12 digits, so the i64 parse cannot fail;
    // the guard keeps the code total.
    let ts: i64 = ts_raw.parse().map_err(|_| StreamCode::MalformedAuth)?;
    for (name, size) in [("kid", KID_LEN), ("sid", SID_LEN), ("sig", SIG_LEN)] {
        if decode_b64url_fixed(param(&params, name), size).is_err() {
            return Err(StreamCode::MalformedAuth);
        }
    }
    Ok(OpenAuth {
        kid: param(&params, "kid").to_string(),
        ts,
        sid: param(&params, "sid").to_string(),
        sig: param(&params, "sig").to_string(),
    })
}

/// Renders the canonical open value "s1 kid=...,ts=...,sid=...,sig=..."
/// (spec 05 section 2.1).
pub fn format_open_auth(auth: &OpenAuth) -> String {
    format!(
        "s1 kid={},ts={},sid={},sig={}",
        auth.kid, auth.ts, auth.sid, auth.sig
    )
}

/// Builds the six-line open signing string of spec 05 section 2.5, joined
/// with LF and no trailing LF.
pub fn open_signing_string(
    status: u16,
    request_sig: &str,
    kid: &str,
    ts: i64,
    sid: &str,
) -> String {
    [
        OPEN_DOMAIN,
        &status.to_string(),
        request_sig,
        kid,
        &ts.to_string(),
        sid,
    ]
    .join("\n")
}

/// Builds the six-line frame signing string of spec 05 section 2.15, joined
/// with LF and no trailing LF.
pub fn frame_signing_string(sid: &str, seq: u64, ts: i64, prev: &str, data_hash: &str) -> String {
    [
        FRAME_DOMAIN,
        sid,
        &seq.to_string(),
        &ts.to_string(),
        prev,
        data_hash,
    ]
    .join("\n")
}

/// Spec 05 section 2.15: `data-hash` = base64url(SHA-256(UTF-8 bytes of
/// `data`)). The empty value hashes the empty byte string.
pub fn data_hash(data: &str) -> String {
    body_hash(data.as_bytes())
}

/// Spec 05 section 2.18: the signalled code when `data` is byte-for-byte the
/// template with a canonical limit, `None` for an ordinary message. Every
/// lookalike (another method, an extra or reordered member, whitespace, a
/// non-string code, an unlisted code, a non-canonical limit) stays `None`.
pub fn parse_signal(data: &str) -> Option<StreamCode> {
    for code in SIGNALLED_CODES {
        let prefix = signal_prefix(code);
        let Some(rest) = data.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let Some(limit) = rest.strip_suffix(SIGNAL_SUFFIX) else {
            continue;
        };
        // 2.18: canonical decimal `0` or `[1-9][0-9]*`, value at most 2^53-1.
        if let Some(value) = canonical_uint(limit) {
            if value <= MAX_SAFE_INTEGER {
                return Some(code);
            }
        }
    }
    None
}

/// Spec 05 section 2.18 template bytes for `code` with `limit` in canonical
/// decimal; `None` when `code` is not in the signalled set.
pub fn signal_data(code: StreamCode, limit: u64) -> Option<String> {
    if !SIGNALLED_CODES.contains(&code) {
        return None;
    }
    Some(format!("{}{limit}{SIGNAL_SUFFIX}", signal_prefix(code)))
}

/// The 2.18 template up to the start of `<n>`.
fn signal_prefix(code: StreamCode) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"{}\",\"params\":{{\"code\":\"{}\",\"limit\":",
        SIGNAL_METHOD,
        code.as_str()
    )
}

/// The event type of a frame (spec 05 sections 2.8 and 2.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Message,
    End,
}

impl FrameKind {
    /// The SSE `event` value this kind must carry.
    pub fn event_name(self) -> &'static str {
        match self {
            FrameKind::Message => "message",
            FrameKind::End => "jack-end",
        }
    }
}

/// One verified-grammar frame (spec 05 sections 2.6-2.13). `data` is the
/// joined data value of 2.10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JackFrame {
    pub kind: FrameKind,
    pub data: String,
    pub seq: u64,
    pub ts: i64,
    pub sig: String,
}

/// Parses one event's field lines with the grammar of spec 05 sections
/// 2.6-2.13. Any violation is [`StreamCode::BadFrame`].
pub fn parse_frame(lines: &[SseField]) -> Result<JackFrame, StreamCode> {
    let bad = StreamCode::BadFrame;
    let mut kind: Option<FrameKind> = None;
    let mut jack: Option<&str> = None;
    let mut data: Vec<&str> = Vec::new();
    for line in lines {
        // 2.10: every field value must be valid UTF-8, known name or not.
        let value = std::str::from_utf8(&line.value).map_err(|_| bad)?;
        match line.name.as_slice() {
            b"event" => {
                // 2.8: at most one event line, value exactly message or
                // jack-end.
                if kind.is_some() {
                    return Err(bad);
                }
                kind = Some(match value {
                    "message" => FrameKind::Message,
                    "jack-end" => FrameKind::End,
                    _ => return Err(bad),
                });
            }
            b"data" => data.push(value),
            b"jack" => {
                // 2.7: exactly one jack line per event.
                if jack.is_some() {
                    return Err(bad);
                }
                jack = Some(value);
            }
            // 2.11: id and retry must not appear on a Jack frame.
            b"id" | b"retry" => return Err(bad),
            // 2.13: any other field carries nothing and is ignored.
            _ => {}
        }
    }
    let Some(jack) = jack else {
        return Err(bad);
    };
    let params = parse_params(jack, &["seq", "ts", "sig"]).ok_or(bad)?;
    let seq_raw = param(&params, "seq");
    if !canonical_decimal(seq_raw, 15) {
        return Err(bad);
    }
    let ts_raw = param(&params, "ts");
    if !canonical_decimal(ts_raw, 12) {
        return Err(bad);
    }
    if decode_b64url_fixed(param(&params, "sig"), SIG_LEN).is_err() {
        return Err(bad);
    }
    // 2.10: the values joined with a single LF and no trailing LF.
    let value = data.join("\n");
    // 2.6: a missing event line means the SSE default event type.
    let kind = kind.unwrap_or(FrameKind::Message);
    // 2.9: the kind is a function of the signed data, so it cannot be forged.
    match kind {
        FrameKind::Message if value.is_empty() => return Err(bad),
        FrameKind::End if !value.is_empty() => return Err(bad),
        _ => {}
    }
    // canonical_decimal bounds seq at 15 digits; the safe-integer check of
    // 2.7 keeps the value exactly representable.
    let seq: u64 = seq_raw.parse().map_err(|_| bad)?;
    if seq > MAX_SAFE_INTEGER {
        return Err(bad);
    }
    let ts: i64 = ts_raw.parse().map_err(|_| bad)?;
    Ok(JackFrame {
        kind,
        data: value,
        seq,
        ts,
        sig: param(&params, "sig").to_string(),
    })
}

/// Spec 05 section 2.6 wire bytes: the `event` line, one `data` line per
/// LF-separated piece (an empty piece as `data:` alone), the `jack` line and
/// a blank line; LF only.
pub fn serialize_frame(kind: FrameKind, data: &str, seq: u64, ts: i64, sig: &str) -> String {
    let mut out = String::with_capacity(data.len() + 96);
    out.push_str("event: ");
    out.push_str(kind.event_name());
    out.push('\n');
    for piece in data.split('\n') {
        if piece.is_empty() {
            out.push_str("data:\n");
        } else {
            out.push_str("data: ");
            out.push_str(piece);
            out.push('\n');
        }
    }
    out.push_str(&format!("jack: seq={seq},ts={ts},sig={sig}\n\n"));
    out
}

/// Parsed `Jack-Accept` request header (spec 05 section 1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JackAccept {
    pub s1: bool,
}

/// Spec 05 section 1.1: every `Jack-Accept` line is combined, and only a line
/// that matches `OWS token *( OWS "," OWS token )` contributes tokens. OWS is
/// zero or more SP (HTAB is never OWS) and a token is 1*(ALPHA / DIGIT / "-");
/// OWS appears before the first token and around every comma, never after the
/// last one. A line with trailing SP, a trailing comma, a missing comma or any
/// other byte outside the grammar is rejected as a whole and contributes no
/// token, so it can never enable a stream. Tokens compare case-sensitively.
pub fn parse_jack_accept(values: &[&str]) -> JackAccept {
    let mut accept = JackAccept::default();
    for value in values {
        for token in accept_tokens(value) {
            if token == super::ACCEPT_TOKEN {
                accept.s1 = true;
            }
        }
    }
    accept
}

/// Spec 05 section 1.1: whether the token `s1` appears in the combined list.
pub fn accepts_s1(values: &[&str]) -> bool {
    parse_jack_accept(values).s1
}

/// Yields the tokens of one `Jack-Accept` line, or nothing when the line does
/// not match the 1.1 grammar as a whole.
///
/// The line must be consumed exactly: the last token must be the last byte, so
/// `"s1 "`, `"s1 ,"` and `"s1,"` all contribute nothing while `" s1"` and
/// `" s1 , s2"` contribute `s1`.
fn accept_tokens(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut tokens = Vec::new();
    let mut i = skip_sp(bytes, 0);
    loop {
        let start = i;
        while i < bytes.len() && is_token_byte(bytes[i]) {
            i += 1;
        }
        if i == start {
            // No token where the grammar requires one; this also rejects the
            // empty line and a trailing comma with its empty member.
            return Vec::new();
        }
        tokens.push(&line[start..i]);
        if i == bytes.len() {
            // The line ends at the last token: 1.1 admits no OWS after it.
            return tokens;
        }
        let after_ows = skip_sp(bytes, i);
        if bytes.get(after_ows) != Some(&b',') {
            return Vec::new();
        }
        i = skip_sp(bytes, after_ows + 1);
    }
}

fn skip_sp(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    i
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

/// Spec 05 section 1.4: status 200 plus a `Content-Type` media type of
/// `text/event-stream` (case-insensitive, parameters ignored, SP/HTAB trimmed
/// around the media type). Takes header name/value pairs in order; the caller
/// applies the status check.
pub fn is_event_stream(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type") && {
            let media = value.split(';').next().unwrap_or_default();
            media
                .trim_matches(|c: char| c == ' ' || c == '\t')
                .eq_ignore_ascii_case("text/event-stream")
        }
    })
}

/// Spec 05 section 4.2 step 1-2 helper: the single value, or `Ok(None)` when
/// the header is absent and `Err(MalformedAuth)` when it is repeated.
fn exactly_one<'a>(values: &'a [&'a str]) -> Result<Option<&'a str>, StreamCode> {
    match values {
        [] => Ok(None),
        [value] => Ok(Some(value)),
        _ => Err(StreamCode::MalformedAuth),
    }
}

/// Spec 05 sections 2.2 and 2.7: `name=value` pairs joined by a single `,`
/// with no whitespace; lowercase case-sensitive names, each of `names` exactly
/// once.
fn parse_params<'a>(value: &'a str, names: &[&str]) -> Option<Vec<(&'a str, &'a str)>> {
    let mut out: Vec<(&'a str, &'a str)> = Vec::with_capacity(names.len());
    for part in value.split(',') {
        let (name, val) = part.split_once('=')?;
        if !lower_alpha(name) || !param_value_charset(val) {
            return None;
        }
        if !names.contains(&name) || out.iter().any(|&(seen, _)| seen == name) {
            return None;
        }
        out.push((name, val));
    }
    // Every required name is present exactly once.
    if out.len() != names.len() {
        return None;
    }
    Some(out)
}

/// The value of a name that `parse_params` already required.
fn param<'a>(params: &[(&'a str, &'a str)], name: &str) -> &'a str {
    params
        .iter()
        .find(|&&(seen, _)| seen == name)
        .map(|&(_, value)| value)
        .expect("parse_params guarantees every requested name")
}

/// Reports whether `s` matches `^[a-z]+$` (parameter names, 2.2 and 2.7).
fn lower_alpha(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty() && bytes.iter().all(u8::is_ascii_lowercase)
}

/// Reports whether `s` is non-empty and only `A-Za-z0-9_-` (value alphabet).
fn param_value_charset(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// Reports whether `s` matches `^(0|[1-9][0-9]{0,max-1})$`: canonical unsigned
/// decimal with at most `max_digits` digits (`TS_RE` and `SEQ_RE`).
fn canonical_decimal(s: &str, max_digits: usize) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > max_digits {
        return false;
    }
    if bytes[0] == b'0' {
        return bytes.len() == 1;
    }
    bytes.iter().all(u8::is_ascii_digit)
}

/// Adds the 2.18 rule that the limit is `0` or `[1-9][0-9]*` and fits a u64
/// (`LIMIT_RE` plus the 2^53-1 bound checked by the caller).
fn canonical_uint(s: &str) -> Option<u64> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] == b'0' {
        return if bytes.len() == 1 { Some(0) } else { None };
    }
    if !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    s.parse().ok()
}

/// Reports whether the bytes are exactly `s` or `v` plus one or more ASCII
/// digits (spec 05 section 2.3).
fn is_version_scheme(scheme: &str) -> bool {
    let bytes = scheme.as_bytes();
    bytes.len() >= 2
        && (bytes[0] == b's' || bytes[0] == b'v')
        && bytes[1..].iter().all(u8::is_ascii_digit)
}
