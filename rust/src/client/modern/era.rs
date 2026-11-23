//! Era detection from one *verified* response (spec 04 section 6, `C9`).
//!
//! [`detect_era`] mirrors the reference `detectEra` of
//! `spec/tools/modern/headers/reference/client.mjs`: verification runs before
//! every status rule, so an unverified response never proves an era; the status
//! then selects the signal and a `400` or `404` reads the body as a recognised
//! JSON-RPC error, as Jack's own envelope or as nothing at all. The outcome is
//! one triple of the closed `{era, action, reason}` vocabulary, plus the
//! mutually implemented versions of a `-32022` retry.

use serde_json::Value;

use crate::modern::Era;

/// One response as the client saw it: its status and its body, plus whether the
/// 01 section 5 response signature verified. Verification runs before every
/// status rule of `C9`, so an unverified response never proves an era.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedResponse<'a> {
    /// Whether the 01 section 5 response signature verified.
    pub verified: bool,
    /// HTTP status of the response.
    pub status: u16,
    /// Body bytes exactly as received.
    pub body: &'a [u8],
}

/// The action a `C9` detection prescribes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraAction {
    /// The response proves the modern era; the operation proceeds.
    StayModern,
    /// The response proves the legacy era; fall back to `initialize`.
    FallbackInitialize,
    /// The server listed versions it implements; retry with the mutual ones.
    RetryWithSupported,
    /// The operation fails: no era was proven, or no version overlaps.
    Abort,
}

impl EraAction {
    /// Canonical lowercase name: `"stay_modern"`, `"fallback_initialize"`,
    /// `"retry_with_supported"` or `"abort"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StayModern => "stay_modern",
            Self::FallbackInitialize => "fallback_initialize",
            Self::RetryWithSupported => "retry_with_supported",
            Self::Abort => "abort",
        }
    }
}

/// The closed reason vocabulary of a `C9` detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraReason {
    /// The response signature did not verify, so it carries no era signal.
    Unverified,
    /// The body is not a modern-era signal and not Jack's envelope.
    NoModernError,
    /// The body is Jack's own `{"error":{...}}` envelope with a string code.
    JackEnvelope,
    /// A `404` whose body is a recognised JSON-RPC `-32601` error.
    ModernMethodNotFound,
    /// A `-32022` retry with no usable supported list or no mutual version.
    UnsupportedVersionNoOverlap,
    /// The status carries no era signal at all.
    NoEraSignal,
}

impl EraReason {
    /// Canonical lowercase name: `"unverified"`, `"no_modern_error"`,
    /// `"jack_envelope"`, `"modern_method_not_found"`,
    /// `"unsupported_version_no_overlap"` or `"no_era_signal"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::NoModernError => "no_modern_error",
            Self::JackEnvelope => "jack_envelope",
            Self::ModernMethodNotFound => "modern_method_not_found",
            Self::UnsupportedVersionNoOverlap => "unsupported_version_no_overlap",
            Self::NoEraSignal => "no_era_signal",
        }
    }
}

/// One `C9` outcome: era `None` means "no signal, the operation fails".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EraDetection {
    /// The era the response proves, or `None` when it proves none.
    pub era: Option<Era>,
    /// What the client does next.
    pub action: EraAction,
    /// Why the detection reached that action; `None` for a plain era proof.
    pub reason: Option<EraReason>,
    /// The mutually implemented versions of a `-32022` retry, in the server's
    /// order; empty unless the action is `RetryWithSupported`.
    pub supported: Vec<String>,
}

/// Builds a detection without a `-32022` supported list.
fn detection(era: Option<Era>, action: EraAction, reason: Option<EraReason>) -> EraDetection {
    EraDetection {
        era,
        action,
        reason,
        supported: Vec::new(),
    }
}

/// The detection of a `2xx` response or of a modern-era `400`: the server is
/// modern and the operation proceeds.
fn stay_modern() -> EraDetection {
    detection(Some(Era::Modern), EraAction::StayModern, None)
}

/// The detection of a response that reads legacy.
fn fallback(reason: EraReason) -> EraDetection {
    detection(
        Some(Era::Legacy),
        EraAction::FallbackInitialize,
        Some(reason),
    )
}

/// Parses a response body as a JSON object (spec 04 `C9`): an empty or
/// whitespace-only body, invalid JSON and every non-object carry no signal.
fn parse_body(body: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(body).ok()?;
    if text.trim().is_empty() {
        return None;
    }
    let parsed: Value = serde_json::from_str(text).ok()?;
    parsed.is_object().then_some(parsed)
}

/// The `error` member of a body when it is an object, else `None`.
fn error_of(body: &Value) -> Option<&Value> {
    body.get("error").filter(|error| error.is_object())
}

/// The integer value of a JSON number, as `Number.isInteger` reads it: a
/// number with no fractional part, including one written `-32020.0`.
fn integer_code(code: &Value) -> Option<i64> {
    if let Some(code) = code.as_i64() {
        return Some(code);
    }
    let float = code.as_f64()?;
    (float.is_finite() && float.fract() == 0.0).then_some(float as i64)
}

/// The `error` object of a recognised JSON-RPC error, else `None`: `jsonrpc`
/// exactly `"2.0"`, a present `id` member that is `null`, a string or a number,
/// and an `error` object with an integer `code` and a string `message`.
fn recognised_error(body: &Value) -> Option<&Value> {
    let members = body.as_object()?;
    if members.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return None;
    }
    let id = members.get("id")?;
    if !(id.is_null() || id.is_string() || id.is_number()) {
        return None;
    }
    let error = error_of(body)?;
    let error_members = error.as_object()?;
    integer_code(error_members.get("code")?)?;
    error_members.get("message").filter(|m| m.is_string())?;
    Some(error)
}

/// The code of a recognised JSON-RPC error.
fn code_of(error: &Value) -> Option<i64> {
    integer_code(error.get("code")?)
}

/// The mutual versions of a `-32022` error, in the server's order (spec 04
/// `C9`): the `error.data.supported` array is usable only when every element
/// is a string, and only its members implemented by the client survive.
fn mutual_versions(error: &Value, client_versions: &[&str]) -> Vec<String> {
    let usable = error
        .get("data")
        .and_then(|data| data.get("supported"))
        .and_then(Value::as_array)
        .filter(|versions| versions.iter().all(Value::is_string));
    let Some(versions) = usable else {
        return Vec::new();
    };
    versions
        .iter()
        .filter_map(Value::as_str)
        .filter(|version| client_versions.contains(version))
        .map(str::to_owned)
        .collect()
}

/// Reports whether `body` is Jack's own envelope (spec 04 `C9`): a JSON object
/// with **no** `jsonrpc` member whose `error` object carries a string `code`.
fn is_jack_envelope(body: &Value) -> bool {
    let Some(members) = body.as_object() else {
        return false;
    };
    if members.contains_key("jsonrpc") {
        return false;
    }
    error_of(body).is_some_and(|error| {
        error
            .as_object()
            .and_then(|error| error.get("code"))
            .is_some_and(Value::is_string)
    })
}

/// Detects the server era from one *verified* response (spec 04 `C9`).
///
/// The rules run in the reference order and the first one wins: an unverified
/// response aborts before any status is read, a `2xx` proves the modern era, a
/// `400` reads a modern JSON-RPC error (`-32020`, `-32021`, `-32022`) or falls
/// back to `initialize`, a `404` reads a `-32601` error as a modern server
/// without that method, a `405` reads legacy and every other status carries no
/// signal. `client_versions` are the versions the client implements, used only
/// to filter the `supported` list of a `-32022` retry.
pub fn detect_era(response: &VerifiedResponse<'_>, client_versions: &[&str]) -> EraDetection {
    if !response.verified {
        return detection(None, EraAction::Abort, Some(EraReason::Unverified));
    }
    match response.status {
        200..=299 => stay_modern(),
        400 => detect_bad_request(response.body, client_versions),
        404 => {
            let body = parse_body(response.body);
            let modern_method_not_found =
                body.as_ref().and_then(recognised_error).and_then(code_of) == Some(-32601);
            if modern_method_not_found {
                detection(
                    Some(Era::Modern),
                    EraAction::StayModern,
                    Some(EraReason::ModernMethodNotFound),
                )
            } else {
                fallback(EraReason::NoModernError)
            }
        }
        405 => fallback(EraReason::NoModernError),
        _ => detection(None, EraAction::Abort, Some(EraReason::NoEraSignal)),
    }
}

/// The `400` rules of `C9`.
fn detect_bad_request(body: &[u8], client_versions: &[&str]) -> EraDetection {
    let parsed = parse_body(body);
    let recognised = parsed.as_ref().and_then(recognised_error);
    if let Some(error) = recognised {
        match code_of(error) {
            Some(-32020 | -32021) => return stay_modern(),
            Some(-32022) => {
                let mutual = mutual_versions(error, client_versions);
                if mutual.is_empty() {
                    return detection(
                        Some(Era::Modern),
                        EraAction::Abort,
                        Some(EraReason::UnsupportedVersionNoOverlap),
                    );
                }
                return EraDetection {
                    era: Some(Era::Modern),
                    action: EraAction::RetryWithSupported,
                    reason: None,
                    supported: mutual,
                };
            }
            _ => return fallback(EraReason::NoModernError),
        }
    }
    match parsed.as_ref() {
        Some(body) if is_jack_envelope(body) => fallback(EraReason::JackEnvelope),
        _ => fallback(EraReason::NoModernError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The detection of a verified response with `status` and `body`, against
    /// the given client versions.
    fn detect_with(status: u16, body: &str, client_versions: &[&str]) -> EraDetection {
        let response = VerifiedResponse {
            verified: true,
            status,
            body: body.as_bytes(),
        };
        detect_era(&response, client_versions)
    }

    /// The detection of a verified response with no client versions.
    fn detect(status: u16, body: &str) -> EraDetection {
        detect_with(status, body, &[])
    }

    /// The expected detection of an era proof without a `-32022` list.
    fn expected(era: Era, action: EraAction, reason: Option<EraReason>) -> EraDetection {
        EraDetection {
            era: Some(era),
            action,
            reason,
            supported: Vec::new(),
        }
    }

    /// The expected `legacy`/`fallback_initialize` detection.
    fn legacy(reason: EraReason) -> EraDetection {
        expected(Era::Legacy, EraAction::FallbackInitialize, Some(reason))
    }

    /// The expected `modern`/`stay_modern` detection.
    fn modern() -> EraDetection {
        expected(Era::Modern, EraAction::StayModern, None)
    }

    /// The expected no-signal detection.
    fn no_signal(reason: EraReason) -> EraDetection {
        EraDetection {
            era: None,
            action: EraAction::Abort,
            reason: Some(reason),
            supported: Vec::new(),
        }
    }

    /// A recognised JSON-RPC `400` error body with `code` and `data`.
    fn error_body(code: i64, data: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":{code},"message":"m"{data}}}}}"#)
    }

    #[test]
    fn two_xx_is_modern() {
        assert_eq!(
            detect(200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            modern()
        );
        assert_eq!(detect(204, ""), modern());
    }

    #[test]
    fn unverified_carries_no_signal() {
        let ok = VerifiedResponse {
            verified: false,
            status: 200,
            body: b"{}",
        };
        assert_eq!(detect_era(&ok, &[]), no_signal(EraReason::Unverified));
        let unauthorised = VerifiedResponse {
            verified: false,
            status: 401,
            body: b"",
        };
        assert_eq!(
            detect_era(&unauthorised, &[]),
            no_signal(EraReason::Unverified)
        );
    }

    #[test]
    fn bad_request_with_modern_era_codes_is_modern() {
        assert_eq!(detect(400, &error_body(-32020, "")), modern());
        assert_eq!(detect(400, &error_body(-32021, "")), modern());
        let null_id = r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32020,"message":"m"}}"#;
        assert_eq!(detect(400, null_id), modern());
    }

    #[test]
    fn version_mismatch_retries_with_mutual_versions() {
        let body = error_body(-32022, r#","data":{"supported":["2026-07-28"]}"#);
        let detection = detect_with(400, &body, &["2026-07-28"]);
        assert_eq!(
            detection,
            EraDetection {
                era: Some(Era::Modern),
                action: EraAction::RetryWithSupported,
                reason: None,
                supported: vec!["2026-07-28".to_owned()],
            }
        );
    }

    #[test]
    fn version_mismatch_keeps_the_server_order() {
        let body = error_body(
            -32022,
            r#","data":{"supported":["2027-01-01","2025-11-25"]}"#,
        );
        let detection = detect_with(400, &body, &["2025-11-25", "2026-07-28"]);
        assert_eq!(
            detection,
            EraDetection {
                era: Some(Era::Modern),
                action: EraAction::RetryWithSupported,
                reason: None,
                supported: vec!["2025-11-25".to_owned()],
            }
        );
    }

    #[test]
    fn version_mismatch_without_a_usable_list_aborts() {
        let unsupported = expected(
            Era::Modern,
            EraAction::Abort,
            Some(EraReason::UnsupportedVersionNoOverlap),
        );
        let client = ["2026-07-28"];
        for body in [
            error_body(-32022, ""),
            error_body(-32022, r#","data":{}"#),
            error_body(-32022, r#","data":{"supported":[]}"#),
            error_body(-32022, r#","data":{"supported":"2026-07-28"}"#),
            error_body(-32022, r#","data":{"supported":["2026-07-28",7]}"#),
            error_body(-32022, r#","data":{"supported":["2027-01-01"]}"#),
        ] {
            assert_eq!(detect_with(400, &body, &client), unsupported, "{body}");
        }
    }

    #[test]
    fn unrecognised_bad_request_bodies_read_legacy() {
        let no_modern_error = legacy(EraReason::NoModernError);
        for body in [
            r#"{"error":{"code":-32020}}"#,
            r#"{"error":{"code":-32020,"message":"m"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32020}}"#,
            r#"{"jsonrpc":"2.0","error":{"code":-32020,"message":"m"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602.5,"message":"m"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":7}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":"-32020","message":"m"}}"#,
            "",
            "   \n\t ",
            "not json",
            "[1,2,3]",
        ] {
            assert_eq!(detect(400, body), no_modern_error, "{body}");
        }
    }

    #[test]
    fn bad_request_jack_envelope_reads_legacy() {
        let envelope = r#"{"error":{"code":"invalid_request","message":"bad"}}"#;
        assert_eq!(detect(400, envelope), legacy(EraReason::JackEnvelope));
        let with_jsonrpc = r#"{"jsonrpc":"1.0","error":{"code":"invalid_request"}}"#;
        assert_eq!(detect(400, with_jsonrpc), legacy(EraReason::NoModernError));
    }

    #[test]
    fn bad_request_with_other_codes_reads_legacy() {
        for code in [-32602, -32601, -32002] {
            assert_eq!(
                detect(400, &error_body(code, "")),
                legacy(EraReason::NoModernError),
                "{code}"
            );
        }
    }

    #[test]
    fn not_found_reads_the_method_missing() {
        let missing = expected(
            Era::Modern,
            EraAction::StayModern,
            Some(EraReason::ModernMethodNotFound),
        );
        assert_eq!(detect(404, &error_body(-32601, "")), missing);
        let no_modern_error = legacy(EraReason::NoModernError);
        assert_eq!(detect(404, r#"{"error":{"code":-32601}}"#), no_modern_error);
        assert_eq!(detect(404, ""), no_modern_error);
        assert_eq!(
            detect(404, r#"{"error":{"code":"not_found","message":"m"}}"#),
            no_modern_error
        );
    }

    #[test]
    fn method_not_allowed_reads_legacy() {
        assert_eq!(
            detect(405, r#"{"error":{"code":"invalid_request","message":"m"}}"#),
            legacy(EraReason::NoModernError)
        );
        assert_eq!(detect(405, ""), legacy(EraReason::NoModernError));
    }

    #[test]
    fn other_statuses_carry_no_signal() {
        for status in [500, 429] {
            let response = VerifiedResponse {
                verified: true,
                status,
                body: b"",
            };
            assert_eq!(
                detect_era(&response, &[]),
                no_signal(EraReason::NoEraSignal),
                "{status}"
            );
        }
    }

    #[test]
    fn actions_and_reasons_have_wire_names() {
        let actions = [
            (EraAction::StayModern, "stay_modern"),
            (EraAction::FallbackInitialize, "fallback_initialize"),
            (EraAction::RetryWithSupported, "retry_with_supported"),
            (EraAction::Abort, "abort"),
        ];
        for (action, name) in actions {
            assert_eq!(action.as_str(), name);
        }
        let reasons = [
            (EraReason::Unverified, "unverified"),
            (EraReason::NoModernError, "no_modern_error"),
            (EraReason::JackEnvelope, "jack_envelope"),
            (EraReason::ModernMethodNotFound, "modern_method_not_found"),
            (
                EraReason::UnsupportedVersionNoOverlap,
                "unsupported_version_no_overlap",
            ),
            (EraReason::NoEraSignal, "no_era_signal"),
        ];
        for (reason, name) in reasons {
            assert_eq!(reason.as_str(), name);
        }
    }
}
