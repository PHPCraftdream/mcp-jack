//! Error types of the client SDK (Go: client/errors.go). Protocol rejections
//! parsed from a (verified) server body carry the HTTP status and wire code;
//! client-side failures carry none.

use std::fmt;

use crate::error::JackError;

/// A non-2xx response whose verified body was
/// {"error":{"code":...,"message":...}} (Go: client.HTTPError). Carries the
/// HTTP status and wire code.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "jack client: http {} {}: {}",
            self.status, self.code, self.message
        )
    }
}

impl std::error::Error for HttpError {}

/// A JSON-RPC error object (Go: client.RPCError): the `error` member of an
/// otherwise successful call, and — surfacing as [`ClientError::Rpc`] — a
/// verified non-2xx reply whose body is a JSON-RPC error with a numeric code
/// (spec 04 section 6; see [`ClientError::reply_error`] for its typed view).
#[derive(Debug, Clone, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "jack client: rpc error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

/// An MCP result with isError true (Go: client.ToolError). `structured` is
/// the raw structuredContent, present when the server sent one.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolError {
    pub message: String,
    pub structured: Option<serde_json::Value>,
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "jack client: tool error: {}", self.message)
    }
}

impl std::error::Error for ToolError {}

/// A 401 answered WITHOUT a verified Jack-Auth header. Per spec 01 section 5
/// ("A client MUST NOT act on an unsigned or unverified response beyond
/// reporting its status") the unsigned body is never parsed, so this carries
/// the HTTP status and nothing else. Go's Transport.RoundTrip behaves the
/// same (client/transport.go).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnauthenticatedResponseError {
    pub status: u16,
}

impl fmt::Display for UnauthenticatedResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "jack client: unauthenticated response: status {}",
            self.status
        )
    }
}

impl std::error::Error for UnauthenticatedResponseError {}

/// The era a [`ReplyError`] classifies, from its JSON-RPC code (spec 04
/// section 6, `C9`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyEra {
    /// `-32020`, `-32021` or `-32022`: a modern-era refusal.
    Modern,
    /// `-32601`: the server speaks the modern era but not that method.
    MethodNotFound,
    /// Any other code: no era signal.
    None,
}

impl ReplyEra {
    /// Canonical lowercase name: `"modern"`, `"method_not_found"` or `"none"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Modern => "modern",
            Self::MethodNotFound => "method_not_found",
            Self::None => "none",
        }
    }

    /// Classifies a numeric JSON-RPC `error.code` (spec 04 section 6, `C9`):
    /// `-32020`, `-32021` and `-32022` are modern-era refusals, `-32601` is a
    /// modern server that does not know the method, and any other code carries
    /// no era signal ([`ReplyEra::None`]).
    pub fn of_code(code: i64) -> ReplyEra {
        match code {
            -32022..=-32020 => Self::Modern,
            -32601 => Self::MethodNotFound,
            _ => Self::None,
        }
    }
}

/// A verified non-2xx JSON-RPC error object (spec 04 section 6): the HTTP
/// status, the numeric `error.code`, `error.message` and `error.data`, plus
/// the era classification of the code. Additive alongside [`HttpError`], which
/// keeps parsing Jack's legacy `{"error":{"code":"<string>"}}` envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplyError {
    /// HTTP status as received and verified.
    pub status: u16,
    /// The numeric `error.code`.
    pub code: i64,
    /// The string `error.message`.
    pub message: String,
    /// The `error.data` member, when present.
    pub data: Option<serde_json::Value>,
    /// The era the code classifies.
    pub era: ReplyEra,
}

impl ReplyError {
    /// Parses a verified non-2xx body as a JSON-RPC error object: a JSON object
    /// whose `jsonrpc` is exactly `"2.0"` and whose `error` is an object with
    /// an integer `code` and a string `message`. Any other body is `None`.
    pub fn parse(status: u16, body: &[u8]) -> Option<ReplyError> {
        let parsed: serde_json::Value = serde_json::from_slice(body).ok()?;
        let members = parsed.as_object()?;
        if members.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
            return None;
        }
        let error = members.get("error")?.as_object()?;
        let code = integer_code(error.get("code")?)?;
        let message = error.get("message")?.as_str()?;
        Some(ReplyError {
            status,
            code,
            message: message.to_owned(),
            data: error.get("data").cloned(),
            era: ReplyEra::of_code(code),
        })
    }
}

impl fmt::Display for ReplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "jack client: http {} {}: {}",
            self.status, self.code, self.message
        )
    }
}

impl std::error::Error for ReplyError {}

/// The integer value of a JSON number, accepting a number with no fractional
/// part (so a `-32020.0` reads like `-32020`).
fn integer_code(code: &serde_json::Value) -> Option<i64> {
    if let Some(code) = code.as_i64() {
        return Some(code);
    }
    let float = code.as_f64()?;
    (float.is_finite() && float.fract() == 0.0).then_some(float as i64)
}

/// The client error type. Protocol rejections parsed from a (verified) server
/// body carry the HTTP status and wire code; client-side failures carry none
/// (Go: plain errors / sentinel / typed errors of package client).
///
/// A verified non-2xx reply whose body is a JSON-RPC error object with a
/// numeric `error.code` (spec 04 section 6) surfaces as [`ClientError::Rpc`]
/// carrying that numeric code, message and data; [`ClientError::reply_error`]
/// reconstructs the typed [`ReplyError`] view of it. Jack's legacy
/// `{"error":{"code":"<string>"}}` envelope keeps producing
/// [`ClientError::Http`] with the string code, exactly as before.
#[derive(Debug, Clone, PartialEq)]
pub enum ClientError {
    Http(HttpError),
    Rpc(RpcError),
    Tool(ToolError),
    Unauthenticated(UnauthenticatedResponseError),
    /// A JackError-surfaced failure: response-verification rejections (spec 01
    /// section 5) and local protocol validation (e.g. a pinned key that fails
    /// spec 03 section 2). Both are client-side — neither ever becomes an HTTP
    /// response — so http_status is 0; call sites zero the validator's
    /// server-side admission status before wrapping it here.
    Protocol(JackError),
    /// A streaming response was refused before verification (Go:
    /// ErrStreamingUnsupported; spec 01 section 5 open question Q1).
    Streaming,
    /// Any other client-side failure (configuration, signer, transport I/O,
    /// encoding). The message never carries server-derived data.
    Client(String),
}

impl ClientError {
    /// Reconstructs the typed [`ReplyError`] view of a JSON-RPC error surfaced
    /// as [`ClientError::Rpc`] (a verified non-2xx reply with a numeric
    /// `error.code`, or a 2xx `tools/call` body carrying an `error` member):
    /// the code, message and data are the [`RpcError`] fields and the era is
    /// [`ReplyEra::of_code`]. `None` for every other variant.
    ///
    /// `status` is `0` for this reconstruction, because [`RpcError`] carries no
    /// HTTP status; use [`ReplyError::parse`] on a verified non-2xx body when
    /// the status is needed.
    pub fn reply_error(&self) -> Option<ReplyError> {
        let ClientError::Rpc(err) = self else {
            return None;
        };
        Some(ReplyError {
            status: 0,
            code: err.code,
            message: err.message.clone(),
            data: err.data.clone(),
            era: ReplyEra::of_code(err.code),
        })
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Http(e) => write!(f, "{e}"),
            ClientError::Rpc(e) => write!(f, "{e}"),
            ClientError::Tool(e) => write!(f, "{e}"),
            ClientError::Unauthenticated(e) => write!(f, "{e}"),
            ClientError::Protocol(e) => write!(f, "{e}"),
            ClientError::Streaming => write!(
                f,
                "jack client: streaming responses cannot be verified and are refused (spec 01 section 5, open question Q1)"
            ),
            // The stored strings are complete Go-style messages.
            ClientError::Client(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Protocol(e) => Some(e),
            _ => None,
        }
    }
}

/// Decodes the tolerant error body {"error":{"code":string,"message":string}}
/// (Go: wireError + parseErrorBody). Any parse failure or wrong shape yields
/// ("", "") — this must never error, because the body may be untrusted.
// Wired into the transport/rpc response handling path (see transport.rs).
pub(crate) fn parse_error_body(body: &[u8]) -> (String, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return (String::new(), String::new());
    };
    let Some(error) = v.get("error").and_then(|e| e.as_object()) else {
        return (String::new(), String::new());
    };
    let code = match error.get("code").and_then(|c| c.as_str()) {
        Some(c) => c.to_string(),
        None => return (String::new(), String::new()),
    };
    let message = match error.get("message").and_then(|m| m.as_str()) {
        Some(m) => m.to_string(),
        None => return (String::new(), String::new()),
    };
    (code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Trait method call on the enum: source() needs the trait in scope.
    use std::error::Error as _;

    fn http() -> HttpError {
        HttpError {
            status: 403,
            code: "operation_denied".to_string(),
            message: "not allowed".to_string(),
        }
    }

    fn rpc() -> RpcError {
        RpcError {
            code: -32601,
            message: "method not found".to_string(),
            data: None,
        }
    }

    fn tool() -> ToolError {
        ToolError {
            message: "boom".to_string(),
            structured: None,
        }
    }

    fn unauth() -> UnauthenticatedResponseError {
        UnauthenticatedResponseError { status: 401 }
    }

    #[test]
    fn display_formats() {
        assert_eq!(
            format!("{}", http()),
            "jack client: http 403 operation_denied: not allowed"
        );
        assert_eq!(
            format!("{}", rpc()),
            "jack client: rpc error -32601: method not found"
        );
        assert_eq!(format!("{}", tool()), "jack client: tool error: boom");
        assert_eq!(
            format!("{}", unauth()),
            "jack client: unauthenticated response: status 401"
        );
        let protocol = ClientError::Protocol(JackError::new(0, "bad_signature", "nope"));
        assert_eq!(format!("{protocol}"), "jack: bad_signature: nope");
        assert_eq!(
            format!("{}", ClientError::Streaming),
            "jack client: streaming responses cannot be verified and are refused (spec 01 section 5, open question Q1)"
        );
        let client = ClientError::Client("jack client: nonce: short".to_string());
        assert_eq!(format!("{client}"), "jack client: nonce: short");
        // Variant displays flow through the top-level enum too.
        assert_eq!(
            format!("{}", ClientError::Http(http())),
            format!("{}", http())
        );
    }

    #[test]
    fn error_source_only_for_protocol() {
        assert!(
            ClientError::Protocol(JackError::new(0, "bad_signature", ""))
                .source()
                .is_some()
        );
        assert!(ClientError::Client("x".to_string()).source().is_none());
        assert!(ClientError::Streaming.source().is_none());
        assert!(ClientError::Http(http()).source().is_none());
    }

    #[test]
    fn parse_error_body_envelope() {
        let body = br#"{"error":{"code":"operation_denied","message":"not allowed"}}"#;
        assert_eq!(
            parse_error_body(body),
            ("operation_denied".to_string(), "not allowed".to_string())
        );
    }

    #[test]
    fn parse_error_body_tolerant() {
        assert_eq!(
            parse_error_body(br#"{"error":{}}"#),
            ("".to_string(), "".to_string())
        );
        assert_eq!(
            parse_error_body(br#"{"code":"x","message":"y"}"#),
            ("".to_string(), "".to_string())
        );
        assert_eq!(
            parse_error_body(br#"{"error":"str"}"#),
            ("".to_string(), "".to_string())
        );
        assert_eq!(
            parse_error_body(br#"{"error":{"code":7,"message":"y"}}"#),
            ("".to_string(), "".to_string())
        );
        assert_eq!(
            parse_error_body(br#"{"error":{"code":"x","message":true}}"#),
            ("".to_string(), "".to_string())
        );
        assert_eq!(
            parse_error_body(b"not json"),
            ("".to_string(), "".to_string())
        );
        assert_eq!(parse_error_body(b""), ("".to_string(), "".to_string()));
    }

    #[test]
    fn reply_error_numeric_codes_and_eras() {
        let body = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"Header mismatch: x","data":{"k":1}}}"#;
        let err = ReplyError::parse(400, body).expect("numeric JSON-RPC error");
        assert_eq!(err.status, 400);
        assert_eq!(err.code, -32020);
        assert_eq!(err.message, "Header mismatch: x");
        assert_eq!(err.data, Some(serde_json::json!({"k": 1})));
        assert_eq!(err.era, ReplyEra::Modern);
        assert_eq!(
            format!("{err}"),
            "jack client: http 400 -32020: Header mismatch: x"
        );

        for (code, era) in [
            (-32020, ReplyEra::Modern),
            (-32021, ReplyEra::Modern),
            (-32022, ReplyEra::Modern),
            (-32601, ReplyEra::MethodNotFound),
            (-32602, ReplyEra::None),
            (-32002, ReplyEra::None),
        ] {
            let body =
                format!(r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":{code},"message":"m"}}}}"#);
            let err = ReplyError::parse(404, body.as_bytes()).expect("recognised error");
            assert_eq!(err.era, era, "{code}");
        }

        assert_eq!(ReplyEra::of_code(-32020), ReplyEra::Modern);
        assert_eq!(ReplyEra::of_code(-32021), ReplyEra::Modern);
        assert_eq!(ReplyEra::of_code(-32022), ReplyEra::Modern);
        assert_eq!(ReplyEra::of_code(-32601), ReplyEra::MethodNotFound);
        assert_eq!(ReplyEra::of_code(0), ReplyEra::None);
        assert_eq!(ReplyEra::of_code(-32602), ReplyEra::None);
        assert_eq!(ReplyEra::Modern.as_str(), "modern");
        assert_eq!(ReplyEra::MethodNotFound.as_str(), "method_not_found");
        assert_eq!(ReplyEra::None.as_str(), "none");
    }

    #[test]
    fn reply_error_reconstructs_from_rpc_only() {
        let rpc = ClientError::Rpc(RpcError {
            code: -32021,
            message: "refused".to_string(),
            data: Some(serde_json::json!({"why": 1})),
        });
        let reply = rpc.reply_error().expect("the Rpc variant reconstructs");
        assert_eq!(reply.status, 0, "RpcError carries no HTTP status");
        assert_eq!(reply.code, -32021);
        assert_eq!(reply.message, "refused");
        assert_eq!(reply.data, Some(serde_json::json!({"why": 1})));
        assert_eq!(reply.era, ReplyEra::Modern);

        let tool = ClientError::Tool(ToolError {
            message: "boom".to_string(),
            structured: None,
        });
        assert_eq!(tool.reply_error(), None);
        assert_eq!(ClientError::Http(http()).reply_error(), None);
        assert_eq!(ClientError::Streaming.reply_error(), None);
    }

    #[test]
    fn reply_error_rejects_everything_else() {
        for body in [
            br#"{"error":{"code":"operation_denied","message":"m"}}"#.as_slice(),
            br#"{"error":{"code":-32020,"message":"m"}}"#.as_slice(),
            br#"{"jsonrpc":"1.0","id":1,"error":{"code":-32020,"message":"m"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":"-32020","message":"m"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32020}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":7}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"error":-32020}"#.as_slice(),
            b"not json".as_slice(),
            b"".as_slice(),
        ] {
            assert_eq!(ReplyError::parse(400, body), None, "{body:?}");
        }
        // A float without a fractional part is still an integer code.
        let body = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32020.0,"message":"m"}}"#;
        assert_eq!(
            ReplyError::parse(400, body).map(|e| e.code),
            Some(-32020),
            "integral float code"
        );
    }
}
