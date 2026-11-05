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

/// The JSON-RPC error member of an otherwise successful call (Go:
/// client.RPCError).
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

/// The client error type. Protocol rejections parsed from a (verified) server
/// body carry the HTTP status and wire code; client-side failures carry none
/// (Go: plain errors / sentinel / typed errors of package client).
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
}
