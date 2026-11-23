//! JSON envelope structs of the HTTP adapter's responses (spec 01 section 4,
//! spec 04 `C7`).
//!
//! They live beside the adapter instead of in it to keep each source file
//! small. Field declaration order is load-bearing: it fixes the JSON key
//! order to match Go's struct marshaling byte for byte.

use serde_json::value::RawValue;

/// Renders the rejection body of spec 01 section 4 (Go: errorBody).
pub(super) fn error_body(code: &str, message: &str) -> String {
    // Unreachable failure: serde cannot fail on String fields.
    serde_json::to_string(&ErrorEnvelope {
        error: ErrorDetail { code, message },
    })
    .expect("error envelope always serializes")
}

#[derive(serde::Serialize)]
struct ErrorDetail<'a> {
    code: &'a str,
    message: &'a str,
}

#[derive(serde::Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorDetail<'a>,
}

/// Field declaration order is load-bearing: it fixes the JSON key order to
/// match Go's struct marshaling byte for byte.
#[derive(serde::Serialize)]
pub(super) struct TextContent<'a> {
    #[serde(rename = "type")]
    pub(super) r#type: &'a str,
    pub(super) text: &'a str,
}

#[derive(serde::Serialize)]
pub(super) struct CallToolResult<'a> {
    pub(super) content: [TextContent<'a>; 1],
    #[serde(rename = "structuredContent")]
    pub(super) structured_content: &'a serde_json::Value,
    #[serde(rename = "isError")]
    pub(super) is_error: bool,
    /// Spec 04 `C7`: present only in the modern era.
    #[serde(rename = "resultType", skip_serializing_if = "Option::is_none")]
    pub(super) result_type: Option<&'a str>,
    /// Spec 04 `C7`: Jack implementation info, modern era only.
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub(super) meta: Option<ServerInfoMeta<'a>>,
}

#[derive(serde::Serialize)]
pub(super) struct ServerInfoMeta<'a> {
    #[serde(rename = "io.modelcontextprotocol/serverInfo")]
    pub(super) server_info: ServerInfo<'a>,
}

#[derive(serde::Serialize)]
pub(super) struct ServerInfo<'a> {
    pub(super) name: &'a str,
    pub(super) version: &'a str,
}

#[derive(serde::Serialize)]
pub(super) struct RpcResponse<'a> {
    pub(super) jsonrpc: &'a str,
    /// None serializes as null, matching Go's nil json.RawMessage.
    pub(super) id: Option<Box<RawValue>>,
    pub(super) result: CallToolResult<'a>,
}
