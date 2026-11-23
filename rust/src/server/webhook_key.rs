//! Candidate native tool `jack.server.webhook_key` (spec 06 rule R7.6): the
//! key set and egress ranges a webhook receiver may cross-check against the
//! Server Card. Read-only candidate route: NOT part of the closed set of 11
//! current-v1 native tools (`is_native_tool` stays false; registration goes
//! through `Verifier::with_webhook_keys`), it takes no arguments, changes no
//! state and writes no audit event. Refusal classes, in check order: 403
//! operation_denied (wrong route or no caller), 400 invalid_params (any
//! argument payload other than absent, `null` or `{}`).

use serde_json::json;
use serde_json::value::RawValue;

use crate::error::{codes, JackError};
use crate::server::verify::{NativeCall, NativeResult, NativeTools};

/// Candidate native tool: the webhook key set and egress ranges published on
/// the Server Card (spec 06 rule R7.6). NOT part of the closed current-v1 set
/// (`is_native_tool` stays false); reachable only through a separately
/// configured handler (`Verifier::with_webhook_keys`).
pub const TOOL_SERVER_WEBHOOK_KEY: &str = "jack.server.webhook_key";

/// Builds the single 403 refusal of the tool: a wrong route and an
/// unauthenticated call are indistinguishable.
fn operation_denied() -> JackError {
    JackError::new(403, codes::OPERATION_DENIED, "operation is not permitted")
}

/// The tool takes no arguments; anything but absent, `null` or `{}` is
/// invalid_params, judged on the raw JSON text.
fn invalid_params() -> JackError {
    JackError::new(
        400,
        codes::INVALID_PARAMS,
        "an argument is missing, mistyped or out of range",
    )
}

/// Reports whether `params.arguments` carries no argument at all: the member
/// absent, JSON `null` or an empty object. Every other payload (a member, an
/// array, a scalar, malformed JSON) is refused.
fn no_arguments(arguments: &Option<Box<RawValue>>) -> bool {
    let Some(raw) = arguments else {
        return true;
    };
    match serde_json::from_str::<serde_json::Value>(raw.get()) {
        Ok(serde_json::Value::Null) => true,
        Ok(serde_json::Value::Object(members)) => members.is_empty(),
        _ => false,
    }
}

/// Serves only the explicit candidate route `jack.server.webhook_key`: it is
/// handed the JWK set the Server Card publishes (`{"keys":[...]}`) and the
/// egress ranges, keeps no state and returns them unchanged.
pub struct WebhookKeyTool {
    signing_keys: serde_json::Value,
    egress_ip_ranges: Vec<String>,
}

impl WebhookKeyTool {
    /// Keeps the published key set and ranges; nothing is parsed or validated
    /// here, so the answer is exactly the configured subset (spec 06 rule
    /// R7.6: the tool narrows the card and never widens it).
    pub fn new(signing_keys: serde_json::Value, egress_ip_ranges: Vec<String>) -> Self {
        Self {
            signing_keys,
            egress_ip_ranges,
        }
    }
}

impl NativeTools for WebhookKeyTool {
    fn call(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        if c.tool != TOOL_SERVER_WEBHOOK_KEY || c.caller.is_none() {
            return Err(operation_denied());
        }
        if !no_arguments(&c.arguments) {
            return Err(invalid_params());
        }
        Ok(NativeResult {
            structured: json!({
                "webhook_key": {
                    "signing_keys": self.signing_keys,
                    "egress_ip_ranges": self.egress_ip_ranges,
                },
            }),
        })
    }
}
