//! Integration tests for the candidate native tool
//! `jack.server.webhook_key` (spec 06 rule R7.6), driven DIRECTLY through
//! `NativeTools::call` and, for the routing, through `Verifier::verify` with a
//! canonically signed request. The tool keeps no state and needs no rotation
//! store, so this file is not platform-gated.

use std::sync::Arc;

use mcp_jack::client::auth::sign_request;
use mcp_jack::client::signer::{InMemorySigner, Signer};
use mcp_jack::encoding::encode_b64url;
use mcp_jack::error::JackError;
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateEdit, StateStore};
use mcp_jack::server::verify::{
    is_native_tool, Clock, Config, NativeCall, NativeTools, Request, Verifier, TOOL_SERVER_KEY,
};
use mcp_jack::server::webhook_key::{WebhookKeyTool, TOOL_SERVER_WEBHOOK_KEY};
use serde_json::{json, Value};

/// Audience both the tool and the verifier see.
const AUD: &str = "https://svc.example.test";
/// Fixture clock and header ts (Go: fixtureNow).
const NOW: i64 = 1_767_225_600;

/// The JWK set the Server Card publishes (content is opaque to the tool).
fn signing_keys() -> Value {
    json!({
        "keys": [{
            "kid": "webhook-key-1",
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        }],
    })
}

/// The egress ranges published next to the key set.
fn egress_ip_ranges() -> Vec<String> {
    vec!["192.0.2.0/24".to_owned(), "2001:db8::/32".to_owned()]
}

/// The exact answer the tool must produce (spec 06 rule R7.6).
fn expected_structured() -> Value {
    json!({
        "webhook_key": {
            "signing_keys": signing_keys(),
            "egress_ip_ranges": egress_ip_ranges(),
        },
    })
}

fn webhook_tool() -> WebhookKeyTool {
    WebhookKeyTool::new(signing_keys(), egress_ip_ranges())
}

/// A registered caller (seed 35); no signature is checked at this layer.
fn caller_entry() -> (InMemorySigner, RegistryEntry) {
    let signer = InMemorySigner::from_seed(&[35u8; 32]).expect("caller signer");
    let entry = RegistryEntry {
        kid: signer.kid().to_owned(),
        public_key: encode_b64url(&signer.public_key()),
        name: "caller".into(),
        admin: false,
        not_before: None,
        not_after: None,
    };
    (signer, entry)
}

/// NativeCall builder: every call looks authenticated (kid "kid-x", ts/now
/// pinned) and carries its own empty in-memory state store.
fn call_req<'a>(
    tool: &'a str,
    arguments: Option<&'a str>,
    caller: Option<&'a RegistryEntry>,
) -> NativeCall<'a> {
    NativeCall {
        tool,
        arguments: arguments.map(|text| {
            serde_json::value::RawValue::from_string(text.to_owned())
                .expect("arguments are valid JSON")
        }),
        caller,
        kid: "kid-x",
        ts: NOW,
        now: NOW,
        aud: AUD,
        state: Arc::new(MemoryState::new()) as Arc<dyn StateStore>,
        target: String::new(),
    }
}

fn assert_refusal(err: JackError, status: u16, code: &str, message: &str) {
    assert_eq!(err.http_status, status, "http status");
    assert_eq!(err.code, code, "code");
    assert_eq!(err.message, message, "message");
}

#[test]
fn no_caller_is_operation_denied() {
    let tool = webhook_tool();

    // Even on the right route, an unauthenticated call is denied.
    let mut req = call_req(TOOL_SERVER_WEBHOOK_KEY, None, None);
    let err =
        NativeTools::call(&tool, &mut req).expect_err("a call without a caller must be denied");
    assert_refusal(err, 403, "operation_denied", "operation is not permitted");

    // The caller gate precedes argument decoding: an unauthenticated call
    // stays 403 even when its arguments would be 400.
    let mut req = call_req(TOOL_SERVER_WEBHOOK_KEY, Some(r#"{"kid":"x"}"#), None);
    let err = NativeTools::call(&tool, &mut req)
        .expect_err("the caller check comes before the argument check");
    assert_refusal(err, 403, "operation_denied", "operation is not permitted");
}

#[test]
fn any_caller_gets_the_exact_result() {
    let (_signer, caller) = caller_entry();
    let tool = webhook_tool();

    // Absent arguments, JSON null and an empty object all mean "no
    // arguments" and serve the same exact answer.
    for arguments in [None, Some("null"), Some("{}")] {
        let mut req = call_req(TOOL_SERVER_WEBHOOK_KEY, arguments, Some(&caller));
        let result = NativeTools::call(&tool, &mut req)
            .unwrap_or_else(|e| panic!("arguments {arguments:?} must be served: {}", e.code));
        assert_eq!(result.structured, expected_structured());
    }

    // The candidate route stays OUT of the closed current-v1 allowlist.
    assert!(
        !is_native_tool(TOOL_SERVER_WEBHOOK_KEY),
        "jack.server.webhook_key must not become a current-v1 native tool"
    );
}

#[test]
fn other_tool_name_is_operation_denied() {
    let (_signer, caller) = caller_entry();
    let tool = webhook_tool();

    // The tool serves ONLY the explicit candidate route, even for a
    // current-v1 tool name and an authenticated caller.
    let mut req = call_req("jack.whoami", None, Some(&caller));
    let err =
        NativeTools::call(&tool, &mut req).expect_err("another tool name must be denied first");
    assert_refusal(err, 403, "operation_denied", "operation is not permitted");
}

#[test]
fn foreign_arguments_are_invalid_params() {
    let (_signer, caller) = caller_entry();
    let tool = webhook_tool();

    // Any member, array, scalar or malformed payload is invalid_params; the
    // class is judged on the raw JSON text.
    let bad = [
        r#"{"kid":"webhook-key-1"}"#,
        r#"{"arguments":null}"#,
        "[]",
        r#""null""#,
        "0",
        "true",
        "not json",
    ];
    for text in bad {
        let mut req = call_req(TOOL_SERVER_WEBHOOK_KEY, Some(text), Some(&caller));
        let err =
            NativeTools::call(&tool, &mut req).expect_err("a foreign argument payload must refuse");
        assert_refusal(
            err,
            400,
            "invalid_params",
            "an argument is missing, mistyped or out of range",
        );
    }
}

/// JSON-RPC tools/call body with the delayed-parameter shape of the spec.
fn call_body(tool: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"{tool}"}}}}"#)
}

/// Signs one request for the verifier (spec 01 section 3) with a canonical
/// 16-byte nonce derived from `counter`.
fn signed_request(signer: &InMemorySigner, tool: &str, counter: u64) -> Request {
    let mut nonce = [0u8; 16];
    nonce[8..].copy_from_slice(&counter.to_be_bytes());
    let body = call_body(tool);
    let signed = sign_request(signer, AUD, "POST", "/mcp", body.as_bytes(), &nonce, NOW)
        .expect("signing must succeed");
    Request {
        method: "POST".to_owned(),
        target: "/mcp".to_owned(),
        auth_values: vec![signed.header_value],
        body: body.into_bytes(),
    }
}

#[test]
fn verifier_routes_webhook_key_and_keeps_server_key_denied() {
    let (signer, caller) = caller_entry();
    let state = MemoryState::new();
    state
        .update(&mut |edit: &mut StateEdit| {
            edit.put_key(caller.clone());
            Ok(())
        })
        .expect("seed registry");
    let now: Clock = Arc::new(|| NOW);
    let verifier = Verifier::new(Config {
        aud: AUD.to_owned(),
        state: Arc::new(state),
        nonces: Arc::new(NonceStore::new()),
        audit: None,
        native: None,
        window_seconds: 30,
        now,
    })
    .expect("test config is valid")
    .with_webhook_keys(Arc::new(webhook_tool()));

    // The configured route reaches the tool and returns its exact result.
    let res = verifier.verify(&signed_request(&signer, TOOL_SERVER_WEBHOOK_KEY, 1));
    assert!(
        res.accepted,
        "jack.server.webhook_key must be accepted: {} {}",
        res.http_status, res.code
    );
    assert_eq!(res.tool, TOOL_SERVER_WEBHOOK_KEY, "tool name is reported");
    assert!(res.native, "a candidate route call is still native");
    assert_eq!(res.structured, Some(expected_structured()));

    // jack.server.key has no rotation handler here: the branch stays 403 and
    // never falls back to the ordinary native dispatcher.
    let res = verifier.verify(&signed_request(&signer, TOOL_SERVER_KEY, 2));
    assert!(!res.accepted, "jack.server.key MUST stay denied");
    assert_eq!(res.http_status, 403, "http status");
    assert_eq!(res.code, "operation_denied", "code");
    assert_eq!(res.message, "operation is not permitted", "message");
    assert!(res.structured.is_none(), "a refusal carries no result");
}
