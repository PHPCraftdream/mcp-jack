//! Scenario implementations for interop-client (interop README section 6),
//! mirroring interop/go/client/scenarios.go scenario by scenario.

use std::collections::HashMap;
use std::sync::Arc;

use mcp_jack::client::error::ClientError;
use mcp_jack::client::rpc::{Client, Config};
use mcp_jack::client::signer::{InMemorySigner, Signer};
use mcp_jack::client::tools::{
    InviteCreateParams, InviteCreateResult, UserCreateParams, TOOL_ADMIN_USER_LIST,
    TOOL_ADMIN_USER_SET_SCOPES, TOOL_ENROLL, TOOL_WHOAMI,
};
use mcp_jack::client::transport::{
    HttpRequest, HttpResponse, SigningTransport, Transport, TransportError,
};
use mcp_jack::encoding::{decode_b64url_fixed, encode_b64url};
use mcp_jack::error::codes;

use super::net;
use super::{
    emit, fatal, hex_decode_32, is_auth_failure_code, parse_error_code, rpc_body, unix_now,
    Outcome, StepResult,
};

/// The documented expectation of an intermediate step (mirror of Go's
/// requireIntermediate arguments).
pub enum Intermediate {
    Ok,
    Rejected(u16, &'static str),
}

/// Shared per-run state (Go: env).
pub struct Env {
    pub scenario: String,
    pub base_url: String,
    pub aud: String,
    pub server_key: [u8; 32],
    pub args: HashMap<String, String>,
    pub seeds: HashMap<String, super::SeedKey>,
    pub primary: Arc<InMemorySigner>,
    pub primary_name: Option<String>,
    pub transport: Arc<net::TcpTransport>,
    /// One shared signed transport for typed calls; per-call signer
    /// overrides (enroll/rotate) pass through round_trip_as.
    pub raw_typed: SigningTransport<Arc<net::TcpTransport>>,
}

impl Env {
    fn arg(&self, k: &str) -> Option<&str> {
        self.args.get(k).map(|v| v.as_str())
    }

    /// The signer for a fixture identity name (Go: e.signer). No
    /// memoization: each scenario makes a handful of calls.
    fn signer(&self, name: &str) -> Arc<InMemorySigner> {
        if Some(name) == self.primary_name.as_deref() {
            return Arc::clone(&self.primary);
        }
        let entry = match self.seeds.get(name) {
            Some(e) => e,
            None => fatal(format!("unknown identity '{name}'")),
        };
        let seed = match hex_decode_32(&entry.seed_hex) {
            Ok(s) => s,
            Err(_) => fatal(format!("bad seed hex for identity '{name}'")),
        };
        match InMemorySigner::from_seed(&seed) {
            Ok(s) => Arc::new(s),
            Err(e) => fatal(format!("signer for '{name}': {e}")),
        }
    }

    /// The fixture kid of an identity (Go: e.kid).
    fn kid(&self, name: &str) -> String {
        match self.seeds.get(name) {
            Some(e) => e.kid.clone(),
            None => fatal(format!("unknown identity '{name}'")),
        }
    }

    /// The primary fixture name (Go: e.primaryName; empty when the seed did
    /// not match any entry, like Go's zero value).
    fn primary_name(&self) -> &str {
        self.primary_name.as_deref().unwrap_or("")
    }

    /// Step 0 of the invite-based scenarios: root mints an invite, checked
    /// against Intermediate::Ok; the code carries on success.
    fn invite_step(&self, idx: usize) -> Result<InviteCreateResult, StepResult> {
        let res = self.typed("root").admin_invite_create(&InviteCreateParams {
            scopes: vec!["read".to_owned()],
            kind: None,
            ttl_seconds: None,
            key_ttl_seconds: None,
        });
        match res {
            Ok(inv) => {
                if let Some(out) = self.require_intermediate(
                    idx,
                    self.sdk_step(Ok::<(), ClientError>(())),
                    Intermediate::Ok,
                ) {
                    return Err(out);
                }
                Ok(inv)
            }
            Err(err) => Err(
                match self.require_intermediate(
                    idx,
                    self.sdk_step(Err::<(), _>(err)),
                    Intermediate::Ok,
                ) {
                    Some(out) => out,
                    // Unreachable: a failed step never matches the expectation.
                    None => unreachable!(),
                },
            ),
        }
    }

    /// An SDK client for an identity (Go: e.typed; no memoization needed).
    fn typed(&self, name: &str) -> Client {
        match Client::new(Config {
            base_url: format!("{}/mcp", self.base_url),
            aud: self.aud.clone(),
            signer: self.signer(name),
            server_key: self.server_key,
            transport: Arc::clone(&self.transport) as Arc<dyn Transport>,
            now: None,
            nonce: None,
            window_seconds: 0,
        }) {
            Ok(c) => c,
            Err(e) => fatal(format!("client for '{name}': {e}")),
        }
    }

    /// Classifies an unsigned 401 (mirror of Go classifyTransportError's
    /// Unauthenticated branch). The Rust SDK never parses an untrusted body
    /// (rust/src/client/error.rs documents the divergence), but the harness
    /// must report the wire code — so it peeks the raw response stashed by
    /// the transport. Scenario execution is strictly sequential, so "last
    /// response" is exactly the offending one.
    fn unauth_result(&self, status: u16) -> StepResult {
        let code = self
            .transport
            .last_response()
            .and_then(|resp| parse_error_code(&resp.body));
        match code {
            Some(code) if is_auth_failure_code(&code) => StepResult::rejected(status, code),
            // Any other unsigned 401 must not be acted on beyond its status
            // (spec 01 section 5: absent header is missing_auth).
            _ => StepResult::client_error(codes::MISSING_AUTH),
        }
    }

    /// Classifies one SDK typed call (Go: sdkStep). Intermediate steps never
    /// report the payload (Go passes nil data), hence Result<(), _>.
    fn sdk_step(&self, res: Result<(), ClientError>) -> StepResult {
        match res {
            Ok(()) => StepResult {
                kind: Outcome::Ok,
                // Every ok wire result reports http_status 200; the payload of an
                // intermediate step is never reported (Go passes nil data).
                status: Some(200),
                code: None,
                data: None,
            },
            Err(ClientError::Http(e)) => StepResult::rejected(e.status, e.code),
            Err(ClientError::Unauthenticated(u)) => self.unauth_result(u.status),
            Err(ClientError::Rpc(e)) => StepResult::rejected(200, e.code.to_string()),
            Err(ClientError::Protocol(j)) => StepResult::client_error(j.code),
            // Go's default branch: a harness-level failure.
            Err(e @ (ClientError::Tool(_) | ClientError::Streaming | ClientError::Client(_))) => {
                fatal(format!("unexpected error from typed call: {e}"))
            }
        }
    }

    /// One tools/call through the shared signed transport with an explicit
    /// signer (Go: typedRawCall).
    fn typed_raw_call(
        &self,
        signer: &dyn Signer,
        tool: &str,
        arguments: Option<&str>,
    ) -> StepResult {
        let body = rpc_body(1, tool, arguments);
        let req = HttpRequest {
            method: "POST".to_owned(),
            url: format!("{}/mcp", self.base_url),
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body,
        };
        match self.raw_typed.round_trip_as(signer, None, req) {
            Ok(resp) => {
                if (200..300).contains(&resp.status) {
                    self.result_from_2xx(&resp.body)
                } else {
                    StepResult::rejected(
                        resp.status,
                        parse_error_code(&resp.body).unwrap_or_default(),
                    )
                }
            }
            Err(TransportError::Unauthenticated(u)) => self.unauth_result(u.status),
            Err(TransportError::Protocol(j)) => StepResult::client_error(j.code),
            Err(e) => fatal(format!("unexpected error from typed call: {e}")),
        }
    }

    /// Classifies a signature-verified 2xx JSON-RPC envelope; the result
    /// member is kept verbatim (Go: resultFrom2xx).
    fn result_from_2xx(&self, body: &[u8]) -> StepResult {
        #[derive(serde::Deserialize)]
        struct Envelope {
            result: Option<Box<serde_json::value::RawValue>>,
            error: Option<ErrorMember>,
        }
        #[derive(serde::Deserialize)]
        struct ErrorMember {
            code: Box<serde_json::value::RawValue>,
        }
        let envelope: Envelope = match serde_json::from_slice(body) {
            Ok(e) => e,
            Err(e) => fatal(format!("malformed json-rpc envelope: {e}")),
        };
        if let Some(err) = envelope.error {
            // Go rawMessageString: strip one quote pair from the raw code.
            let code = err.code.get().trim_matches('"').to_owned();
            return StepResult::rejected(200, code);
        }
        let Some(result) = envelope.result else {
            fatal("malformed json-rpc envelope: no result member");
        };
        StepResult::ok(result)
    }

    /// Signs one request with a random (or pinned) nonce and timestamp, then
    /// sends it (Go: rawCall).
    fn raw_call(
        &self,
        signer: &dyn Signer,
        method: &str,
        target: &str,
        body: &[u8],
        ts_override: Option<i64>,
        nonce_b64: Option<&str>,
    ) -> StepResult {
        let nonce = match nonce_b64 {
            Some(b64) => {
                let n = match decode_b64url_fixed(b64, 16) {
                    Ok(n) => n,
                    Err(e) => fatal(format!("nonce must decode to 16 bytes: {e}")),
                };
                <[u8; 16]>::try_from(n).expect("decode_b64url_fixed(_, 16) yields 16 bytes")
            }
            None => match mcp_jack::client::random_nonce() {
                Ok(n) => n,
                Err(e) => fatal(format!("nonce: {e}")),
            },
        };
        let ts = ts_override.unwrap_or_else(unix_now);
        let signed = match mcp_jack::client::sign_request(
            signer, &self.aud, method, target, body, &nonce, ts,
        ) {
            Ok(s) => s,
            Err(e) => fatal(format!("SignRequest: {e}")),
        };
        let resp = match net::send_exact(
            &self.transport,
            method,
            &format!("{}{}", self.base_url, target),
            &signed.header_value,
            method == "POST",
            body,
        ) {
            Ok(r) => r,
            Err(msg) => fatal(msg),
        };
        self.classify_wire(resp, &signed.auth.sig)
    }

    /// Sends exact pre-signed bytes and classifies the response (Go:
    /// sendWithHeader).
    fn classify_wire(&self, resp: HttpResponse, request_sig: &str) -> StepResult {
        let header_values = resp.header_values("Jack-Auth");
        let wire_code = parse_error_code(&resp.body).unwrap_or_default();
        let now = unix_now();

        // 401 answers to failed authentication may be unsigned; if a header
        // IS present we still verify it and fail the client on a bad
        // signature.
        if resp.status == 401 && is_auth_failure_code(&wire_code) {
            if !header_values.is_empty() {
                if let Err(j) = mcp_jack::signing::verify_response(
                    &self.server_key,
                    resp.status as i64,
                    &header_values,
                    request_sig,
                    &resp.body,
                    now,
                    0,
                ) {
                    return StepResult::client_error(j.code);
                }
            }
            return StepResult::rejected(resp.status, wire_code);
        }

        // Everything else must carry a valid signature (spec 01 section 5).
        if let Err(j) = mcp_jack::signing::verify_response(
            &self.server_key,
            resp.status as i64,
            &header_values,
            request_sig,
            &resp.body,
            now,
            0,
        ) {
            return StepResult::client_error(j.code);
        }
        if (200..300).contains(&resp.status) {
            self.result_from_2xx(&resp.body)
        } else {
            StepResult::rejected(resp.status, wire_code)
        }
    }

    /// Checks a step's documented expectation; None means proceed (Go:
    /// requireIntermediate).
    fn require_intermediate(
        &self,
        idx: usize,
        got: StepResult,
        want: Intermediate,
    ) -> Option<StepResult> {
        let matched = match want {
            Intermediate::Ok => got.kind == Outcome::Ok,
            Intermediate::Rejected(status, code) => {
                got.kind == Outcome::Rejected
                    && got.status == Some(status)
                    && got.code.as_deref() == Some(code)
            }
        };
        if matched {
            return None;
        }
        Some(StepResult::step_failure(idx, &got))
    }
}

/// Dispatches one scenario and emits the ONE stdout line (Go: the scenarios
/// map plus main's emit).
pub fn run(env: &Env, scenario: &str) -> ! {
    let out = match scenario {
        "ping" => ping(env),
        "echo" => echo(env),
        "whoami" => whoami(env),
        "denied-tool" => denied_tool(env),
        "unmapped-tool" => unmapped_tool(env),
        "unknown-key" => unknown_key(env),
        "replay" => replay(env),
        "clock-skew" => clock_skew(env),
        "tampered-body" => tampered_body(env),
        "bad-server-key" => bad_server_key(env),
        "expired-key" => expired_key(env),
        "key-not-yet-valid" => key_not_yet_valid(env),
        "stream" => stream(env),
        "agent-admin" => agent_admin(env),
        "invalid-request" => invalid_request(env),
        "unknown-native-tool" => unknown_native_tool(env),
        "enroll" => enroll(env),
        "enroll-used-invite" => enroll_used_invite(env),
        "rotate" => rotate(env),
        "admin-create" => admin_create(env),
        "revoke-key" => revoke_key(env),
        "last-admin" => last_admin(env),
        _ => fatal(format!("unknown scenario '{scenario}'")),
    };
    emit(&env.scenario, out)
}

fn ping(e: &Env) -> StepResult {
    e.raw_call(
        e.primary.as_ref(),
        "POST",
        "/mcp",
        &rpc_body(1, "", None),
        None,
        None,
    )
}

fn echo(e: &Env) -> StepResult {
    let Some(text) = e.arg("text") else {
        fatal("echo requires --arg text=...");
    };
    e.raw_call(
        e.primary.as_ref(),
        "POST",
        "/mcp",
        &rpc_body(
            1,
            "echo",
            Some(&serde_json::json!({ "text": text }).to_string()),
        ),
        None,
        None,
    )
}

fn whoami(e: &Env) -> StepResult {
    e.typed_raw_call(e.primary.as_ref(), TOOL_WHOAMI, None)
}

fn denied_tool(e: &Env) -> StepResult {
    e.raw_call(
        e.primary.as_ref(),
        "POST",
        "/mcp",
        &rpc_body(1, "svc.config.set", None),
        None,
        None,
    )
}

fn unmapped_tool(e: &Env) -> StepResult {
    e.raw_call(
        e.primary.as_ref(),
        "POST",
        "/mcp",
        &rpc_body(1, "other.tool", None),
        None,
        None,
    )
}

fn unknown_key(e: &Env) -> StepResult {
    e.raw_call(
        e.primary.as_ref(),
        "POST",
        "/mcp",
        &rpc_body(1, "svc.status", None),
        None,
        None,
    )
}

fn replay(e: &Env) -> StepResult {
    // Build the exact bytes and header ONCE; both sends reuse them. ping is
    // answered by the fixed handler (scenarios.json replay step 0);
    // svc.status would get a signed -32601 instead.
    let body = rpc_body(1, "", None);
    let nonce = match mcp_jack::client::random_nonce() {
        Ok(n) => n,
        Err(err) => fatal(format!("nonce: {err}")),
    };
    let signed = match mcp_jack::client::sign_request(
        e.primary.as_ref(),
        &e.aud,
        "POST",
        "/mcp",
        &body,
        &nonce,
        unix_now(),
    ) {
        Ok(s) => s,
        Err(err) => fatal(format!("SignRequest: {err}")),
    };
    let send = || -> StepResult {
        match net::send_exact(
            &e.transport,
            "POST",
            &format!("{}{}", e.base_url, "/mcp"),
            &signed.header_value,
            true,
            &body,
        ) {
            Ok(resp) => e.classify_wire(resp, &signed.auth.sig),
            Err(msg) => fatal(msg),
        }
    };
    if let Some(out) = e.require_intermediate(0, send(), Intermediate::Ok) {
        return out;
    }
    send()
}

fn clock_skew(e: &Env) -> StepResult {
    let ts = unix_now() - 120;
    e.raw_call(
        e.primary.as_ref(),
        "POST",
        "/mcp",
        &rpc_body(1, "svc.status", None),
        Some(ts),
        None,
    )
}

fn tampered_body(e: &Env) -> StepResult {
    let body = rpc_body(1, "svc.restart", None);
    let nonce = match mcp_jack::client::random_nonce() {
        Ok(n) => n,
        Err(err) => fatal(format!("nonce: {err}")),
    };
    let signed = match mcp_jack::client::sign_request(
        e.primary.as_ref(),
        &e.aud,
        "POST",
        "/mcp",
        &body,
        &nonce,
        unix_now(),
    ) {
        Ok(s) => s,
        Err(err) => fatal(format!("SignRequest: {err}")),
    };
    // Mutate AFTER signing: final '}' (0x7D) becomes '|' (0x7C).
    let mut mutated = body.clone();
    let last = mutated.len() - 1;
    mutated[last] = 0x7C;
    match net::send_exact(
        &e.transport,
        "POST",
        &format!("{}{}", e.base_url, "/mcp"),
        &signed.header_value,
        true,
        &mutated,
    ) {
        Ok(resp) => e.classify_wire(resp, &signed.auth.sig),
        Err(msg) => fatal(msg),
    }
}

// The harness pins the WRONG key (mallory) for this scenario; the signed
// 200 answer then fails client verification.
fn bad_server_key(e: &Env) -> StepResult {
    e.raw_call(
        e.primary.as_ref(),
        "POST",
        "/mcp",
        &rpc_body(1, "", None),
        None,
        None,
    )
}

fn expired_key(e: &Env) -> StepResult {
    e.raw_call(
        e.primary.as_ref(),
        "POST",
        "/mcp",
        &rpc_body(1, "svc.status", None),
        None,
        None,
    )
}

fn key_not_yet_valid(e: &Env) -> StepResult {
    e.raw_call(
        e.primary.as_ref(),
        "POST",
        "/mcp",
        &rpc_body(1, "svc.status", None),
        None,
        None,
    )
}

fn stream(e: &Env) -> StepResult {
    e.raw_call(e.primary.as_ref(), "GET", "/sse", &[], None, None)
}

fn agent_admin(e: &Env) -> StepResult {
    e.typed_raw_call(e.primary.as_ref(), TOOL_ADMIN_USER_LIST, None)
}

fn invalid_request(e: &Env) -> StepResult {
    e.raw_call(
        e.primary.as_ref(),
        "POST",
        "/mcp",
        b"this is not JSON",
        None,
        None,
    )
}

fn unknown_native_tool(e: &Env) -> StepResult {
    e.raw_call(
        e.primary.as_ref(),
        "POST",
        "/mcp",
        &rpc_body(1, "jack.admin.nuke", None),
        None,
        None,
    )
}

fn enroll(e: &Env) -> StepResult {
    let name = e.primary_name();
    let inv = match e.invite_step(0) {
        Ok(inv) => inv,
        Err(out) => return out,
    };
    let step1 = e.sdk_step(
        e.typed(name)
            .enroll(&inv.code, "newbie", e.primary.as_ref())
            .map(|_| ()),
    );
    if let Some(out) = e.require_intermediate(1, step1, Intermediate::Ok) {
        return out;
    }
    e.typed_raw_call(e.primary.as_ref(), TOOL_WHOAMI, None)
}

fn enroll_used_invite(e: &Env) -> StepResult {
    let inv = match e.invite_step(0) {
        Ok(inv) => inv,
        Err(out) => return out,
    };
    let step1 = e.sdk_step(
        e.typed("newbie")
            .enroll(&inv.code, "newbie", e.signer("newbie").as_ref())
            .map(|_| ()),
    );
    if let Some(out) = e.require_intermediate(1, step1, Intermediate::Ok) {
        return out;
    }
    // Argument keys are written in json! in spec order; serde_json Value maps
    // are alphabetical, and code,name,public_key IS alphabetical order.
    let args = serde_json::json!({
        "code": inv.code,
        "name": "newbie2",
        "public_key": encode_b64url(&e.primary.public_key()),
    });
    e.typed_raw_call(e.primary.as_ref(), TOOL_ENROLL, Some(&args.to_string()))
}

fn rotate(e: &Env) -> StepResult {
    let name = e.primary_name();
    let step0 = e.sdk_step(
        e.typed(name)
            .rotate_key(e.signer("newbie").as_ref())
            .map(|_| ()),
    );
    if let Some(out) = e.require_intermediate(0, step0, Intermediate::Ok) {
        return out;
    }
    // The old alice key must now be dead (unsigned 401 unknown_key); the
    // code comes from unauth_result's stash, mirroring Go's parsed-code
    // behavior.
    let step1 = e.sdk_step(e.typed(name).whoami().map(|_| ()));
    if let Some(out) = e.require_intermediate(1, step1, Intermediate::Rejected(401, "unknown_key"))
    {
        return out;
    }
    e.typed_raw_call(e.signer("newbie").as_ref(), TOOL_WHOAMI, None)
}

fn admin_create(e: &Env) -> StepResult {
    let inv = match e.invite_step(0) {
        Ok(inv) => inv,
        Err(out) => return out,
    };
    let step1 = e.sdk_step(
        e.typed("root")
            .admin_user_create(&UserCreateParams {
                name: "dave".to_owned(),
                public_key: encode_b64url(&e.primary.public_key()),
                scopes: vec!["read".to_owned()],
                kind: None,
                not_before: None,
                not_after: None,
            })
            .map(|_| ()),
    );
    if let Some(out) = e.require_intermediate(1, step1, Intermediate::Ok) {
        return out;
    }
    let step2 = e.sdk_step(
        e.typed("newbie")
            .enroll(&inv.code, "newbie", e.signer("newbie").as_ref())
            .map(|_| ()),
    );
    if let Some(out) = e.require_intermediate(2, step2, Intermediate::Ok) {
        return out;
    }
    e.typed_raw_call(e.primary.as_ref(), TOOL_WHOAMI, None)
}

fn revoke_key(e: &Env) -> StepResult {
    let step0 = e.sdk_step(e.typed("root").admin_user_revoke(&e.kid("bob")).map(|_| ()));
    if let Some(out) = e.require_intermediate(0, step0, Intermediate::Ok) {
        return out;
    }
    e.typed_raw_call(e.primary.as_ref(), TOOL_WHOAMI, None)
}

fn last_admin(e: &Env) -> StepResult {
    // kid,scopes is alphabetical, so json!'s Value map keeps spec order.
    let args = serde_json::json!({
        "kid": e.primary.kid(),
        "scopes": ["read"],
    });
    e.typed_raw_call(
        e.primary.as_ref(),
        TOOL_ADMIN_USER_SET_SCOPES,
        Some(&args.to_string()),
    )
}
