//! Request verifier: authentication + authorization (Go: server/verify.go).

use std::sync::Arc;

use serde_json::value::RawValue;

use crate::auth_header::{parse_request_auth, RequestAuth};
use crate::encoding::{decode_b64url_fixed, key_id};
use crate::error::{codes, JackError};
use crate::server::audit::{AuditEvent, AuditSink, AUDIT_FAILURE, AUDIT_SUCCESS};
use crate::server::nonce::NonceStore;
use crate::server::policy::{Decision, Policy};
use crate::server::state::{RegistryEntry, StateStore};
use crate::signing::{request_signing_string, DEFAULT_WINDOW_SECONDS};

/// Protocol-native tool: enroll a new key (spec 03 section 3.2).
pub const TOOL_ENROLL: &str = "jack.enroll";
/// Protocol-native tool: identify the caller (spec 03).
pub const TOOL_WHOAMI: &str = "jack.whoami";
/// Protocol-native tool: rotate a key (spec 03 section 3.1).
pub const TOOL_ROTATE_KEY: &str = "jack.key.rotate";
/// Protocol-native admin tool (spec 03 section 6).
pub const TOOL_ADMIN_USER_LIST: &str = "jack.admin.user.list";
/// Protocol-native admin tool (spec 03 section 6).
pub const TOOL_ADMIN_USER_GET: &str = "jack.admin.user.get";
/// Protocol-native admin tool (spec 03 section 4).
pub const TOOL_ADMIN_USER_CREATE: &str = "jack.admin.user.create";
/// Protocol-native admin tool (spec 03 section 4).
pub const TOOL_ADMIN_USER_SET_SCOPES: &str = "jack.admin.user.set_scopes";
/// Protocol-native admin tool (spec 03 section 4).
pub const TOOL_ADMIN_USER_REVOKE: &str = "jack.admin.user.revoke";
/// Protocol-native admin tool (spec 03 section 3.2).
pub const TOOL_ADMIN_INVITE_CREATE: &str = "jack.admin.invite.create";
/// Protocol-native admin tool (spec 03 section 3.2).
pub const TOOL_ADMIN_INVITE_LIST: &str = "jack.admin.invite.list";
/// Protocol-native admin tool (spec 03 section 3.2).
pub const TOOL_ADMIN_INVITE_REVOKE: &str = "jack.admin.invite.revoke";

/// The closed set of protocol-native tools; anything else starting with
/// "jack." is unknown and denied (Go: nativeTools).
const NATIVE_TOOLS: [&str; 11] = [
    TOOL_ENROLL,
    TOOL_WHOAMI,
    TOOL_ROTATE_KEY,
    TOOL_ADMIN_USER_LIST,
    TOOL_ADMIN_USER_GET,
    TOOL_ADMIN_USER_CREATE,
    TOOL_ADMIN_USER_SET_SCOPES,
    TOOL_ADMIN_USER_REVOKE,
    TOOL_ADMIN_INVITE_CREATE,
    TOOL_ADMIN_INVITE_LIST,
    TOOL_ADMIN_INVITE_REVOKE,
];

/// Reports whether `name` is one of the protocol-native tools.
pub fn is_native_tool(name: &str) -> bool {
    NATIVE_TOOLS.contains(&name)
}

/// Reports whether calls to the tool are written to the audit sink
/// (spec 03 section 8: enroll, rotate and every admin tool).
fn audited_tool(name: &str) -> bool {
    name == TOOL_ENROLL || name == TOOL_ROTATE_KEY || name.starts_with("jack.admin.")
}

/// The verifier clock: Unix seconds. The verifier NEVER reads a wall clock;
/// callers inject their time source (spec 01 section 4 runner rules).
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// What a protocol-native tool handler receives (Go: NativeCall).
pub struct NativeCall<'a> {
    /// Tool name, one of the `TOOL_*` constants.
    pub tool: &'a str,
    /// `params.arguments` as sent; None only when the member is absent (a
    /// null stays Some). Raw JSON text is preserved so integer arguments can
    /// be judged on their text (spec 03 section 3: no fraction, no exponent;
    /// -0 is 0).
    pub arguments: Option<Box<RawValue>>,
    /// Registry entry of the authenticated key; None when enrolling with an
    /// unregistered kid.
    pub caller: Option<&'a RegistryEntry>,
    /// Kid from the Jack-Auth header (for enrollment, the hash of the
    /// submitted key).
    pub kid: &'a str,
    /// ts parameter of the Jack-Auth header (rotate proofs bind it).
    pub ts: i64,
    /// Verifier clock, Unix seconds.
    pub now: i64,
    /// Server audience string.
    pub aud: &'a str,
    /// Registry and invite store; handlers change it only through
    /// `StateStore::update`.
    pub state: Arc<dyn StateStore>,
    /// OUTPUT: handler sets what the audit event names as target (kid,
    /// invite id or name), even on failure.
    pub target: String,
}

/// Successful outcome of a native tool (Go: NativeResult). Null means "no
/// structured content".
#[derive(Debug)]
pub struct NativeResult {
    /// Becomes the `structuredContent` of the MCP CallToolResult.
    pub structured: serde_json::Value,
}

/// Implements the jack.* tools (spec 03). Returns a JackError for every
/// protocol rejection; the verifier records the audit event and the HTTP
/// adapter turns the outcome into a response.
pub trait NativeTools: Send + Sync {
    fn call(&self, c: &mut NativeCall) -> Result<NativeResult, JackError>;
}

/// Verifier configuration (Go: Config).
pub struct Config {
    /// Audience signed into every request; compared with this value, never
    /// with the Host header (spec 01 section 3.1).
    pub aud: String,
    /// Registry and invite store.
    pub state: Arc<dyn StateStore>,
    /// Records seen (kid, nonce) pairs.
    pub nonces: Arc<NonceStore>,
    /// Maps MCP operations to scopes.
    pub policy: Arc<Policy>,
    /// Audit sink for protocol-native calls; optional.
    pub audit: Option<Arc<dyn AuditSink>>,
    /// Implements the jack.* tools; None denies every jack.* tool.
    pub native: Option<Arc<dyn NativeTools>>,
    /// Timestamp window seconds; <= 0 means DEFAULT_WINDOW_SECONDS (Go: zero
    /// means DefaultWindow).
    pub window_seconds: i64,
    /// Verifier clock, Unix seconds.
    pub now: Clock,
}

/// Authenticates and authorizes requests (spec 01 section 4, spec 02
/// section 4).
pub struct Verifier {
    cfg: Config,
}

impl Verifier {
    /// Validates cfg (Go: NewVerifier). Only aud can be invalid in Rust: the
    /// other Go checks are types here (Arc is non-null by construction).
    pub fn new(cfg: Config) -> Result<Self, String> {
        if cfg.aud.is_empty() {
            return Err("server: Config.Aud must be non-empty".to_owned());
        }
        Ok(Self { cfg })
    }

    /// Effective window: a non-positive window means the default (Go:
    /// `if cfg.Window <= 0`).
    fn window(&self) -> i64 {
        if self.cfg.window_seconds <= 0 {
            DEFAULT_WINDOW_SECONDS
        } else {
            self.cfg.window_seconds
        }
    }

    /// Runs the pipeline of spec 01 section 4 and spec 02 section 4 on one
    /// request. Stops at the first failing step; a rejection never reveals
    /// more than its code.
    pub fn verify(&self, req: &Request) -> VerifyResult {
        let now = (self.cfg.now)();
        let auth_values: Vec<&str> = req.auth_values.iter().map(String::as_str).collect();

        let auth = match parse_request_auth(&auth_values) {
            Ok(auth) => auth,
            Err(err) => return rejection_from(&err),
        };

        // Step 4-5: resolve the verify key — either the registered entry or,
        // via the enrollment exception, a valid submitted key hashing to kid.
        let caller = self.cfg.state.lookup(&auth.kid);
        let verify_key = match caller.as_ref() {
            Some(entry) => {
                if !entry_active(entry, now) {
                    return fail(
                        VerifyResult::default(),
                        401,
                        codes::KEY_INACTIVE,
                        "key is not active",
                    );
                }
                match decode_b64url_fixed(&entry.public_key, 32) {
                    Ok(key) => key,
                    // Registry data is operator-owned; a malformed key there
                    // is a server fault, not a client rejection.
                    Err(_) => {
                        return fail(
                            VerifyResult::default(),
                            500,
                            "internal_error",
                            "registry holds an invalid public key",
                        )
                    }
                }
            }
            None => match enrollment_key(req, &auth.kid) {
                Ok(key) => key,
                Err(rej) => return rej,
            },
        };

        // Step 6: window. abs_diff cannot overflow where `now - ts` would.
        let window = self.window();
        if now.abs_diff(auth.ts) > window.unsigned_abs() {
            return fail(
                VerifyResult::default(),
                401,
                codes::TIMESTAMP_OUT_OF_WINDOW,
                "timestamp is outside the acceptance window",
            );
        }

        // Step 7: signature. The parser already checked the sig encoding;
        // the branch is kept to mirror Go and survive refactors.
        let sig = match decode_b64url_fixed(&auth.sig, 64) {
            Ok(sig) => sig,
            Err(_) => {
                return fail(
                    VerifyResult::default(),
                    401,
                    codes::BAD_SIGNATURE,
                    "malformed signature",
                )
            }
        };
        let signing = request_signing_string(
            &req.method,
            &req.target,
            &self.cfg.aud,
            &auth.kid,
            auth.ts,
            &auth.nonce,
            &req.body,
        );
        if !crate::ed25519::verify(&verify_key, signing.as_bytes(), &sig) {
            return fail(
                VerifyResult::default(),
                401,
                codes::BAD_SIGNATURE,
                "signature does not verify",
            );
        }

        // Step 8: the nonce is recorded only after the signature verified, so
        // unauthenticated requests cannot fill the cache (spec 01 section 4).
        // Store polarity: true means a live REPLAY.
        if self
            .cfg
            .nonces
            .check_and_record(&auth.kid, &auth.nonce, now, auth.ts + window)
        {
            return fail(
                VerifyResult::default(),
                401,
                codes::REPLAYED_NONCE,
                "nonce was already used",
            );
        }

        let res = VerifyResult {
            kid: auth.kid.clone(),
            nonce_recorded: true,
            request_sig: auth.sig.clone(),
            ..Default::default()
        };
        self.authorize(req, &auth, now, caller.as_ref(), res)
    }

    /// Step 9: body shape, protocol-native tools, policy (Go: authorize).
    fn authorize(
        &self,
        req: &Request,
        auth: &RequestAuth,
        now: i64,
        caller: Option<&RegistryEntry>,
        mut res: VerifyResult,
    ) -> VerifyResult {
        // GET carries no body; nothing to classify.
        if req.method == "GET" {
            res.accepted = true;
            return res;
        }

        let Some(msg) = classify_body(&req.body) else {
            return fail(
                res,
                400,
                codes::INVALID_REQUEST,
                "the body is not an acceptable JSON-RPC object",
            );
        };
        res.rpc_id = msg.id.clone();
        if msg.kind == MessageKind::Response {
            res.accepted = true;
            return res;
        }
        if let Some(tool) = &msg.tool {
            res.tool = tool.clone();
        }

        // Owned clone: the arguments move out of msg while tool is alive.
        let jack_tool = msg.tool.clone().filter(|t| t.starts_with("jack."));
        if let Some(tool) = jack_tool {
            // Set BEFORE any denial: a denied native call is still native.
            res.native = true;
            // Unknown jack.* tool or missing handler: 403 with NO audit
            // event — the call never reached a tool.
            let Some(handler) = self.cfg.native.as_ref().filter(|_| is_native_tool(&tool)) else {
                return fail(
                    res,
                    403,
                    codes::OPERATION_DENIED,
                    "operation is not permitted",
                );
            };
            let mut call = NativeCall {
                tool: &tool,
                arguments: msg.arguments,
                caller,
                kid: &auth.kid,
                ts: auth.ts,
                now,
                aud: &self.cfg.aud,
                state: Arc::clone(&self.cfg.state),
                target: String::new(),
            };
            let out = handler.call(&mut call);

            // Audit only the tools spec 03 section 8 lists; the event is
            // returned on res even when no sink is configured, and a sink
            // error never changes the verdict.
            if audited_tool(call.tool) {
                let mut event = AuditEvent {
                    time: now,
                    tool: call.tool.to_owned(),
                    outcome: AUDIT_SUCCESS.to_owned(),
                    code: String::new(),
                    actor_kid: auth.kid.clone(),
                    actor_name: caller.map(|c| c.name.clone()).unwrap_or_default(),
                    target: call.target.clone(),
                };
                if let Err(jerr) = &out {
                    event.outcome = AUDIT_FAILURE.to_owned();
                    event.code = jerr.code.clone();
                }
                res.audit = Some(event.clone());
                if let Some(sink) = self.cfg.audit.as_ref() {
                    let _ = sink.record(event);
                }
            }

            return match out {
                Ok(native_result) => {
                    res.accepted = true;
                    res.structured = Some(native_result.structured);
                    res
                }
                Err(jerr) => fail(res, jerr.http_status, &jerr.code, &jerr.message),
            };
        }

        // Unreachable: only a jack.enroll request passes step 4 without a
        // registry entry, and it was handled above.
        let Some(caller) = caller else {
            return fail(res, 401, codes::UNKNOWN_KEY, "unknown key");
        };
        let decision: Decision = self.cfg.policy.evaluate(&msg.method, msg.tool.as_deref());
        if !decision.allowed {
            return fail(
                res,
                403,
                codes::OPERATION_DENIED,
                "operation is not permitted",
            );
        }
        if let Some(scope) = &decision.scope {
            if !caller.scopes.iter().any(|s| s == scope) {
                return fail(
                    res,
                    403,
                    codes::INSUFFICIENT_SCOPE,
                    "the key lacks the required scope",
                );
            }
        }
        res.accepted = true;
        res
    }
}

/// One HTTP request reduced to what verification needs (Go: Request).
#[derive(Debug)]
pub struct Request {
    /// HTTP method.
    pub method: String,
    /// Origin-form request target exactly as received.
    pub target: String,
    /// Values of every Jack-Auth header, in order.
    pub auth_values: Vec<String>,
    /// The exact request body.
    pub body: Vec<u8>,
}

/// Outcome of `Verifier::verify` (Go: Result).
#[derive(Debug, Default)]
pub struct VerifyResult {
    /// True when the request is authenticated and authorized.
    pub accepted: bool,
    /// Authenticated key id (empty when authentication failed).
    pub kid: String,
    /// HTTP status, code and message of a rejection.
    pub http_status: u16,
    pub code: String,
    pub message: String,
    /// True when the request consumed its nonce (authentication succeeded,
    /// including requests rejected only at authorization; false for replays).
    pub nonce_recorded: bool,
    /// sig of the request; the response is bound to it.
    pub request_sig: String,
    /// id of the JSON-RPC object as sent (raw JSON text; None for GET,
    /// notifications without id, and non-JSON bodies).
    pub rpc_id: Option<String>,
    /// Tool name of a tools/call request ("" otherwise).
    pub tool: String,
    /// True when the request called a protocol-native tool.
    pub native: bool,
    /// structuredContent of a successful native tool call.
    pub structured: Option<serde_json::Value>,
    /// Audit event written for the call, if any.
    pub audit: Option<AuditEvent>,
}

/// Builds the rejection form of a result: only status, code and message.
fn fail(mut res: VerifyResult, http_status: u16, code: &str, message: &str) -> VerifyResult {
    res.http_status = http_status;
    res.code = code.to_owned();
    res.message = message.to_owned();
    res
}

/// Maps a JackError to a rejection result (Go: rejectionFrom; every error
/// this crate produces is a JackError, so the fallback arm of Go is gone).
fn rejection_from(err: &JackError) -> VerifyResult {
    fail(
        VerifyResult::default(),
        err.http_status,
        &err.code,
        &err.message,
    )
}

/// Reports whether now is inside the entry's validity interval
/// (spec 02 section 1: not_before <= now < not_after).
fn entry_active(entry: &RegistryEntry, now: i64) -> bool {
    entry.not_before.is_none_or(|t| t <= now) && entry.not_after.is_none_or(|t| now < t)
}

/// Implements the one exception to "unknown key is rejected" (spec 01
/// section 4, spec 03 section 3.2): an unregistered kid is accepted for a
/// POST tools/call of jack.enroll whose submitted public key is valid and
/// hashes to kid. The request is then verified against that submitted key.
/// Any shape mismatch is the plain unknown-key rejection; only an invalid
/// submitted key upgrades to 400 key_rejected, and validity is checked
/// BEFORE the hash comparison.
// allow(result_large_err): the Err arm is the rare rejection path; boxing it
// would obscure the Go shape it mirrors for no real gain.
#[allow(clippy::result_large_err)]
fn enrollment_key(req: &Request, kid: &str) -> Result<Vec<u8>, VerifyResult> {
    let unknown = || {
        fail(
            VerifyResult::default(),
            401,
            codes::UNKNOWN_KEY,
            "unknown key",
        )
    };
    if req.method != "POST" {
        return Err(unknown());
    }
    let Some(msg) = classify_body(&req.body) else {
        return Err(unknown());
    };
    if msg.kind != MessageKind::Request
        || msg.method != "tools/call"
        || msg.tool.as_deref() != Some(TOOL_ENROLL)
    {
        return Err(unknown());
    }
    // arguments absent (None) or null ("null", which fails to parse into a
    // Map) are both shape errors -> unknown key.
    let Some(arguments) = &msg.arguments else {
        return Err(unknown());
    };
    let Ok(args) =
        serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(arguments.get())
    else {
        return Err(unknown());
    };
    // A null/number/bool public_key is not a string -> unknown key.
    let Some(submitted) = args.get("public_key").and_then(serde_json::Value::as_str) else {
        return Err(unknown());
    };
    let key = match decode_b64url_fixed(submitted, 32) {
        Ok(key) => key,
        Err(_) => {
            return Err(fail(
                VerifyResult::default(),
                400,
                codes::KEY_REJECTED,
                "public key is not acceptable",
            ))
        }
    };
    // Validity precedes the hash comparison (spec 03 section 2), so a
    // small-order key is key_rejected even when its hash already mismatches.
    if crate::ed25519::validate_public_key(&key).is_err() {
        return Err(fail(
            VerifyResult::default(),
            400,
            codes::KEY_REJECTED,
            "public key is not acceptable",
        ));
    }
    if key_id(&key) != kid {
        return Err(unknown());
    }
    Ok(key)
}

/// Request or client answer (Go: kindRequest / kindResponse).
#[derive(Debug, Clone, PartialEq, Eq)]
enum MessageKind {
    /// A request or a notification.
    Request,
    /// A client answer to a server-initiated request.
    Response,
}

/// The part of a JSON-RPC object the verifier needs (Go: rpcMessage).
#[derive(Debug, Clone)]
struct RpcMessage {
    kind: MessageKind,
    /// id member as sent (exact raw text); None when absent.
    id: Option<String>,
    /// method name; empty for responses.
    method: String,
    /// tools/call tool name; None when absent or not a string.
    tool: Option<String>,
    /// params.arguments as sent; None only when the member is absent.
    arguments: Option<Box<RawValue>>,
}

/// Body members as sent: a map type only accepts a JSON object (spec 02
/// section 4: the body "MUST be a single UTF-8 JSON-RPC 2.0 object"; arrays,
/// including batch arrays and positional representations, and scalars are
/// invalid) and keeps the LAST value of a duplicated key (spec README Q11).
/// A derived struct would instead also deserialize from arrays positionally
/// and reject duplicates with `duplicate_field`.
type RawMembers = std::collections::HashMap<String, Box<RawValue>>;

/// Returns Some only when the raw JSON text parses to a JSON string
/// (mirrors Go jsonString: null, numbers, bools are all None).
fn raw_as_string(value: &RawValue) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(value.get())
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_owned()))
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
fn classify_body(body: &[u8]) -> Option<RpcMessage> {
    let text = std::str::from_utf8(body).ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::encode_b64url;
    use crate::server::state::{MemoryState, StateEdit, KIND_HUMAN};
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::sync::LazyLock;

    const NOW: i64 = 1_767_225_600;
    const AUD: &str = "https://svc.example.test";
    const PING: &str = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    const DEFAULT_POLICY: &str = r#"{"version":1,"rules":[
        {"match":{"method":"ping"},"scope":null},
        {"match":{"method":"tools/list"},"scope":null},
        {"match":{"method":"notifications/*"},"scope":null},
        {"match":{"method":"tools/call","tool":"svc.danger.*"},"effect":"deny"},
        {"match":{"method":"tools/call","tool":"svc.config.set"},"scope":"config:write"},
        {"match":{"method":"tools/call","tool":"svc.reload"},"scope":"lifecycle"},
        {"match":{"method":"tools/call","tool":"svc.restart"},"scope":"lifecycle"},
        {"match":{"method":"tools/call","tool":"svc.*"},"scope":"read"}
    ]}"#;

    static POLICY: LazyLock<Arc<Policy>> = LazyLock::new(|| {
        Arc::new(Policy::parse(DEFAULT_POLICY.as_bytes()).expect("default policy must parse"))
    });

    /// Deterministic test key pair derived from a fixed id (mirrors
    /// state.rs state_test_key).
    fn test_key(id: &str) -> (SigningKey, RegistryEntry) {
        let seed = Sha256::digest(id.as_bytes());
        let signing = SigningKey::from_bytes(&seed.into());
        let public = signing.verifying_key().to_bytes();
        (
            signing,
            RegistryEntry {
                kid: key_id(&public),
                public_key: encode_b64url(&public),
                name: id.to_string(),
                kind: KIND_HUMAN.to_string(),
                scopes: vec!["read".to_owned()],
                not_before: None,
                not_after: None,
            },
        )
    }

    fn seeded_state(entries: &[&RegistryEntry]) -> Arc<dyn StateStore> {
        let state = MemoryState::new();
        state
            .update(&mut |edit: &mut StateEdit| {
                for entry in entries {
                    edit.put_key((*entry).clone());
                }
                Ok(())
            })
            .expect("seeding must succeed");
        Arc::new(state)
    }

    fn config(
        now: i64,
        state: Arc<dyn StateStore>,
        native: Option<Arc<dyn NativeTools>>,
    ) -> Config {
        Config {
            aud: AUD.to_owned(),
            state,
            nonces: Arc::new(NonceStore::new()),
            policy: Arc::clone(&POLICY),
            audit: None,
            native,
            window_seconds: 30,
            now: Arc::new(move || now),
        }
    }

    fn verifier(cfg: Config) -> Verifier {
        Verifier::new(cfg).expect("test config is valid")
    }

    fn call_body(tool: &str, arguments: Option<&str>) -> String {
        match arguments {
            Some(args) => format!(
                r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"{tool}","arguments":{args}}}}}"#
            ),
            None => format!(
                r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"{tool}"}}}}"#
            ),
        }
    }

    /// Builds a canonically signed request (spec 01 section 3).
    fn signed(
        method: &str,
        target: &str,
        body: &[u8],
        key: &SigningKey,
        kid: &str,
        ts: i64,
        nonce: &str,
    ) -> Request {
        let signing = request_signing_string(method, target, AUD, kid, ts, nonce, body);
        let sig = encode_b64url(&key.sign(signing.as_bytes()).to_bytes());
        Request {
            method: method.to_owned(),
            target: target.to_owned(),
            auth_values: vec![format!("v1 kid={kid},ts={ts},nonce={nonce},sig={sig}")],
            body: body.to_vec(),
        }
    }

    /// Canonical 22-char nonce for a counter (16 bytes, spec 01 sections 2-3).
    fn nonce(n: u64) -> String {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&n.to_be_bytes());
        encode_b64url(&bytes)
    }

    fn post_call(
        tool: &str,
        arguments: Option<&str>,
        key: &SigningKey,
        kid: &str,
        nonce: &str,
    ) -> Request {
        let body = call_body(tool, arguments);
        signed("POST", "/mcp", body.as_bytes(), key, kid, NOW, nonce)
    }

    fn get(key: &SigningKey, kid: &str, ts: i64, nonce: &str) -> Request {
        signed("GET", "/mcp", b"", key, kid, ts, nonce)
    }

    struct StubNative;

    impl NativeTools for StubNative {
        fn call(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
            c.target = c.kid.to_owned();
            if c.tool == TOOL_ENROLL && c.caller.is_some() {
                return Err(JackError::new(
                    409,
                    codes::KEY_EXISTS,
                    "stub: already registered",
                ));
            }
            if c.tool.starts_with("jack.admin.")
                && !c
                    .caller
                    .is_some_and(|e| e.scopes.iter().any(|s| s == "admin"))
            {
                return Err(JackError::new(
                    403,
                    codes::INSUFFICIENT_SCOPE,
                    "stub: admin required",
                ));
            }
            Ok(NativeResult {
                structured: serde_json::Value::Null,
            })
        }
    }

    fn stub() -> Arc<dyn NativeTools> {
        Arc::new(StubNative)
    }

    #[test]
    fn scheme_checked_before_parameters() {
        let (key, entry) = test_key("alice");
        let v = verifier(config(NOW, seeded_state(&[&entry]), None));

        let mut req = get(&key, &entry.kid, NOW, &nonce(1));
        req.auth_values = vec!["v2 kid=xx".to_owned()];
        let res = v.verify(&req);
        // Path ends at step 3: the scheme is examined before any parameter
        // grammar, so the malformed kid/nonce are never checked.
        assert_eq!(res.http_status, 401);
        assert_eq!(res.code, codes::UNSUPPORTED_VERSION);
        assert!(!res.nonce_recorded);

        // Step 3: unsupported_version.
        req.auth_values = vec!["v2".to_owned()];
        assert_eq!(v.verify(&req).code, codes::UNSUPPORTED_VERSION);

        // "V1" is not a v+digits scheme: malformed_auth, not
        // unsupported_version. Path ends at step 2.
        req.auth_values = vec![format!(
            "V1 kid={},ts={NOW},nonce={},sig={}",
            entry.kid,
            nonce(1),
            "A".repeat(86)
        )];
        assert_eq!(v.verify(&req).code, codes::MALFORMED_AUTH);
    }

    #[test]
    fn unknown_key_vs_enrollment_exception() {
        let (alice_key, alice) = test_key("alice");
        let (mallory_key, mallory) = test_key("mallory");
        let state = seeded_state(&[&alice]);
        let v = verifier(config(NOW, Arc::clone(&state), None));

        // (a) Unregistered kid, plain call: ends at step 4 unknown_key.
        let req = post_call("svc.status", None, &mallory_key, &mallory.kid, &nonce(1));
        let res = v.verify(&req);
        assert_eq!(res.http_status, 401);
        assert_eq!(res.code, codes::UNKNOWN_KEY);
        assert!(!res.nonce_recorded);

        // (b) Enrollment whose submitted key does not hash to kid: ends at
        // step 4 unknown_key (enrollment shape matches, the submitted key is
        // valid, but key_id(submitted) != kid).
        let body = call_body(
            TOOL_ENROLL,
            Some(&format!(r#"{{"public_key":"{}"}}"#, alice.public_key)),
        );
        let req = signed(
            "POST",
            "/mcp",
            body.as_bytes(),
            &mallory_key,
            &mallory.kid,
            NOW,
            &nonce(2),
        );
        assert_eq!(v.verify(&req).code, codes::UNKNOWN_KEY);

        // (c) Small-order key: 400 key_rejected even though its hash != kid.
        // Ends at spec 03 section 3.2 step 3: validity precedes the hash
        // comparison.
        let bad_pub = encode_b64url(&[1u8; 32]);
        let body = call_body(
            TOOL_ENROLL,
            Some(&format!(r#"{{"public_key":"{bad_pub}"}}"#)),
        );
        let req = signed(
            "POST",
            "/mcp",
            body.as_bytes(),
            &mallory_key,
            &mallory.kid,
            NOW,
            &nonce(3),
        );
        let res = v.verify(&req);
        assert_eq!(res.http_status, 400);
        assert_eq!(res.code, codes::KEY_REJECTED);

        // (d) Valid enrollment, no handler: steps 4 (exception ok), 5
        // skipped, 6, 7, 8 pass; ends at step 9 native dispatch: 403
        // operation_denied, nonce consumed, no audit event.
        let (carol_key, carol) = test_key("carol");
        let state = seeded_state(&[&alice]);
        let v = verifier(config(NOW, state, None));
        let body = call_body(
            TOOL_ENROLL,
            Some(&format!(r#"{{"public_key":"{}"}}"#, carol.public_key)),
        );
        let req = signed(
            "POST",
            "/mcp",
            body.as_bytes(),
            &carol_key,
            &carol.kid,
            NOW,
            &nonce(4),
        );
        let res = v.verify(&req);
        assert_eq!(res.http_status, 403);
        assert_eq!(res.code, codes::OPERATION_DENIED);
        assert!(res.native);
        assert!(res.nonce_recorded);
        assert!(res.audit.is_none());

        // (e) Same with a handler: accepted, audit success.
        let state = seeded_state(&[&alice]);
        let v = verifier(config(NOW, state, Some(stub())));
        let body = call_body(
            TOOL_ENROLL,
            Some(&format!(r#"{{"public_key":"{}"}}"#, carol.public_key)),
        );
        let req = signed(
            "POST",
            "/mcp",
            body.as_bytes(),
            &carol_key,
            &carol.kid,
            NOW,
            &nonce(5),
        );
        let res = v.verify(&req);
        assert!(res.accepted);
        assert_eq!(res.structured, Some(serde_json::Value::Null));
        assert!(res.nonce_recorded);
        let event = res.audit.expect("enroll is audited");
        assert_eq!(event.tool, TOOL_ENROLL);
        assert_eq!(event.outcome, AUDIT_SUCCESS);
        assert_eq!(event.actor_kid, carol.kid);
        assert_eq!(event.actor_name, "");
        assert_eq!(event.target, carol.kid);

        // (f) Registered kid enrolling again: step 4 takes the normal
        // (registered) path through steps 6-8; ends at step 9 with the
        // handler rejection 409, audit failure.
        let v = verifier(config(NOW, seeded_state(&[&alice]), Some(stub())));
        let req = post_call(
            TOOL_ENROLL,
            Some(&format!(r#"{{"public_key":"{}"}}"#, alice.public_key)),
            &alice_key,
            &alice.kid,
            &nonce(6),
        );
        let res = v.verify(&req);
        assert_eq!(res.http_status, 409);
        assert_eq!(res.code, codes::KEY_EXISTS);
        let event = res.audit.expect("enroll is audited");
        assert_eq!(event.outcome, AUDIT_FAILURE);
        assert_eq!(event.code, codes::KEY_EXISTS);
    }

    #[test]
    fn replay_only_after_signature() {
        let (key, entry) = test_key("alice");
        let state = seeded_state(&[&entry]);
        let cfg = config(NOW, state, None);
        let nonces = Arc::clone(&cfg.nonces);
        nonces.check_and_record(&entry.kid, &nonce(1), 0, NOW + 10);

        // (a) Valid signature but replayed nonce. The reuse here IS the
        // subject — a replay. Steps 1-7 pass; ends at step 8.
        let v = verifier(cfg);
        let req = post_call("svc.status", None, &key, &entry.kid, &nonce(1));
        let res = v.verify(&req);
        assert_eq!(res.code, codes::REPLAYED_NONCE);
        assert!(!res.nonce_recorded);
        assert_eq!(nonces.len(), 1);
        drop(v);

        // (b) Bad signature with a replayed nonce: bad_signature wins, and
        // nothing was inserted. Step 6 passes (|NOW-NOW| = 0); ends at step 7.
        let state = seeded_state(&[&entry]);
        let cfg = config(NOW, state, None);
        let nonces = Arc::clone(&cfg.nonces);
        nonces.check_and_record(&entry.kid, &nonce(2), 0, NOW + 10);
        let v = verifier(cfg);
        let mut req = get(&key, &entry.kid, NOW, &nonce(2));
        req.auth_values[0] = format!(
            "v1 kid={},ts={NOW},nonce={},sig={}",
            entry.kid,
            nonce(2),
            "A".repeat(86)
        );
        req.method = "POST".to_owned();
        req.body = PING.as_bytes().to_vec();
        let res = v.verify(&req);
        assert_eq!(res.code, codes::BAD_SIGNATURE);
        assert_eq!(nonces.len(), 1);
        drop(v);

        // (c) A failed attempt does not consume the nonce for the later
        // valid request reusing it. Fresh store, no preseed.
        let state = seeded_state(&[&entry]);
        let cfg = config(NOW, state, None);
        let v = verifier(cfg);
        let mut bad = get(&key, &entry.kid, NOW, &nonce(3));
        bad.method = "POST".to_owned();
        bad.body = PING.as_bytes().to_vec();
        bad.auth_values[0] = format!(
            "v1 kid={},ts={NOW},nonce={},sig={}",
            entry.kid,
            nonce(3),
            "A".repeat(86)
        );
        assert_eq!(v.verify(&bad).code, codes::BAD_SIGNATURE);
        // Deliberate reuse: proving the failed attempt did not record.
        let good = post_call("svc.status", None, &key, &entry.kid, &nonce(3));
        let res = v.verify(&good);
        assert!(res.accepted);
        assert!(res.nonce_recorded);
    }

    #[test]
    fn invalid_utf8_checked_before_json() {
        let (key, entry) = test_key("alice");
        let body: &[u8] = b"{\"jsonrpc\":\"2.0\",\"method\":\"p\xffng\"}";
        let v = verifier(config(NOW, seeded_state(&[&entry]), None));

        // Steps 1-8 pass; ends at step 9 classify failure.
        let req = signed("POST", "/mcp", body, &key, &entry.kid, NOW, &nonce(4));
        let res = v.verify(&req);
        assert_eq!(res.http_status, 400);
        assert_eq!(res.code, codes::INVALID_REQUEST);
        assert!(res.nonce_recorded);

        // Step 4 precedes step 9: an unknown kid still gets unknown_key.
        let (mallory_key, mallory) = test_key("mallory");
        let req = signed(
            "POST",
            "/mcp",
            body,
            &mallory_key,
            &mallory.kid,
            NOW,
            &nonce(5),
        );
        assert_eq!(v.verify(&req).code, codes::UNKNOWN_KEY);
    }

    #[test]
    fn empty_post_rejected() {
        let (key, entry) = test_key("alice");
        let v = verifier(config(NOW, seeded_state(&[&entry]), None));
        // Steps 1-8 pass; ends at step 9: 400 invalid_request.
        let req = signed("POST", "/mcp", b"", &key, &entry.kid, NOW, &nonce(6));
        let res = v.verify(&req);
        assert_eq!(res.http_status, 400);
        assert_eq!(res.code, codes::INVALID_REQUEST);
        assert!(res.nonce_recorded);
        assert!(!res.accepted);
        assert_eq!(res.rpc_id, None);
    }

    #[test]
    fn window_checked_before_signature() {
        let (key, entry) = test_key("alice");
        let v = verifier(config(NOW, seeded_state(&[&entry]), None));

        // Ends at step 6 timestamp_out_of_window.
        let req = signed(
            "POST",
            "/mcp",
            PING.as_bytes(),
            &key,
            &entry.kid,
            NOW - 31,
            &nonce(7),
        );
        assert_eq!(v.verify(&req).code, codes::TIMESTAMP_OUT_OF_WINDOW);

        // Step 6 passes (|30| is not > 30); ends at step 7 bad_signature.
        let mut req = signed(
            "POST",
            "/mcp",
            PING.as_bytes(),
            &key,
            &entry.kid,
            NOW - 30,
            &nonce(8),
        );
        req.auth_values[0] = format!(
            "v1 kid={},ts={},nonce={},sig={}",
            entry.kid,
            NOW - 30,
            nonce(8),
            "A".repeat(86)
        );
        assert_eq!(v.verify(&req).code, codes::BAD_SIGNATURE);
    }

    #[test]
    fn default_window_when_unset() {
        let (key, entry) = test_key("alice");
        let mut cfg = config(NOW, seeded_state(&[&entry]), None);
        cfg.window_seconds = 0;
        let v = verifier(cfg);

        // Steps 1-8 + GET accept.
        assert!(
            v.verify(&get(&key, &entry.kid, NOW - 30, &nonce(9)))
                .accepted
        );
        // Ends at step 6.
        assert_eq!(
            v.verify(&get(&key, &entry.kid, NOW - 31, &nonce(10))).code,
            codes::TIMESTAMP_OUT_OF_WINDOW
        );
    }

    #[test]
    fn get_and_unknown_key() {
        let (key, entry) = test_key("alice");
        let v = verifier(config(NOW, seeded_state(&[&entry]), None));

        // Steps 1-8 + GET accept.
        let res = v.verify(&get(&key, &entry.kid, NOW, &nonce(11)));
        assert!(res.accepted);
        assert_eq!(res.kid, entry.kid);
        assert!(res.nonce_recorded);
        assert_eq!(res.tool, "");
        assert!(!res.native);
        assert_eq!(res.rpc_id, None);

        // Ends at step 4.
        let (mallory_key, mallory) = test_key("mallory");
        assert_eq!(
            v.verify(&get(&mallory_key, &mallory.kid, NOW, &nonce(12)))
                .code,
            codes::UNKNOWN_KEY
        );
    }

    #[test]
    fn authorization_codes() {
        let (alice_key, alice) = test_key("alice");
        let (admin, mut admin_entry) = test_key("admin");
        admin_entry.scopes = vec!["admin".to_owned(), "read".to_owned()];
        let state = seeded_state(&[&alice, &admin_entry]);
        let v = verifier(config(NOW, state, None));

        // Steps 1-8 pass; ends at step 9 policy: 403 insufficient_scope.
        let req = post_call("svc.restart", None, &alice_key, &alice.kid, &nonce(13));
        let res = v.verify(&req);
        assert_eq!(res.http_status, 403);
        assert_eq!(res.code, codes::INSUFFICIENT_SCOPE);
        assert!(res.nonce_recorded);

        // Policy deny beats any scopes: 403 operation_denied.
        let req = post_call(
            "svc.danger.wipe",
            None,
            &admin,
            &admin_entry.kid,
            &nonce(14),
        );
        assert_eq!(v.verify(&req).code, codes::OPERATION_DENIED);

        // No matching rule: 403 operation_denied.
        let req = signed(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","id":1,"method":"resources/read"}"#,
            &alice_key,
            &alice.kid,
            NOW,
            &nonce(15),
        );
        assert_eq!(v.verify(&req).code, codes::OPERATION_DENIED);

        // Alice holds the "read" scope svc.* requires: accepted.
        let req = post_call("svc.status", None, &alice_key, &alice.kid, &nonce(16));
        assert!(v.verify(&req).accepted);
    }

    #[test]
    fn rpc_id_and_response_shapes() {
        let (key, entry) = test_key("alice");
        let v = verifier(config(NOW, seeded_state(&[&entry]), None));

        let check = |body: &str, n: u64| {
            v.verify(&signed(
                "POST",
                "/mcp",
                body.as_bytes(),
                &key,
                &entry.kid,
                NOW,
                &nonce(n),
            ))
        };

        let res = check(r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#, 17);
        assert!(res.accepted);
        assert_eq!(res.rpc_id, Some("7".to_owned()));

        // A null result still counts as present.
        let res = check(r#"{"jsonrpc":"2.0","id":7,"result":null}"#, 18);
        assert!(res.accepted);
        assert_eq!(res.rpc_id, Some("7".to_owned()));

        // The raw id text keeps the quotes.
        let res = check(
            r#"{"jsonrpc":"2.0","id":"a","error":{"code":1,"message":"x"}}"#,
            19,
        );
        assert!(res.accepted);
        assert_eq!(res.rpc_id, Some("\"a\"".to_owned()));

        let res = check(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            20,
        );
        assert!(res.accepted);
        assert_eq!(res.rpc_id, None);

        // result AND error together is not a valid shape.
        assert_eq!(
            check(
                r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}"#,
                21
            )
            .code,
            codes::INVALID_REQUEST
        );
        // A response needs an id.
        assert_eq!(
            check(r#"{"jsonrpc":"2.0","result":{}}"#, 22).code,
            codes::INVALID_REQUEST
        );
        assert_eq!(
            check(r#"{"jsonrpc":"1.0","method":"ping"}"#, 23).code,
            codes::INVALID_REQUEST
        );
        // A null method is NOT a response shape.
        assert_eq!(
            check(r#"{"jsonrpc":"2.0","method":null,"id":1,"result":{}}"#, 24).code,
            codes::INVALID_REQUEST
        );
    }

    #[test]
    fn native_denied_without_handler() {
        let (key, entry) = test_key("alice");
        let v = verifier(config(NOW, seeded_state(&[&entry]), None));
        // Ends at step 9: 403 operation_denied, no audit event.
        let req = post_call(TOOL_WHOAMI, None, &key, &entry.kid, &nonce(25));
        let res = v.verify(&req);
        assert_eq!(res.http_status, 403);
        assert_eq!(res.code, codes::OPERATION_DENIED);
        assert!(res.native);
        assert!(res.audit.is_none());
        assert!(res.nonce_recorded);

        // Unknown jack.* tool: denied even with a handler, no audit event.
        // Ends at step 9 (is_native_tool false).
        let v = verifier(config(NOW, seeded_state(&[&entry]), Some(stub())));
        let req = post_call("jack.nope", None, &key, &entry.kid, &nonce(26));
        let res = v.verify(&req);
        assert_eq!(res.code, codes::OPERATION_DENIED);
        assert!(res.native);
        assert!(res.audit.is_none());
    }

    #[test]
    fn classify_body_table() {
        let kind_of = |body: &str| classify_body(body.as_bytes()).map(|m| m.kind);
        let none = |body: &str| assert!(classify_body(body.as_bytes()).is_none(), "body: {body}");

        assert_eq!(
            kind_of(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
            Some(MessageKind::Request)
        );
        assert_eq!(
            kind_of(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Some(MessageKind::Request)
        );
        assert_eq!(
            kind_of(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            Some(MessageKind::Response)
        );
        assert_eq!(
            kind_of(r#"{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"x"}}"#),
            Some(MessageKind::Response)
        );
        // A null id is still a present id.
        assert_eq!(
            kind_of(r#"{"jsonrpc":"2.0","id":null,"result":{}}"#),
            Some(MessageKind::Response)
        );

        none("");
        none("null");
        none(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#);
        none(r#"{"JSONRPC":"2.0","method":"ping"}"#);
        none(r#"{"jsonrpc":"1.0","method":"ping"}"#);
        none(r#"{"jsonrpc":2.0,"method":"ping"}"#);
        none(r#"{"jsonrpc":"2.0","method":null}"#);
        none(r#"{"jsonrpc":"2.0","method":7}"#);
        none(r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}"#);
        none(r#"{"jsonrpc":"2.0","result":{}}"#);
        none(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#);
        none(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}"#);
        none(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":null}}"#);
        assert!(
            classify_body(b"{\"jsonrpc\":\"2.0\",\"method\":\"p\xffng\"}").is_none(),
            "invalid UTF-8 must be rejected before parsing"
        );

        let call = classify_body(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status"}}"#
                .as_bytes(),
        )
        .expect("valid call");
        assert_eq!(call.tool.as_deref(), Some("svc.status"));
        assert!(call.arguments.is_none());

        let call = classify_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","arguments":{"k":"v"}}}"#.as_bytes()).expect("valid call");
        assert_eq!(
            call.arguments.map(|a| a.get().to_owned()),
            Some(r#"{"k":"v"}"#.to_owned())
        );

        let req = classify_body(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#.as_bytes())
            .expect("valid request");
        assert_eq!(req.id, Some("null".to_owned()));

        none(r#"["2.0","ping"]"#);
        none("[]");
        none(r#"[{"jsonrpc":"2.0","method":"ping"}]"#);
        none(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["name"]}"#);
        none("5");
        none(r#""hi""#);

        // Duplicate members keep the LAST value (spec README Q11); a derived
        // struct would instead reject them with duplicate_field.
        let dup = classify_body(
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"resources/read"}"#.as_bytes(),
        )
        .expect("duplicate members keep the last value");
        assert_eq!(dup.method, "resources/read");
        let dup = classify_body(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","name":"svc.reload"}}"#.as_bytes(),
        )
        .expect("duplicate params.name keeps the last value");
        assert_eq!(dup.tool.as_deref(), Some("svc.reload"));
    }

    // spec 02 section 4: "the body MUST be a single UTF-8 JSON-RPC 2.0 object"
    // -> 400 invalid_request for arrays (positional or batch), scalars and null.
    #[test]
    fn object_bodies_only() {
        let (key, entry) = test_key("alice");
        let v = verifier(config(NOW, seeded_state(&[&entry]), None));
        let bodies = [
            r#"["2.0","ping"]"#,
            "[]",
            r#"[{"jsonrpc":"2.0","method":"ping"}]"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["name"]}"#,
            "5",
            r#""hi""#,
            "null",
        ];
        for (i, body) in bodies.iter().enumerate() {
            let req = signed(
                "POST",
                "/mcp",
                body.as_bytes(),
                &key,
                &entry.kid,
                NOW,
                &nonce((i + 27) as u64),
            );
            let res = v.verify(&req);
            assert_eq!(res.http_status, 400, "body: {body}");
            assert_eq!(res.code, codes::INVALID_REQUEST, "body: {body}");
            assert!(res.nonce_recorded, "body: {body}");
        }
    }

    #[test]
    fn duplicate_members_last_value_wins() {
        let (key, entry) = test_key("alice");
        let v = verifier(config(NOW, seeded_state(&[&entry]), None));

        // If the FIRST value won, ping would be allowed; the LAST value must
        // reach the policy, and resources/read matches no rule -> 403. This
        // proves the last value, not the first, and not a parse rejection.
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"resources/read"}"#;
        let req = signed(
            "POST",
            "/mcp",
            body.as_bytes(),
            &key,
            &entry.kid,
            NOW,
            &nonce(34),
        );
        let res = v.verify(&req);
        assert_eq!(res.http_status, 403);
        assert_eq!(res.code, codes::OPERATION_DENIED);

        // First name is deny-ruled, last name is allowed (read scope).
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.danger.wipe","name":"svc.status"}}"#;
        let req = signed(
            "POST",
            "/mcp",
            body.as_bytes(),
            &key,
            &entry.kid,
            NOW,
            &nonce(35),
        );
        assert!(v.verify(&req).accepted);
    }
}
