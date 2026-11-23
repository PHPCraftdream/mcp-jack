//! Request verifier: authentication + authorization (Go: server/verify.go).

use std::collections::HashSet;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use serde_json::value::RawValue;

use crate::auth_header::{parse_request_auth, RequestAuth};
use crate::encoding::{decode_b64url_fixed, key_id};
use crate::error::{codes, JackError};
use crate::server::audit::{AuditEvent, AuditSink, AUDIT_FAILURE, AUDIT_SUCCESS};
#[cfg(target_os = "linux")]
use crate::server::durable_admission::{
    reserve_durable, AdmissionFinish, CallerSnapshot, SharedDurableNonceStore,
};
use crate::server::identity::VerifiedIdentity;
use crate::server::native::invite_id_of;
use crate::server::nonce::NonceStore;
use crate::server::state::{RegistryEntry, StateStore};
use crate::server::webhook_key::TOOL_SERVER_WEBHOOK_KEY;
use crate::signing::{request_signing_string, DEFAULT_WINDOW_SECONDS};

/// Protocol-native tool: enroll a new key (spec 03 section 3.2).
pub const TOOL_ENROLL: &str = "jack.enroll";
/// Protocol-native tool: identify the caller (spec 03).
pub const TOOL_WHOAMI: &str = "jack.whoami";
/// Protocol-native tool: rotate a key (spec 03 section 3.1).
pub const TOOL_ROTATE_KEY: &str = "jack.key.rotate";
/// Candidate native tool: one published page of the server key ring (Go:
/// ToolServerKey). NOT part of the closed current-v1 set (`is_native_tool`
/// stays false); reachable only through a separately configured rotation
/// handler (`Verifier::with_server_keys`).
pub const TOOL_SERVER_KEY: &str = "jack.server.key";
/// Protocol-native admin tool (spec 03 section 6).
pub const TOOL_ADMIN_USER_LIST: &str = "jack.admin.user.list";
/// Protocol-native admin tool (spec 03 section 6).
pub const TOOL_ADMIN_USER_GET: &str = "jack.admin.user.get";
/// Protocol-native admin tool (spec 03 section 4).
pub const TOOL_ADMIN_USER_CREATE: &str = "jack.admin.user.create";
/// Protocol-native admin tool (spec 03 section 4).
pub const TOOL_ADMIN_USER_SET_ADMIN: &str = "jack.admin.user.set_admin";
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
    TOOL_ADMIN_USER_SET_ADMIN,
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
    /// Audit sink for protocol-native calls; optional.
    pub audit: Option<Arc<dyn AuditSink>>,
    /// Implements the jack.* tools; None denies every jack.* tool.
    pub native: Option<Arc<dyn NativeTools>>,
    /// Timestamp window seconds; zero selects DEFAULT_WINDOW_SECONDS, and
    /// nonzero values must be in 1..=120 (Go: Config.Window).
    pub window_seconds: i64,
    /// Verifier clock, Unix seconds. Initial key/invite checks and freshness
    /// use the highest sample seen so far; authorization (including native-tool
    /// and audit time) shares it in the volatile profile. Durable post-commit
    /// authorization keeps its store-sampled finalNow; response timestamps
    /// use the raw sample.
    pub now: Clock,
}

/// Authenticates and authorizes requests (spec 01 section 4, spec 02
/// section 4).
pub struct Verifier {
    cfg: Config,
    /// Candidate jack.server.key handler (Go: Config.ServerKeys); None
    /// denies the route. Deliberately NOT a Config field: adding a field
    /// would break every existing struct literal of the static public API.
    server_keys: Option<Arc<dyn NativeTools>>,
    /// Candidate jack.server.webhook_key handler (spec 06 rule R7.6); None
    /// denies the route. Builder-only for the same static-API reason.
    webhook_keys: Option<Arc<dyn NativeTools>>,
    /// Candidate durable nonce store (Go: Config.DurableNonces); None uses
    /// the volatile store. Builder-only for the same static-API reason.
    #[cfg(target_os = "linux")]
    durable: Option<Arc<SharedDurableNonceStore>>,
    /// Latched durable-profile refusal for an invalid window. Ordinary
    /// construction validates this config first, but the infallible durable
    /// builder rechecks it and fails every later request closed.
    #[cfg(target_os = "linux")]
    durable_window_invalid: bool,
    /// Highest clock sample seen; request time is monotonic within a process.
    high_water: AtomicI64,
}

impl Verifier {
    /// Validates cfg (Go: NewVerifier). In addition to aud, the window can be
    /// invalid; the other Go checks are types here (Arc is non-null by construction).
    pub fn new(mut cfg: Config) -> Result<Self, String> {
        if cfg.aud.is_empty() {
            return Err("server: Config.Aud must be non-empty".to_owned());
        }
        if crate::client::auth::has_control(&cfg.aud) {
            return Err("server: Config.Aud must not contain control characters".to_owned());
        }
        if cfg.window_seconds < 0 || cfg.window_seconds > 120 {
            return Err(
                "server: window must be 0 (default 30) or an integer between 1 and 120 seconds"
                    .to_owned(),
            );
        }
        if cfg.window_seconds == 0 {
            cfg.window_seconds = DEFAULT_WINDOW_SECONDS;
        }
        Ok(Self {
            cfg,
            server_keys: None,
            webhook_keys: None,
            #[cfg(target_os = "linux")]
            durable: None,
            #[cfg(target_os = "linux")]
            durable_window_invalid: false,
            high_water: AtomicI64::new(i64::MIN),
        })
    }

    /// Routes `jack.server.key` to this handler (Go: Config.ServerKeys). The
    /// caller must pair it with a rotating response profile at the HTTP
    /// layer; the library cannot enforce that pairing without breaking the
    /// infallible static constructor.
    pub fn with_server_keys(mut self, server_keys: Arc<dyn NativeTools>) -> Self {
        self.server_keys = Some(server_keys);
        self
    }

    /// Routes `jack.server.webhook_key` to this handler (spec 06 rule R7.6).
    /// The tool is read-only, so no rotating response profile is needed; None
    /// keeps the route answering 403 operation_denied.
    pub fn with_webhook_keys(mut self, webhook_keys: Arc<dyn NativeTools>) -> Self {
        self.webhook_keys = Some(webhook_keys);
        self
    }

    /// Selects the candidate durable nonce profile (Go: Config.DurableNonces).
    /// The volatile nonce store is not used while one is configured; every
    /// refusal maps to the candidate storage statuses and codes (spec section
    /// 5). Linux-gated together with the durable store.
    #[cfg(target_os = "linux")]
    pub fn with_durable_nonces(mut self, durable: Arc<SharedDurableNonceStore>) -> Self {
        // Preserve the durable-profile R9 refusal as a second fail-closed
        // guard; this infallible builder rechecks windows rejected by new().
        self.durable_window_invalid = self.cfg.window_seconds < 0 || self.cfg.window_seconds > 120;
        self.durable = Some(durable);
        self
    }

    /// Effective window: zero selects the default (Go: `if cfg.Window == 0`;
    /// construction rejects negative and over-limit values before this is used).
    fn window(&self) -> i64 {
        if self.cfg.window_seconds == 0 {
            DEFAULT_WINDOW_SECONDS
        } else {
            self.cfg.window_seconds
        }
    }

    /// Verifier clock, Unix seconds (Go: cfg.Now); the HTTP adapter reads it
    /// so response signing uses exactly the verifier's time source.
    pub fn now(&self) -> i64 {
        (self.cfg.now)()
    }

    /// Request time that never goes backwards: max(sample, highest seen).
    fn effective_now(&self, sample: i64) -> i64 {
        self.high_water
            .fetch_max(sample, Ordering::SeqCst)
            .max(sample)
    }

    /// Runs the pipeline of spec 01 section 4 and spec 02 section 4 on one
    /// request. Stops at the first failing step; a rejection never reveals
    /// more than its code.
    pub fn verify(&self, req: &Request) -> VerifyResult {
        let now = (self.cfg.now)();
        let effective = self.effective_now(now);
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
                if !entry_active(entry, effective) {
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
            None => match enrollment_key(req, &auth.kid, self.cfg.state.as_ref(), effective) {
                Ok(key) => key,
                Err(rej) => return rej,
            },
        };

        // Step 6: window. abs_diff cannot overflow where `now - ts` would.
        let window = self.window();
        if effective.abs_diff(auth.ts) > window.unsigned_abs() {
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

        // Candidate durable profile: reserve AFTER signature verification and
        // BEFORE any authorization/state change/dispatch (spec section 2); the
        // volatile store below is skipped. The committed lease is finished by
        // the HTTP adapter after the response is produced.
        #[cfg(target_os = "linux")]
        if let Some(store) = self.durable.as_ref() {
            if self.durable_window_invalid {
                return fail(
                    VerifyResult::default(),
                    500,
                    "internal_error",
                    "server: durable window must be between 1 and 120 seconds",
                );
            }
            let snapshot = match caller.as_ref() {
                Some(entry) => CallerSnapshot::registered(entry.clone()),
                None => CallerSnapshot::enrolled(auth.kid.clone()),
            };
            let window = self.window();
            let outcome = reserve_durable(
                store,
                &auth,
                &signing,
                window,
                snapshot,
                Arc::clone(&self.cfg.state),
                &self.cfg.now,
            );
            return match outcome.final_now {
                Some(final_now) => {
                    self.authorize(req, &auth, final_now, caller.as_ref(), outcome.result)
                }
                None => outcome.result,
            };
        }

        // Step 8: the nonce is recorded only after the signature verified, so
        // requests that fail verification cannot fill the cache (spec 01 section 4).
        // Store polarity: true means a live REPLAY.
        if self
            .cfg
            .nonces
            .check_and_record(&auth.kid, &auth.nonce, effective, auth.ts + window)
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
        self.authorize(req, &auth, effective, caller.as_ref(), res)
    }

    /// Step 9: body shape, protocol-native tools, forwarding (Go: authorize).
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
            res.identity = self.identity_for(caller);
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
            res.identity = self.identity_for(caller);
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
            // The candidate route bypasses the current-v1 allowlist and goes
            // to its own lane (Go: `if msg.tool == ToolServerKey { native =
            // v.cfg.ServerKeys }`). Unknown jack.* tool, candidate route
            // without a rotation profile, or missing handler: 403 with NO
            // audit event — the call never reached a tool.
            let handler = if tool == TOOL_SERVER_KEY {
                self.server_keys.as_ref()
            } else if tool == TOOL_SERVER_WEBHOOK_KEY {
                self.webhook_keys.as_ref()
            } else {
                self.cfg.native.as_ref().filter(|_| is_native_tool(&tool))
            };
            let Some(handler) = handler else {
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
        // registry entry, and it was handled above (native calls, so the
        // identity stays None).
        let caller = match caller {
            Some(caller) => caller,
            None => return fail(res, 401, codes::UNKNOWN_KEY, "unknown key"),
        };
        // Ordinary MCP traffic is forwarded unchanged for ANY authenticated
        // caller, whatever the method or tool name (spec 02 section 2
        // pass-through); the verified identity snapshot rides along (spec 02
        // section 3).
        res.identity = Some(VerifiedIdentity::new(
            caller.kid.clone(),
            caller.name.clone(),
            caller.admin,
        ));
        res.accepted = true;
        res
    }

    /// Builds the identity snapshot for a forwarded accept (spec 02 section
    /// 3). `caller` is None only for the enrollment request, which is native
    /// and never forwarded; that shape is rejected earlier as unknown_key, so
    /// the None arm is defensive.
    fn identity_for(&self, caller: Option<&RegistryEntry>) -> Option<VerifiedIdentity> {
        caller.map(|c| VerifiedIdentity::new(c.kid.clone(), c.name.clone(), c.admin))
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
    /// The verified caller identity for requests forwarded to the wrapped
    /// handler; None for rejections and protocol-native calls (spec 02
    /// section 3).
    pub identity: Option<VerifiedIdentity>,
    /// Committed durable admission lease; finished after the response is
    /// produced (Go: Result.admission + Done). Linux-gated with the store.
    #[cfg(target_os = "linux")]
    pub admission: AdmissionFinish,
}

/// Builds the rejection form of a result: only status, code and message.
fn fail(mut res: VerifyResult, http_status: u16, code: &str, message: &str) -> VerifyResult {
    res.http_status = http_status;
    res.code = code.to_owned();
    res.message = message.to_owned();
    // A rejection never carries an identity.
    res.identity = None;
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
pub(crate) fn entry_active(entry: &RegistryEntry, now: i64) -> bool {
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
fn enrollment_key(
    req: &Request,
    kid: &str,
    state: &dyn StateStore,
    now: i64,
) -> Result<Vec<u8>, VerifyResult> {
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
    // map) are both shape errors -> unknown key. Members decode as raw text
    // (Go: json.RawMessage), so a number in a member the exception never
    // reads is never parsed or range-checked.
    let Some(arguments) = &msg.arguments else {
        return Err(unknown());
    };
    let Ok(args) = serde_json::from_str::<RawMembers>(arguments.get()) else {
        return Err(unknown());
    };
    // Invite gate before any key handling, so a caller without a live invite
    // learns nothing about key validity.
    if !live_invite(state, &args, now) {
        return Err(unknown());
    }
    // A null/number/bool public_key is not a string -> unknown key.
    let Some(submitted) = args.get("public_key").and_then(|v| raw_as_string(v)) else {
        return Err(unknown());
    };
    let key = match decode_b64url_fixed(&submitted, 32) {
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

/// Reports whether `code` names an invite that exists and is unexpired at
/// `now`. Read-only: the tool still consumes the invite atomically later.
fn live_invite(state: &dyn StateStore, args: &RawMembers, now: i64) -> bool {
    let Some(code) = args.get("code").and_then(|v| raw_as_string(v)) else {
        return false;
    };
    let Ok(raw_code) = decode_b64url_fixed(&code, 32) else {
        return false;
    };
    state
        .lookup_invite(&invite_id_of(&raw_code))
        .is_some_and(|invite| now < invite.expires_at)
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
/// invalid). Duplicate names never reach it: `unacceptable_body` rejects them
/// first. A derived struct would also deserialize from arrays positionally.
type RawMembers = std::collections::HashMap<String, Box<RawValue>>;

/// Returns Some only when the raw JSON text parses to a JSON string
/// (mirrors Go jsonString: null, numbers, bools are all None).
fn raw_as_string(value: &RawValue) -> Option<String> {
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
fn classify_body(body: &[u8]) -> Option<RpcMessage> {
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

#[cfg(test)]
mod tests;
