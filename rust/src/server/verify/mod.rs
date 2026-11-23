//! Request verifier: authentication + authorization (Go: server/verify.go).
//!
//! Verification runs in two phases so an era-aware caller can insert the modern rules of spec 04
//! `S1`-`S12` between them: [`Verifier::authenticate`] performs steps 1-8 of spec 01 section 4 and
//! the body classification of spec 02 section 2 (no native effect, no audit event) and hands out a
//! [`PendingRequest`]; [`Verifier::dispatch`] then runs the native tool call with its audit event,
//! or produces the forwarded accept. [`Verifier::verify`] is the one-shot path over the same code
//! and stays the behaviour of the legacy profile.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
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

mod body;
mod pending;

use body::{classify_body, raw_as_string, MessageKind, RawMembers, RpcMessage};
pub use pending::{Authentication, PendingRequest};
use pending::{PendingAction, PendingState};

/// The `400 invalid_request` message for an unacceptable body (spec 02
/// section 2): the single generic message, byte-identical to 0.1.x on every
/// profile. The modern fixed `tools/call` message of spec 04 `S6` is produced
/// only by the HTTP adapter, from the engine's
/// [`ClassificationRefusal`](crate::server::modern::ModernOutcome::ClassificationRefusal),
/// because this layer also answers the legacy profile.
const INVALID_BODY_MESSAGE: &str = "the body is not an acceptable JSON-RPC object";

/// Protocol-native tool: enroll a new key (spec 03 section 3.2).
pub const TOOL_ENROLL: &str = "jack.enroll";
/// Protocol-native tool: identify the caller (spec 03).
pub const TOOL_WHOAMI: &str = "jack.whoami";
/// Protocol-native tool: rotate a key (spec 03 section 3.1).
pub const TOOL_ROTATE_KEY: &str = "jack.key.rotate";
/// Candidate native tool: one published page of the server key ring (Go: ToolServerKey). NOT part
/// of the closed current-v1 set (`is_native_tool` stays false); reachable only through a
/// separately configured rotation handler (`Verifier::with_server_keys`).
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
    /// `params.arguments` as sent; None only when the member is absent (a null stays Some). Raw
    /// JSON text is preserved so integer arguments can be judged on their text (spec 03 section 3:
    /// no fraction, no exponent; -0 is 0).
    pub arguments: Option<Box<RawValue>>,
    /// Registry entry of the authenticated key; None when enrolling with an unregistered kid.
    pub caller: Option<&'a RegistryEntry>,
    /// Kid from the Jack-Auth header (for enrollment, the hash of the submitted key).
    pub kid: &'a str,
    /// ts parameter of the Jack-Auth header (rotate proofs bind it).
    pub ts: i64,
    /// Verifier clock, Unix seconds.
    pub now: i64,
    /// Server audience string.
    pub aud: &'a str,
    /// Registry and invite store; handlers change it only through `StateStore::update`.
    pub state: Arc<dyn StateStore>,
    /// OUTPUT: handler sets what the audit event names as target (kid, invite id or name), even on
    /// failure.
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
    /// Audience signed into every request; compared with this value, never with the Host header
    /// (spec 01 section 3.1).
    pub aud: String,
    /// Registry and invite store.
    pub state: Arc<dyn StateStore>,
    /// Records seen (kid, nonce) pairs.
    pub nonces: Arc<NonceStore>,
    /// Audit sink for protocol-native calls; optional.
    pub audit: Option<Arc<dyn AuditSink>>,
    /// Implements the jack.* tools; None denies every jack.* tool.
    pub native: Option<Arc<dyn NativeTools>>,
    /// Timestamp window seconds; zero selects DEFAULT_WINDOW_SECONDS, and nonzero values must be in
    /// 1..=120 (Go: Config.Window).
    pub window_seconds: i64,
    /// Verifier clock, Unix seconds. Initial key/invite checks and freshness use the highest sample
    /// seen so far; authorization (including native-tool and audit time) shares it in the volatile
    /// profile. Durable post-commit authorization keeps its store-sampled finalNow; response
    /// timestamps use the raw sample.
    pub now: Clock,
}

/// Authenticates and authorizes requests (spec 01 section 4, spec 02
/// section 4).
pub struct Verifier {
    cfg: Config,
    /// Candidate jack.server.key handler (Go: Config.ServerKeys); None denies the route.
    /// Deliberately NOT a Config field: adding a field would break every existing struct literal
    /// of the static public API.
    server_keys: Option<Arc<dyn NativeTools>>,
    /// Candidate jack.server.webhook_key handler (spec 06 rule R7.6); None
    /// denies the route. Builder-only for the same static-API reason.
    webhook_keys: Option<Arc<dyn NativeTools>>,
    /// Candidate durable nonce store (Go: Config.DurableNonces); None uses the volatile store.
    /// Builder-only for the same static-API reason.
    #[cfg(target_os = "linux")]
    durable: Option<Arc<SharedDurableNonceStore>>,
    /// Latched durable-profile refusal for an invalid window. Ordinary construction validates this
    /// config first, but the infallible durable builder rechecks it and fails every later request
    /// closed.
    #[cfg(target_os = "linux")]
    durable_window_invalid: bool,
    /// Highest clock sample seen; request time is monotonic within a process.
    high_water: AtomicI64,
    /// Identity of THIS verifier, stamped into every [`PendingRequest`] it issues: `dispatch`
    /// refuses a pending request issued by another one (fail closed). Read-only after construction.
    issuer: u64,
}

/// Process-wide source of issuer ids; 0 is never handed out, so a
/// zero-initialised value can never match a real issuer.
static NEXT_ISSUER: AtomicU64 = AtomicU64::new(1);

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
            issuer: NEXT_ISSUER.fetch_add(1, Ordering::SeqCst),
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

    /// Effective response window in seconds (spec 01 section 4); the stream heartbeat grant of
    /// spec 05 3.5 uses the server's own window.
    pub fn window_seconds(&self) -> i64 {
        self.window()
    }

    /// Request time that never goes backwards: max(sample, highest seen).
    fn effective_now(&self, sample: i64) -> i64 {
        self.high_water
            .fetch_max(sample, Ordering::SeqCst)
            .max(sample)
    }

    /// Runs the pipeline of spec 01 section 4 and spec 02 section 4 on one
    /// request as a single step: [`Verifier::authenticate`] followed by
    /// [`Verifier::dispatch`]. The legacy profile and direct library callers
    /// keep using this one-shot path, so its behaviour and bytes do not change;
    /// an era-aware caller runs the two phases itself and inserts the modern
    /// rules of spec 04 between them.
    pub fn verify(&self, req: &Request) -> VerifyResult {
        match self.authenticate(req) {
            Authentication::Refused(res) => res,
            Authentication::Pending(pending) => self.dispatch(pending),
        }
    }

    /// Phase 1: steps 1-8 of spec 01 section 4 (parse, key resolution, window,
    /// signature, durable reservation or nonce record) plus the body
    /// classification of spec 02 section 2. Stops at the first failing step; a
    /// rejection never reveals more than its code.
    ///
    /// NO native tool runs and NO audit event is written here: a caller that
    /// refuses the request afterwards (the modern rules `S1`-`S12` of spec 04)
    /// has produced no side effect beyond the recorded nonce or the committed
    /// durable reservation, which is exactly what the one-shot path consumed
    /// before it authorized as well.
    pub fn authenticate(&self, req: &Request) -> Authentication {
        let now = (self.cfg.now)();
        let effective = self.effective_now(now);
        let auth_values: Vec<&str> = req.auth_values.iter().map(String::as_str).collect();

        let auth = match parse_request_auth(&auth_values) {
            Ok(auth) => auth,
            Err(err) => return Authentication::Refused(rejection_from(&err)),
        };

        // Step 4-5: resolve the verify key — either the registered entry or,
        // via the enrollment exception, a valid submitted key hashing to kid.
        let caller = self.cfg.state.lookup(&auth.kid);
        let verify_key = match caller.as_ref() {
            Some(entry) => {
                if !entry_active(entry, effective) {
                    return Authentication::Refused(fail(
                        VerifyResult::default(),
                        401,
                        codes::KEY_INACTIVE,
                        "key is not active",
                    ));
                }
                match decode_b64url_fixed(&entry.public_key, 32) {
                    Ok(key) => key,
                    // Registry data is operator-owned; a malformed key there
                    // is a server fault, not a client rejection.
                    Err(_) => {
                        return Authentication::Refused(fail(
                            VerifyResult::default(),
                            500,
                            "internal_error",
                            "registry holds an invalid public key",
                        ))
                    }
                }
            }
            None => match enrollment_key(req, &auth.kid, self.cfg.state.as_ref(), effective) {
                Ok(key) => key,
                Err(rej) => return Authentication::Refused(rej),
            },
        };

        // Step 6: window. abs_diff cannot overflow where `now - ts` would.
        let window = self.window();
        if effective.abs_diff(auth.ts) > window.unsigned_abs() {
            return Authentication::Refused(fail(
                VerifyResult::default(),
                401,
                codes::TIMESTAMP_OUT_OF_WINDOW,
                "timestamp is outside the acceptance window",
            ));
        }

        // Step 7: signature. The parser already checked the sig encoding;
        // the branch is kept to mirror Go and survive refactors.
        let sig = match decode_b64url_fixed(&auth.sig, 64) {
            Ok(sig) => sig,
            Err(_) => {
                return Authentication::Refused(fail(
                    VerifyResult::default(),
                    401,
                    codes::BAD_SIGNATURE,
                    "malformed signature",
                ))
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
            return Authentication::Refused(fail(
                VerifyResult::default(),
                401,
                codes::BAD_SIGNATURE,
                "signature does not verify",
            ));
        }

        // Candidate durable profile: reserve AFTER signature verification and
        // BEFORE any authorization/state change/dispatch (spec section 2); the
        // volatile store below is skipped. The committed lease is finished by
        // the HTTP adapter after the response is produced, or by the `Drop` of
        // a pending request that is never dispatched.
        #[cfg(target_os = "linux")]
        if let Some(store) = self.durable.as_ref() {
            if self.durable_window_invalid {
                return Authentication::Refused(fail(
                    VerifyResult::default(),
                    500,
                    "internal_error",
                    "server: durable window must be between 1 and 120 seconds",
                ));
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
                Some(final_now) => self.classify(req, &auth, final_now, caller, outcome.result),
                None => Authentication::Refused(outcome.result),
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
            return Authentication::Refused(fail(
                VerifyResult::default(),
                401,
                codes::REPLAYED_NONCE,
                "nonce was already used",
            ));
        }

        let res = VerifyResult {
            kid: auth.kid.clone(),
            nonce_recorded: true,
            request_sig: auth.sig.clone(),
            ..Default::default()
        };
        self.classify(req, &auth, effective, caller, res)
    }

    /// Phase 1 tail: the body shape rules of spec 02 section 2 on top of an
    /// authenticated result, producing either the body rejection or the
    /// dispatch action of a [`PendingRequest`].
    fn classify(
        &self,
        req: &Request,
        auth: &RequestAuth,
        now: i64,
        caller: Option<RegistryEntry>,
        mut res: VerifyResult,
    ) -> Authentication {
        // A body to classify exists only on `POST` (spec 02 section 2 item 2),
        // so a non-`POST` request carries no JSON-RPC here. The HTTP adapter
        // refuses a non-`GET`/non-`POST` method before verification in the
        // legacy profile; the modern profile answers it with the signed 405 of
        // spec 04 `S2` after the era decision instead.
        if req.method != "POST" {
            return self.pending(PendingAction::Forward, res, auth, now, caller);
        }

        let Some(msg) = classify_body(&req.body) else {
            return Authentication::Refused(fail(
                res,
                400,
                codes::INVALID_REQUEST,
                INVALID_BODY_MESSAGE,
            ));
        };
        res.rpc_id = msg.id;
        if msg.kind == MessageKind::Response {
            return self.pending(PendingAction::Forward, res, auth, now, caller);
        }
        let RpcMessage {
            tool, arguments, ..
        } = msg;
        if let Some(tool) = &tool {
            res.tool = tool.clone();
        }

        // Only a jack.* tool is a candidate for the native lane; everything
        // else is ordinary MCP traffic and gets forwarded unchanged.
        match tool.filter(|t| t.starts_with("jack.")) {
            Some(tool) => {
                // Set BEFORE any denial: a denied native call is still native.
                res.native = true;
                self.pending(
                    PendingAction::Native { tool, arguments },
                    res,
                    auth,
                    now,
                    caller,
                )
            }
            None => self.pending(PendingAction::Forward, res, auth, now, caller),
        }
    }

    /// Wraps a classified request as the pending half of [`Authentication`],
    /// stamped with this verifier's issuer id.
    fn pending(
        &self,
        action: PendingAction,
        res: VerifyResult,
        auth: &RequestAuth,
        now: i64,
        caller: Option<RegistryEntry>,
    ) -> Authentication {
        Authentication::Pending(PendingRequest {
            issuer: self.issuer,
            state: Some(PendingState {
                res,
                kid: auth.kid.clone(),
                ts: auth.ts,
                now,
                aud: self.cfg.aud.clone(),
                caller,
                action,
            }),
        })
    }

    /// Phase 2: dispatches an authenticated request — the protocol-native tool
    /// call with its audit event, or the forwarded accept carrying the verified
    /// identity — and returns the same [`VerifyResult`] shape
    /// [`Verifier::verify`] returns.
    ///
    /// `pending` is consumed BY VALUE, so a request can be dispatched at most
    /// once. A pending request issued by another verifier is answered with the
    /// signed 500 `internal_error` (fail closed): the rules that produced it
    /// are not this verifier's, so nothing is executed.
    pub fn dispatch(&self, mut pending: PendingRequest) -> VerifyResult {
        let issuer = pending.issuer;
        let Some(state) = pending.state.take() else {
            // Unreachable: only dispatch empties a pending request, and it
            // consumes the value.
            return fail(
                VerifyResult::default(),
                500,
                "internal_error",
                "internal error",
            );
        };
        let PendingState {
            mut res,
            kid,
            ts,
            now,
            aud,
            caller,
            action,
        } = state;
        if issuer != self.issuer {
            return fail(res, 500, "internal_error", "internal error");
        }

        match action {
            PendingAction::Forward => {
                // Unreachable: only a jack.enroll request passes step 4 without
                // a registry entry, and it is native (so not forwarded); that
                // shape is rejected earlier as unknown_key, so this arm is
                // defensive.
                let Some(caller) = caller else {
                    return fail(res, 401, codes::UNKNOWN_KEY, "unknown key");
                };
                // Ordinary MCP traffic is forwarded unchanged for ANY
                // authenticated caller, whatever the method or tool name (spec
                // 02 section 2 pass-through); the verified identity snapshot
                // rides along (spec 02 section 3).
                res.identity = self.identity_for(Some(&caller));
                res.accepted = true;
                res
            }
            PendingAction::Native { tool, arguments } => {
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
                    arguments,
                    caller: caller.as_ref(),
                    kid: &kid,
                    ts,
                    now,
                    aud: &aud,
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
                        actor_kid: kid.clone(),
                        actor_name: caller.as_ref().map(|c| c.name.clone()).unwrap_or_default(),
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

                match out {
                    Ok(native_result) => {
                        res.accepted = true;
                        res.structured = Some(native_result.structured);
                        res
                    }
                    Err(jerr) => fail(res, jerr.http_status, &jerr.code, &jerr.message),
                }
            }
        }
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

impl VerifyResult {
    /// Finishes the committed durable admission lease once the response has
    /// been produced (Go: Result.Done). Without the Linux-gated store there is
    /// no lease and this is a no-op.
    pub fn finish_admission(&mut self) {
        #[cfg(target_os = "linux")]
        self.admission.finish();
    }
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

#[cfg(test)]
mod tests;
