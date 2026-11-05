//! Protocol-native tools: enrollment, rotation, users, invites (Go: server/native.go).

use std::sync::Arc;

use serde_json::json;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use super::state::{InviteRecord, RegistryEntry, StateEdit, StateStore, KIND_AGENT, KIND_HUMAN};
use super::verify::{
    entry_active, NativeCall, NativeResult, NativeTools, TOOL_ADMIN_INVITE_CREATE,
    TOOL_ADMIN_INVITE_LIST, TOOL_ADMIN_INVITE_REVOKE, TOOL_ADMIN_USER_CREATE, TOOL_ADMIN_USER_GET,
    TOOL_ADMIN_USER_LIST, TOOL_ADMIN_USER_REVOKE, TOOL_ADMIN_USER_SET_SCOPES, TOOL_ENROLL,
    TOOL_ROTATE_KEY, TOOL_WHOAMI,
};
use crate::ed25519::{validate_public_key, verify};
use crate::encoding::{decode_b64url_fixed, encode_b64url, key_id};
use crate::error::{codes, JackError};
use crate::signing::rotate_proof_string;
use crate::syntax::{valid_name, valid_scope};

const DEFAULT_INVITE_TTL: i64 = 3600;
const MAX_INVITE_TTL: i64 = 604800;
const MAX_KEY_TTL: i64 = 31536000;

/// The injected random source type (Go: NativeOptions.RandomBytes).
type RandomBytes = Arc<dyn Fn(usize) -> Result<Vec<u8>, JackError> + Send + Sync>;

/// Configures the native tool implementation (Go: NativeOptions).
#[derive(Default)]
pub struct NativeOptions {
    /// Random source returning n bytes; None = OS getrandom. Invite codes come
    /// from it: tests inject a deterministic source, production must not
    /// (Go: NativeOptions.RandomBytes).
    pub random_bytes: Option<RandomBytes>,
}

/// Implements the jack.* tools of spec 03: enrollment, key rotation, whoami
/// and user and invite administration. Every state change is one
/// `StateStore::update`, so it is atomic (spec 03 section 9) (Go: Native).
pub struct Native {
    random: RandomBytes,
}

impl Native {
    /// Builds the native tool implementation (Go: NewNativeTools).
    pub fn new(opts: NativeOptions) -> Self {
        let random = opts.random_bytes.unwrap_or_else(|| {
            Arc::new(|n: usize| {
                let mut b = vec![0u8; n];
                getrandom::getrandom(&mut b)
                    .map_err(|_| JackError::new(500, "internal_error", "internal error"))?;
                Ok(b)
            })
        });
        Self { random }
    }

    /// Draws a 32-byte invite code and returns it with its invite id
    /// (Go: newInviteCode). Any randomness failure is an internal error.
    fn new_invite_code(&self) -> Result<(String, String), JackError> {
        let raw = (self.random)(32)?;
        if raw.len() != 32 {
            return Err(JackError::new(500, "internal_error", "internal error"));
        }
        Ok((encode_b64url(&raw), invite_id_of(&raw)))
    }
}

/// Creates the first administrator's invite out of band (spec 03 section 5,
/// Go: BootstrapAdmin): one single-use invite for the admin scope and the
/// human kind, valid for `ttl_seconds`. Returns the invite CODE, which exists
/// nowhere else. Not an MCP tool; never called from a network handler.
pub fn bootstrap_admin(
    state: &dyn StateStore,
    now: i64,
    ttl_seconds: i64,
    opts: NativeOptions,
) -> Result<String, JackError> {
    if !(1..=MAX_INVITE_TTL).contains(&ttl_seconds) {
        return Err(JackError::new(
            0,
            "internal_error",
            "server: bootstrap ttl must be between 1 and 604800 seconds",
        ));
    }
    let native = Native::new(opts);
    let (code, invite_id) = native.new_invite_code()?;
    state.update(&mut |e| {
        e.put_invite(InviteRecord {
            invite_id: invite_id.clone(),
            scopes: vec!["admin".to_owned()],
            kind: KIND_HUMAN.to_owned(),
            created_by: "bootstrap".to_owned(),
            created_at: now,
            expires_at: ttl_at(now, ttl_seconds)?,
            key_ttl_seconds: None,
        });
        Ok(())
    })?;
    Ok(code)
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn invalid_params() -> JackError {
    JackError::new(
        400,
        codes::INVALID_PARAMS,
        "an argument is missing, mistyped or out of range",
    )
}

fn key_rejected() -> JackError {
    JackError::new(400, codes::KEY_REJECTED, "the public key is not acceptable")
}

fn internal_error() -> JackError {
    JackError::new(500, "internal_error", "internal error")
}

fn unknown_key() -> JackError {
    JackError::new(401, codes::UNKNOWN_KEY, "unknown key")
}

fn no_such_key() -> JackError {
    JackError::new(404, codes::UNKNOWN_TARGET, "no such key")
}

fn lacks_admin_scope() -> JackError {
    JackError::new(
        403,
        codes::INSUFFICIENT_SCOPE,
        "the key lacks the admin scope",
    )
}

fn invalid_invite() -> JackError {
    JackError::new(403, codes::INVALID_INVITE, "the invite is not valid")
}

fn name_taken() -> JackError {
    JackError::new(409, codes::NAME_TAKEN, "the name is already used")
}

fn key_exists() -> JackError {
    JackError::new(409, codes::KEY_EXISTS, "the key is already registered")
}

fn last_admin() -> JackError {
    JackError::new(
        409,
        codes::LAST_ADMIN,
        "the change would leave no active administrator",
    )
}

// ---------------------------------------------------------------------------
// Strict argument parsing (spec 03 section 3)
// ---------------------------------------------------------------------------

/// `params.arguments` looked up by exact member name, keeping each member's
/// exact JSON text (Go: argMap / json.RawMessage). A duplicated JSON key keeps
/// the last value, like Go's map decode. HashMap rather than serde_json::Map
/// because serde_json only implements Deserialize for Map<String, Value>.
type Args = std::collections::HashMap<String, Box<RawValue>>;

/// Decodes `params.arguments`: absent means no arguments, JSON null or any
/// non-object is invalid (Go: parseArgs).
fn parse_args(raw: &Option<Box<RawValue>>) -> Result<Args, JackError> {
    let Some(raw) = raw else {
        return Ok(Args::new());
    };
    if raw.get() == "null" {
        return Err(invalid_params());
    }
    serde_json::from_str::<Args>(raw.get()).map_err(|_| invalid_params())
}

/// Returns the member's string value; absent or null is None (Go: argMap.str).
fn str_arg(args: &Args, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok())
}

/// Judges a JSON number by its exact text: an integer only when the text is
/// `-?(0|[1-9][0-9]*)` — no fraction, no exponent, no leading zeros (spec 03
/// section 3: `1` and `-0` are integers, `1.0` and `1e3` are not, and a string
/// or boolean is never a number); `-0` is 0. Parsed through i128 so magnitudes
/// beyond i64 fail the caller's range check instead of wrapping (Go: int64
/// unmarshal).
fn json_int(text: &str) -> Option<i128> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // JSON forbids leading zeros: `0` alone is fine, `01` is not.
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    text.parse::<i128>().ok()
}

/// Decodes a JSON number that holds an integer within [min, max], judging the
/// raw JSON text with `json_int` (spec 03 section 3). No f64 round-trip, so
/// 2^53+1 stays exact and `-0` reads as 0 (Go: intFrom).
fn int_arg(args: &Args, key: &str, min: i64, max: i64) -> Option<i64> {
    let raw = args.get(key)?;
    let value = json_int(raw.get())?;
    if value < i128::from(min) || value > i128::from(max) {
        return None;
    }
    i64::try_from(value).ok()
}

/// Decodes an optional validity bound: absent or null is unbounded
/// (Go: timeFrom). Outer None = invalid.
fn time_arg(args: &Args, key: &str) -> Option<Option<i64>> {
    match args.get(key) {
        None => Some(None),
        Some(raw) if raw.get() == "null" => Some(None),
        Some(_) => int_arg(args, key, 0, 999_999_999_999).map(Some),
    }
}

/// Decodes an array of distinct valid scopes; an empty array is valid
/// (Go: scopesFrom).
fn scopes_arg(args: &Args, key: &str) -> Option<Vec<String>> {
    let raw = args.get(key)?;
    let items = serde_json::from_str::<Vec<Box<RawValue>>>(raw.get()).ok()?;
    let mut out = Vec::with_capacity(items.len());
    for item in &items {
        let s = serde_json::from_str::<String>(item.get()).ok()?;
        if !valid_scope(&s) || out.contains(&s) {
            return None;
        }
        out.push(s);
    }
    Some(out)
}

/// Decodes the optional kind; absent means human. A present null is invalid:
/// spec 03 section 3 puts "`kind` is `"human"` or `"agent"`" inside the rule
/// "an argument that is missing, of the wrong type, or outside its stated
/// range is `400 invalid_params`" — null is the wrong type, and the reference
/// verifier agrees (reference-verifier.mjs argKind throws for anything but
/// "human"/"agent"). Go parity: absent -> human, explicit null ->
/// invalid_params (Go: kindFrom).
fn kind_arg(args: &Args) -> Option<String> {
    match args.get("kind") {
        None => Some(KIND_HUMAN.to_owned()),
        Some(raw) => {
            let kind = serde_json::from_str::<String>(raw.get()).ok()?;
            if kind == KIND_HUMAN || kind == KIND_AGENT {
                Some(kind)
            } else {
                None
            }
        }
    }
}

/// Decodes a submitted public key and applies the validity rules of spec 03
/// section 2, validity BEFORE any hash comparison (Go: publicKeyFrom).
fn public_key_arg(args: &Args) -> Result<Vec<u8>, JackError> {
    let Some(raw) = args.get("public_key") else {
        return Err(invalid_params());
    };
    let Ok(s) = serde_json::from_str::<String>(raw.get()) else {
        return Err(invalid_params());
    };
    let key = decode_b64url_fixed(&s, 32).map_err(|_| key_rejected())?;
    validate_public_key(&key).map_err(|_| key_rejected())?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Applies the default kind of records that do not carry one
/// (Go: kindOrHuman).
fn kind_or_human(kind: &str) -> &str {
    if kind.is_empty() {
        KIND_HUMAN
    } else {
        kind
    }
}

/// The user.list/user.get view of an entry (Go: viewOf).
fn entry_view(e: &RegistryEntry) -> serde_json::Value {
    json!({
        "kid": e.kid,
        "public_key": e.public_key,
        "name": e.name,
        "kind": kind_or_human(&e.kind),
        "scopes": e.scopes,
        "not_before": e.not_before,
        "not_after": e.not_after,
    })
}

/// The whoami view: same as the admin view minus public_key (spec 03
/// section 3.1).
fn whoami_view(e: &RegistryEntry) -> serde_json::Value {
    json!({
        "kid": e.kid,
        "name": e.name,
        "kind": kind_or_human(&e.kind),
        "scopes": e.scopes,
        "not_before": e.not_before,
        "not_after": e.not_after,
    })
}

/// The invite.list view; no key_ttl_seconds (Go: inviteView).
fn invite_view(i: &InviteRecord) -> serde_json::Value {
    json!({
        "invite_id": i.invite_id,
        "scopes": i.scopes,
        "kind": kind_or_human(&i.kind),
        "created_by": i.created_by,
        "created_at": i.created_at,
        "expires_at": i.expires_at,
    })
}

/// Counts entries that hold admin and are active at now (spec 03 section 4
/// rule 4; Go: activeAdmins).
fn active_admins(keys: &[RegistryEntry], now: i64) -> usize {
    keys.iter()
        .filter(|k| k.scopes.iter().any(|s| s == "admin") && entry_active(k, now))
        .count()
}

/// Stored id of an invite: base64url(SHA-256(code)); the code itself is never
/// stored (Go: inviteIDOf).
fn invite_id_of(raw_code: &[u8]) -> String {
    encode_b64url(&Sha256::digest(raw_code))
}

/// Adds `seconds` to `now` without wrapping. The spec has no overflow case, so
/// an overflowing TTL fails closed as an internal error instead of wrapping
/// into an immortal key (Go's plain `+` could wrap — deliberate divergence).
fn ttl_at(now: i64, seconds: i64) -> Result<i64, JackError> {
    now.checked_add(seconds).ok_or_else(internal_error)
}

/// Re-reads the calling administrator inside a transaction, so a concurrent
/// change to its scopes is honored (spec 03 section 9; Go: currentAdmin).
fn current_admin(edit: &StateEdit, kid: &str) -> Result<RegistryEntry, JackError> {
    let caller = edit.key(kid).ok_or_else(unknown_key)?;
    if !caller.scopes.iter().any(|s| s == "admin") {
        return Err(lacks_admin_scope());
    }
    Ok(caller)
}

/// Applies rules 1 and 2 of spec 03 section 4 to scopes about to be added to
/// an entry of the given kind (Go: grantable).
fn grantable(
    caller: &RegistryEntry,
    added: &[String],
    kind: &str,
    after: &[String],
) -> Result<(), JackError> {
    for s in added {
        if !caller.scopes.iter().any(|held| held == s) {
            return Err(JackError::new(
                403,
                codes::SCOPE_ESCALATION,
                "the key may not grant a scope it does not hold",
            ));
        }
    }
    if kind == KIND_AGENT && after.iter().any(|s| s == "admin") {
        return Err(JackError::new(
            403,
            codes::AGENT_ADMIN_FORBIDDEN,
            "an agent key cannot hold the admin scope",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tool implementation
// ---------------------------------------------------------------------------

impl NativeTools for Native {
    /// Dispatches one protocol-native tool (Go: Native.Call).
    fn call(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        match c.tool {
            TOOL_ENROLL => self.enroll(c),
            TOOL_WHOAMI => self.whoami(c),
            TOOL_ROTATE_KEY => self.rotate(c),
            TOOL_ADMIN_USER_LIST
            | TOOL_ADMIN_USER_GET
            | TOOL_ADMIN_USER_CREATE
            | TOOL_ADMIN_USER_SET_SCOPES
            | TOOL_ADMIN_USER_REVOKE
            | TOOL_ADMIN_INVITE_CREATE
            | TOOL_ADMIN_INVITE_LIST
            | TOOL_ADMIN_INVITE_REVOKE => self.admin(c),
            // Unreachable via the verifier's closed tool set.
            _ => Err(JackError::new(
                403,
                codes::OPERATION_DENIED,
                "operation is not permitted",
            )),
        }
    }
}

impl Native {
    /// Registers the key that signed the request, using an invite (spec 03
    /// section 3.2, Go: enroll). The verifier has already checked steps 1-4 of
    /// the enrollment procedure.
    fn enroll(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        if c.caller.is_some() {
            return Err(key_exists());
        }
        let args = parse_args(&c.arguments)?;
        // The audit target is the requested name as soon as it is readable,
        // even when another argument is rejected later.
        if let Some(requested) = str_arg(&args, "name") {
            c.target = requested;
        }
        let Some(code) = str_arg(&args, "code") else {
            return Err(invalid_params());
        };
        let Some(name) = str_arg(&args, "name") else {
            return Err(invalid_params());
        };
        let Some(public_key) = str_arg(&args, "public_key") else {
            return Err(invalid_params());
        };
        if !valid_name(&name) {
            return Err(invalid_params());
        }
        // Audit names the target even if the call fails from here on.
        c.target = name.clone();

        let raw_code = decode_b64url_fixed(&code, 32).map_err(|_| invalid_invite())?;
        let invite_id = invite_id_of(&raw_code);

        let mut enrolled: Option<RegistryEntry> = None;
        c.state.update(&mut |e| {
            let invite = e.invite(&invite_id).filter(|i| c.now < i.expires_at);
            let Some(invite) = invite else {
                return Err(invalid_invite());
            };
            if e.key_by_name(&name).is_some() {
                return Err(name_taken());
            }
            if e.key(c.kid).is_some() {
                return Err(key_exists());
            }
            let entry = RegistryEntry {
                kid: c.kid.to_owned(),
                public_key: public_key.clone(),
                name: name.clone(),
                kind: kind_or_human(&invite.kind).to_owned(),
                scopes: invite.scopes.clone(),
                not_before: None,
                not_after: invite
                    .key_ttl_seconds
                    .map(|ttl| ttl_at(c.now, ttl))
                    .transpose()?,
            };
            e.put_key(entry.clone());
            e.remove_invite(&invite_id);
            enrolled = Some(entry);
            Ok(())
        })?;
        // Assigned only on the success path above (Go's captured `enrolled`).
        let enrolled = enrolled.unwrap_or_default();
        Ok(NativeResult {
            structured: json!({
                "kid": enrolled.kid,
                "name": enrolled.name,
                "kind": enrolled.kind,
                "scopes": enrolled.scopes,
            }),
        })
    }

    /// Identifies the caller (Go: whoami). Never sets the audit target.
    fn whoami(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        let Some(caller) = c.caller else {
            return Err(unknown_key());
        };
        parse_args(&c.arguments)?;
        Ok(NativeResult {
            structured: whoami_view(caller),
        })
    }

    /// Replaces the caller's key (spec 03 section 3.1, Go: rotate). The proof
    /// is checked before the new key's existence so a caller cannot learn
    /// which keys are registered without holding the matching private key.
    fn rotate(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        let Some(caller) = c.caller else {
            return Err(unknown_key());
        };
        let args = parse_args(&c.arguments)?;
        // The audit target is the new kid as soon as the new key decodes,
        // even when the proof argument is rejected later.
        if let Ok(decoded) = public_key_arg(&args) {
            c.target = key_id(&decoded);
        }
        let Some(public_key) = str_arg(&args, "public_key") else {
            return Err(invalid_params());
        };
        let Some(proof) = str_arg(&args, "proof") else {
            return Err(invalid_params());
        };
        let raw = public_key_arg(&args)?;
        let new_kid = key_id(&raw);
        c.target = new_kid.clone();

        // A non-canonical 64-byte proof is also invalid_proof.
        let checked = decode_b64url_fixed(&proof, 64).ok().and_then(|sig| {
            let signing = rotate_proof_string(c.aud, &caller.kid, &new_kid, c.ts);
            verify(&raw, signing.as_bytes(), &sig).then_some(())
        });
        if checked.is_none() {
            return Err(JackError::new(
                400,
                codes::INVALID_PROOF,
                "the proof does not verify",
            ));
        }

        c.state.update(&mut |e| {
            if e.key(&new_kid).is_some() {
                return Err(key_exists());
            }
            let mut current = e.key(&caller.kid).ok_or_else(unknown_key)?;
            e.remove_key(&current.kid);
            current.kid = new_kid.clone();
            current.public_key = public_key.clone();
            e.put_key(current);
            Ok(())
        })?;
        Ok(NativeResult {
            structured: json!({ "kid": new_kid }),
        })
    }

    /// Runs the user and invite administration tools in the check order of
    /// spec 03 section 4: admin scope, arguments, key validity, target, rules,
    /// conflicts, last administrator, then the atomic change (Go: admin).
    fn admin(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        let Some(caller) = c.caller else {
            return Err(unknown_key());
        };
        if !caller.scopes.iter().any(|s| s == "admin") {
            return Err(lacks_admin_scope());
        }
        let args = parse_args(&c.arguments)?;

        match c.tool {
            TOOL_ADMIN_USER_LIST => {
                let mut keys = c.state.view().keys;
                keys.sort_by(|a, b| a.name.cmp(&b.name));
                let users: Vec<serde_json::Value> = keys.iter().map(entry_view).collect();
                Ok(NativeResult {
                    structured: json!({ "users": users }),
                })
            }
            TOOL_ADMIN_USER_GET => {
                let Some(kid) = str_arg(&args, "kid") else {
                    return Err(invalid_params());
                };
                c.target = kid.clone();
                let entry = c.state.lookup(&kid).ok_or_else(no_such_key)?;
                Ok(NativeResult {
                    structured: entry_view(&entry),
                })
            }
            TOOL_ADMIN_USER_CREATE => self.user_create(c, &args),
            TOOL_ADMIN_USER_SET_SCOPES => self.user_set_scopes(c, &args),
            TOOL_ADMIN_USER_REVOKE => self.user_revoke(c, &args),
            TOOL_ADMIN_INVITE_CREATE => self.invite_create(c, &args),
            TOOL_ADMIN_INVITE_LIST => self.invite_list(c),
            TOOL_ADMIN_INVITE_REVOKE => self.invite_revoke(c, &args),
            // Unreachable: dispatch filtered the tool set.
            _ => Err(JackError::new(
                403,
                codes::OPERATION_DENIED,
                "operation is not permitted",
            )),
        }
    }

    /// Creates a registry entry directly (Go: userCreate).
    fn user_create(&self, c: &mut NativeCall, args: &Args) -> Result<NativeResult, JackError> {
        let Some(name) = str_arg(args, "name").filter(|n| valid_name(n)) else {
            return Err(invalid_params());
        };
        // Audit names the target even if the call fails from here on (spec 03
        // section 8: target is the name); a malformed name sets nothing.
        c.target = name.clone();
        let Some(scopes) = scopes_arg(args, "scopes") else {
            return Err(invalid_params());
        };
        let Some(kind) = kind_arg(args) else {
            return Err(invalid_params());
        };
        let Some(not_before) = time_arg(args, "not_before") else {
            return Err(invalid_params());
        };
        let Some(not_after) = time_arg(args, "not_after") else {
            return Err(invalid_params());
        };
        if let (Some(from), Some(to)) = (not_before, not_after) {
            if from >= to {
                return Err(invalid_params());
            }
        }
        let raw = public_key_arg(args)?;
        let kid = key_id(&raw);
        let public_key = str_arg(args, "public_key").unwrap_or_default();

        c.state.update(&mut |e| {
            let caller = current_admin(e, c.kid)?;
            grantable(&caller, &scopes, &kind, &scopes)?;
            if e.key_by_name(&name).is_some() {
                return Err(name_taken());
            }
            if e.key(&kid).is_some() {
                return Err(key_exists());
            }
            e.put_key(RegistryEntry {
                kid: kid.clone(),
                public_key: public_key.clone(),
                name: name.clone(),
                kind: kind.clone(),
                scopes: scopes.clone(),
                not_before,
                not_after,
            });
            Ok(())
        })?;
        Ok(NativeResult {
            structured: json!({ "kid": kid }),
        })
    }

    /// Replaces an entry's scopes (Go: userSetScopes).
    fn user_set_scopes(&self, c: &mut NativeCall, args: &Args) -> Result<NativeResult, JackError> {
        let Some(kid) = str_arg(args, "kid") else {
            return Err(invalid_params());
        };
        // Audit names the target even if the call fails from here on (spec 03
        // section 8: target is the kid); malformed scopes must not clear it.
        c.target = kid.clone();
        let Some(scopes) = scopes_arg(args, "scopes") else {
            return Err(invalid_params());
        };

        let mut updated: Option<RegistryEntry> = None;
        c.state.update(&mut |e| {
            let caller = current_admin(e, c.kid)?;
            let mut target = e.key(&kid).ok_or_else(no_such_key)?;
            let added: Vec<String> = scopes
                .iter()
                .filter(|s| !target.scopes.contains(s))
                .cloned()
                .collect();
            grantable(&caller, &added, kind_or_human(&target.kind), &scopes)?;
            if target.scopes.iter().any(|s| !caller.scopes.contains(s)) {
                return Err(JackError::new(
                    403,
                    codes::FORBIDDEN_ADMIN_TARGET,
                    "the key holds a scope the administrator lacks",
                ));
            }
            target.scopes = scopes.clone();
            let mut after = e.keys();
            for entry in after.iter_mut() {
                if entry.kid == kid {
                    *entry = target.clone();
                }
            }
            if active_admins(&after, c.now) < 1 {
                return Err(last_admin());
            }
            e.put_key(target.clone());
            updated = Some(target);
            Ok(())
        })?;
        let updated = updated.unwrap_or_default();
        Ok(NativeResult {
            structured: entry_view(&updated),
        })
    }

    /// Deletes an entry (Go: userRevoke).
    fn user_revoke(&self, c: &mut NativeCall, args: &Args) -> Result<NativeResult, JackError> {
        let Some(kid) = str_arg(args, "kid") else {
            return Err(invalid_params());
        };
        c.target = kid.clone();

        c.state.update(&mut |e| {
            let caller = current_admin(e, c.kid)?;
            let target = e.key(&kid).ok_or_else(no_such_key)?;
            if target.scopes.iter().any(|s| !caller.scopes.contains(s)) {
                return Err(JackError::new(
                    403,
                    codes::FORBIDDEN_ADMIN_TARGET,
                    "the key holds a scope the administrator lacks",
                ));
            }
            let rest: Vec<RegistryEntry> = e.keys().into_iter().filter(|k| k.kid != kid).collect();
            if active_admins(&rest, c.now) < 1 {
                return Err(last_admin());
            }
            e.remove_key(&kid);
            Ok(())
        })?;
        Ok(NativeResult {
            structured: json!({ "kid": kid }),
        })
    }

    /// Mints a single-use invite (Go: inviteCreate).
    fn invite_create(&self, c: &mut NativeCall, args: &Args) -> Result<NativeResult, JackError> {
        let Some(scopes) = scopes_arg(args, "scopes") else {
            return Err(invalid_params());
        };
        let Some(kind) = kind_arg(args) else {
            return Err(invalid_params());
        };
        let ttl_seconds = match args.get("ttl_seconds") {
            None => DEFAULT_INVITE_TTL,
            Some(_) => {
                int_arg(args, "ttl_seconds", 1, MAX_INVITE_TTL).ok_or_else(invalid_params)?
            }
        };
        let key_ttl_seconds = match args.get("key_ttl_seconds") {
            None => None,
            Some(_) => {
                Some(int_arg(args, "key_ttl_seconds", 1, MAX_KEY_TTL).ok_or_else(invalid_params)?)
            }
        };

        let (code, invite_id) = self.new_invite_code().map_err(|_| internal_error())?;
        c.target = invite_id.clone();
        // Computed outside the transaction, like Go.
        let expires_at = ttl_at(c.now, ttl_seconds)?;
        let created_by = c.caller.map(|e| e.kid.clone()).unwrap_or_default();

        c.state.update(&mut |e| {
            let caller = current_admin(e, c.kid)?;
            grantable(&caller, &scopes, &kind, &scopes)?;
            e.put_invite(InviteRecord {
                invite_id: invite_id.clone(),
                scopes: scopes.clone(),
                kind: kind.clone(),
                created_by: created_by.clone(),
                created_at: c.now,
                expires_at,
                key_ttl_seconds,
            });
            Ok(())
        })?;
        Ok(NativeResult {
            structured: json!({
                "invite_id": invite_id,
                "code": code,
                "expires_at": expires_at,
            }),
        })
    }

    /// Lists live invites (Go: inviteList). No audit target.
    fn invite_list(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        let mut live: Vec<InviteRecord> = c
            .state
            .view()
            .invites
            .into_iter()
            .filter(|i| c.now < i.expires_at)
            .collect();
        live.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then(a.invite_id.cmp(&b.invite_id))
        });
        let invites: Vec<serde_json::Value> = live.iter().map(invite_view).collect();
        Ok(NativeResult {
            structured: json!({ "invites": invites }),
        })
    }

    /// Deletes a pending invite (Go: inviteRevoke).
    fn invite_revoke(&self, c: &mut NativeCall, args: &Args) -> Result<NativeResult, JackError> {
        let Some(invite_id) = str_arg(args, "invite_id") else {
            return Err(invalid_params());
        };
        c.target = invite_id.clone();

        c.state.update(&mut |e| {
            current_admin(e, c.kid)?;
            let invite = e.invite(&invite_id).filter(|i| c.now < i.expires_at);
            if invite.is_none() {
                return Err(JackError::new(404, codes::UNKNOWN_TARGET, "no such invite"));
            }
            e.remove_invite(&invite_id);
            Ok(())
        })?;
        Ok(NativeResult {
            structured: json!({ "invite_id": invite_id }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::state::MemoryState;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NOW: i64 = 1_767_225_600;
    const AUD: &str = "aud";

    /// Deterministic key material derived from `id` (Go: stateTestKey).
    fn test_signing(id: &str) -> SigningKey {
        let seed = Sha256::digest(id.as_bytes());
        SigningKey::from_bytes(&seed.into())
    }

    fn test_key(id: &str, name: &str, scopes: &[&str]) -> RegistryEntry {
        let public = test_signing(id).verifying_key().to_bytes();
        RegistryEntry {
            kid: key_id(&public),
            public_key: encode_b64url(&public),
            name: name.to_owned(),
            kind: KIND_HUMAN.to_owned(),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            not_before: None,
            not_after: None,
        }
    }

    /// Native with a deterministic random source; invite codes repeat.
    fn deterministic_native() -> Native {
        Native::new(NativeOptions {
            random_bytes: Some(Arc::new(|n| Ok(vec![0xA5; n]))),
        })
    }

    fn raw_args(json: &str) -> Option<Box<RawValue>> {
        Some(serde_json::from_str::<Box<RawValue>>(json).unwrap())
    }

    fn args_of(json: &str) -> Args {
        parse_args(&raw_args(json)).unwrap()
    }

    fn make_call<'a>(
        tool: &'static str,
        arguments: Option<Box<RawValue>>,
        caller: Option<&'a RegistryEntry>,
        kid: &'a str,
        state: Arc<dyn StateStore>,
    ) -> NativeCall<'a> {
        NativeCall {
            tool,
            arguments,
            caller,
            kid,
            ts: NOW,
            now: NOW,
            aud: AUD,
            state,
            target: String::new(),
        }
    }

    fn seed(entries: &[RegistryEntry], invites: &[InviteRecord], state: &dyn StateStore) {
        state
            .update(&mut |e| {
                for k in entries {
                    e.put_key(k.clone());
                }
                for i in invites {
                    e.put_invite(i.clone());
                }
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn bootstrap_then_enroll() {
        // One store shared by bootstrap and both enroll calls: the invite must
        // be visible to the tool calls.
        let state = Arc::new(MemoryState::new());
        let opts = || NativeOptions {
            random_bytes: Some(Arc::new(|n| Ok(vec![0xA5; n]))),
        };
        // TTL bounds (Go TestBootstrapAdminThenEnroll).
        assert_eq!(
            bootstrap_admin(state.as_ref(), NOW, 0, opts())
                .unwrap_err()
                .code,
            "internal_error"
        );
        assert!(bootstrap_admin(state.as_ref(), NOW, MAX_INVITE_TTL + 1, opts()).is_err());

        let code = bootstrap_admin(state.as_ref(), NOW, 600, opts()).unwrap();
        let view = state.view();
        assert_eq!(view.invites.len(), 1);
        assert_eq!(view.invites[0].scopes, vec!["admin".to_owned()]);
        assert_eq!(view.invites[0].created_by, "bootstrap");
        assert_eq!(view.invites[0].expires_at, NOW + 600);

        // First enrollment succeeds; the entry carries the invite's grants.
        let first = test_key("enroll-1", "first", &[]);
        let native = deterministic_native();
        let mut call = make_call(
            TOOL_ENROLL,
            raw_args(&format!(
                r#"{{"code":"{code}","name":"first","public_key":"{}"}}"#,
                first.public_key
            )),
            None,
            &first.kid,
            Arc::clone(&state) as Arc<dyn StateStore>,
        );
        let res = native.call(&mut call).unwrap();
        assert_eq!(res.structured["kid"], first.kid.as_str());
        assert_eq!(res.structured["name"], "first");
        assert_eq!(res.structured["kind"], "human");
        assert_eq!(res.structured["scopes"], serde_json::json!(["admin"]));
        // Stored entry: scopes from the invite, kid from the submitted key.
        let view = state.view();
        assert_eq!(view.keys.len(), 1);
        assert_eq!(view.keys[0].kid, first.kid);
        assert_eq!(view.keys[0].name, "first");
        assert_eq!(view.keys[0].kind, KIND_HUMAN);
        assert_eq!(view.keys[0].scopes, vec!["admin".to_owned()]);
        assert_eq!(view.keys[0].not_after, None);
        // Single-use: the invite was consumed, a second use is invalid.
        assert!(state.view().invites.is_empty());
        let second = test_key("enroll-2", "second", &[]);
        let mut call = make_call(
            TOOL_ENROLL,
            raw_args(&format!(
                r#"{{"code":"{code}","name":"second","public_key":"{}"}}"#,
                second.public_key
            )),
            None,
            &second.kid,
            Arc::clone(&state) as Arc<dyn StateStore>,
        );
        let err = native.call(&mut call).unwrap_err();
        assert_eq!(err.http_status, 403);
        assert_eq!(err.code, codes::INVALID_INVITE);
    }

    #[test]
    fn invite_code_is_never_stored() {
        let state = Arc::new(MemoryState::new());
        let caller = test_key("admin", "root", &["admin", "read"]);
        seed(std::slice::from_ref(&caller), &[], state.as_ref());
        let native = deterministic_native();
        let mut call = make_call(
            TOOL_ADMIN_INVITE_CREATE,
            raw_args(r#"{"scopes":["read"]}"#),
            Some(&caller),
            &caller.kid,
            Arc::clone(&state) as Arc<dyn StateStore>,
        );
        let res = native.call(&mut call).unwrap();
        let code = res.structured["code"].as_str().unwrap();
        assert_eq!(code.len(), 43);
        let dumped = format!("{:?}", (state.view().keys, state.view().invites));
        assert!(!dumped.contains(code), "invite code leaked into the store");
        // The stored invite id (its hash) may appear.
        assert!(dumped.contains(res.structured["invite_id"].as_str().unwrap()));
    }

    #[test]
    fn admin_requires_admin_before_arguments() {
        let state = Arc::new(MemoryState::new());
        let caller = test_key("plain", "plain", &["read"]);
        seed(std::slice::from_ref(&caller), &[], state.as_ref());
        let native = Native::new(NativeOptions::default());
        let mut call = make_call(
            TOOL_ADMIN_USER_LIST,
            raw_args("7"),
            Some(&caller),
            &caller.kid,
            Arc::clone(&state) as Arc<dyn StateStore>,
        );
        let err = native.call(&mut call).unwrap_err();
        assert_eq!(err.http_status, 403);
        assert_eq!(err.code, codes::INSUFFICIENT_SCOPE);
    }

    #[test]
    fn last_admin_survives_concurrent_revokes() {
        let native = Native::new(NativeOptions::default());
        for _ in 0..50 {
            let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
            let a = test_key("admin-a", "admin-a", &["admin"]);
            let b = test_key("admin-b", "admin-b", &["admin"]);
            seed(&[a.clone(), b.clone()], &[], state.as_ref());
            let successes = AtomicUsize::new(0);
            std::thread::scope(|s| {
                let native = &native;
                let state = &state;
                let successes = &successes;
                let a = &a;
                let b = &b;
                s.spawn(move || {
                    let store: Arc<dyn StateStore> = Arc::clone(state);
                    let mut call = make_call(
                        TOOL_ADMIN_USER_REVOKE,
                        raw_args(&format!(r#"{{"kid":"{}"}}"#, b.kid)),
                        Some(a),
                        &a.kid,
                        store,
                    );
                    if native.call(&mut call).is_ok() {
                        successes.fetch_add(1, Ordering::SeqCst);
                    }
                });
                s.spawn(move || {
                    let store: Arc<dyn StateStore> = Arc::clone(state);
                    let mut call = make_call(
                        TOOL_ADMIN_USER_REVOKE,
                        raw_args(&format!(r#"{{"kid":"{}"}}"#, a.kid)),
                        Some(b),
                        &b.kid,
                        store,
                    );
                    if native.call(&mut call).is_ok() {
                        successes.fetch_add(1, Ordering::SeqCst);
                    }
                });
            });
            // Exactly one transaction can win: the first removes one admin,
            // so the second caller is then gone (401) or its target is gone
            // (404).
            assert_eq!(successes.load(Ordering::SeqCst), 1);
            assert!(active_admins(&state.view().keys, NOW) >= 1);
        }
    }

    #[test]
    fn last_admin_survives_many_concurrent_demotes_and_revokes() {
        let native = Native::new(NativeOptions::default());
        let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
        let a = test_key("admin-a", "admin-a", &["admin", "read"]);
        let b = test_key("admin-b", "admin-b", &["admin", "read"]);
        seed(&[a.clone(), b.clone()], &[], state.as_ref());
        let successes = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|s| {
            let native = &native;
            let successes = &successes;
            let a = &a;
            let b = &b;
            for i in 0..24 {
                let store: Arc<dyn StateStore> = Arc::clone(&state);
                s.spawn(move || {
                    let (caller, target) = if i % 2 == 0 { (a, a) } else { (b, b) };
                    let revoke = i % 4 < 2;
                    let arguments = if revoke {
                        raw_args(&format!(r#"{{"kid":"{}"}}"#, target.kid))
                    } else {
                        raw_args(&format!(r#"{{"kid":"{}","scopes":["read"]}}"#, target.kid))
                    };
                    let tool = if revoke {
                        TOOL_ADMIN_USER_REVOKE
                    } else {
                        TOOL_ADMIN_USER_SET_SCOPES
                    };
                    let mut call = make_call(tool, arguments, Some(caller), &caller.kid, store);
                    if let Ok(res) = native.call(&mut call) {
                        successes
                            .lock()
                            .unwrap()
                            .push(res.structured["kid"].as_str().unwrap().to_owned());
                    }
                });
            }
        });
        let wins = successes.into_inner().unwrap();
        // The first serialized operation always succeeds: both admins are
        // active, so removing or demoting either leaves the other.
        assert!(!wins.is_empty());
        assert!(active_admins(&state.view().keys, NOW) >= 1);
        // Two successes on DISTINCT targets are impossible: each success
        // leaves only one active admin, and a change to the OTHER one then
        // evaluates the last-admin rule against a post-change registry of
        // zero admins (or the demoted caller fails current_admin).
        assert!(
            wins.iter().all(|k| k == &wins[0]),
            "distinct targets succeeded: {wins:?}"
        );
    }

    #[test]
    fn int_arg_is_lexical() {
        // -0 is the integer 0 (spec 03 section 3), in and out of range.
        assert_eq!(int_arg(&args_of(r#"{"v":-0}"#), "v", 0, 100), Some(0));
        assert_eq!(
            int_arg(&args_of(r#"{"v":-0}"#), "v", 1, MAX_INVITE_TTL),
            None
        );
        // Texts that are not valid JSON cannot reach int_arg (the verifier only
        // hands over parsed JSON), so the lexical rule is checked directly.
        for text in ["01", "-01", "+1", "-", "", "--1", "1_0", " 1"] {
            assert_eq!(json_int(text), None, "text {text:?}");
        }
        // Fraction, exponent and non-numbers (valid JSON) all fail.
        for text in ["1.0", "1e3", "1E3", "\"5\"", "true", "null"] {
            assert_eq!(
                int_arg(
                    &args_of(&format!(r#"{{"v":{text}}}"#)),
                    "v",
                    i64::MIN,
                    i64::MAX
                ),
                None,
                "text {text}"
            );
        }
        assert_eq!(int_arg(&args_of(r#"{"v":-1}"#), "v", -5, 5), Some(-1));
        assert_eq!(int_arg(&args_of(r#"{"v":-1}"#), "v", 0, 5), None);
        // No f64 rounding: 2^53+1 stays exact.
        assert_eq!(
            int_arg(&args_of(r#"{"v":9007199254740993}"#), "v", 0, i64::MAX),
            Some(9_007_199_254_740_993)
        );
        assert_eq!(
            int_arg(
                &args_of(r#"{"v":9007199254740993}"#),
                "v",
                0,
                999_999_999_999
            ),
            None
        );
        // A 20-digit magnitude parses in i128 and fails the range check.
        assert_eq!(
            int_arg(&args_of(r#"{"v":99999999999999999999}"#), "v", 0, i64::MAX),
            None
        );
    }

    #[test]
    fn time_arg_table() {
        assert_eq!(time_arg(&args_of(r#"{"v":-0}"#), "v"), Some(Some(0)));
        assert_eq!(time_arg(&args_of(r#"{"v":null}"#), "v"), Some(None));
        assert_eq!(time_arg(&args_of("{}"), "v"), Some(None));
        assert_eq!(time_arg(&args_of(r#"{"v":1.5}"#), "v"), None);
    }

    #[test]
    fn user_create_accepts_negative_zero_not_after() {
        // Mirrors the fixture admin-create-not-after-negative-zero; spec 03
        // section 3: `-0` is the integer 0.
        let state = Arc::new(MemoryState::new());
        let caller = test_key("admin", "root", &["admin", "read"]);
        seed(std::slice::from_ref(&caller), &[], state.as_ref());
        let native = deterministic_native();
        let dave = test_key("dave", "dave", &["read"]);
        let mut call = make_call(
            TOOL_ADMIN_USER_CREATE,
            raw_args(&format!(
                r#"{{"name":"dave","public_key":"{}","scopes":["read"],"not_after":-0}}"#,
                dave.public_key
            )),
            Some(&caller),
            &caller.kid,
            Arc::clone(&state) as Arc<dyn StateStore>,
        );
        native.call(&mut call).unwrap();
        let stored = state.lookup(&dave.kid).unwrap();
        assert_eq!(stored.not_after, Some(0));
        assert_eq!(stored.name, "dave");
    }

    #[test]
    fn kind_arg_null_is_invalid_absent_is_human() {
        assert_eq!(kind_arg(&args_of(r#"{"kind":null}"#)), None);
        assert_eq!(kind_arg(&args_of("{}")), Some(KIND_HUMAN.to_owned()));
    }

    #[test]
    fn audit_target_names_target_on_failures() {
        let state = Arc::new(MemoryState::new());
        let caller = test_key("admin", "root", &["admin", "read"]);
        seed(std::slice::from_ref(&caller), &[], state.as_ref());
        let native = Native::new(NativeOptions::default());

        // (a) user.create: valid name, small-order public key -> key_rejected,
        //     and the target is already the name (spec 03 section 8).
        let bad_pub = encode_b64url(&[1u8; 32]);
        let mut call = make_call(
            TOOL_ADMIN_USER_CREATE,
            raw_args(&format!(
                r#"{{"name":"dave","public_key":"{bad_pub}","scopes":["read"]}}"#
            )),
            Some(&caller),
            &caller.kid,
            Arc::clone(&state) as Arc<dyn StateStore>,
        );
        let err = native.call(&mut call).unwrap_err();
        assert_eq!(err.code, codes::KEY_REJECTED);
        assert_eq!(call.target, "dave");

        // (b) user.set_scopes: well-formed kid, scopes as a string ->
        //     invalid_params, and the target is already the kid.
        let alice = test_key("alice", "alice", &["read"]);
        seed(std::slice::from_ref(&alice), &[], state.as_ref());
        let mut call = make_call(
            TOOL_ADMIN_USER_SET_SCOPES,
            raw_args(&format!(r#"{{"kid":"{}","scopes":"read"}}"#, alice.kid)),
            Some(&caller),
            &caller.kid,
            Arc::clone(&state) as Arc<dyn StateStore>,
        );
        let err = native.call(&mut call).unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);
        assert_eq!(call.target, alice.kid);
    }

    #[test]
    fn failed_tool_calls_mutate_nothing() {
        // Validation precedes the first mutation in EVERY native tool: each
        // closure is checks-then-mutate (enroll: put_key/remove_invite after
        // the invite+name+kid checks; rotate: remove/put after key_exists;
        // user.create: put after grantable+name+kid; set_scopes: put after
        // grantable+forbidden+last_admin; revoke: remove after
        // forbidden+last_admin; invite.create: put after grantable;
        // invite.revoke: remove after found+expiry; bootstrap: put after the
        // ttl check). This pins the tool-level half; the store-level
        // commit-only-on-Ok property (a closure that DOES mutate then fail
        // rolls back) is pinned by state.rs::rollback_on_error.
        let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
        let root = test_key("root", "root", &["admin", "read"]);
        let bob_signing = test_signing("bob");
        let alice = test_key("alice", "alice", &["read"]);
        let bob = test_key("bob", "bob", &["read"]);
        let expired = InviteRecord {
            invite_id: "expired".into(),
            scopes: vec!["read".into()],
            kind: KIND_HUMAN.into(),
            created_by: "root".into(),
            created_at: NOW - 1,
            expires_at: NOW,
            key_ttl_seconds: None,
        };
        seed(
            &[root.clone(), alice.clone(), bob.clone()],
            &[expired],
            state.as_ref(),
        );
        let native = deterministic_native();
        let call = |tool: &'static str,
                    args: String,
                    caller: Option<&RegistryEntry>,
                    kid: &str|
         -> Result<NativeResult, JackError> {
            let mut c = make_call(tool, raw_args(&args), caller, kid, Arc::clone(&state));
            native.call(&mut c)
        };

        // 1. enroll: valid seeded invite, name taken -> 409 name_taken AFTER
        //    the invite check but BEFORE put_key/remove_invite; the failure
        //    does not consume the invite (spec 03 section 3.2 step 7).
        let code = bootstrap_admin(
            state.as_ref(),
            NOW,
            600,
            NativeOptions {
                random_bytes: Some(Arc::new(|n| Ok(vec![0xA5; n]))),
            },
        )
        .unwrap();
        let before: crate::server::state::StateView = state.view();
        let fresh = test_key("fresh", "root", &[]);
        let err = call(
            TOOL_ENROLL,
            format!(
                r#"{{"code":"{code}","name":"root","public_key":"{}"}}"#,
                fresh.public_key
            ),
            None,
            &fresh.kid,
        )
        .unwrap_err();
        assert_eq!(err.http_status, 409);
        assert_eq!(err.code, codes::NAME_TAKEN);
        assert_eq!(before, state.view());
        // view() does not filter: the seeded expired invite plus the bootstrap one.
        assert_eq!(state.view().invites.len(), 2);
        assert!(state.lookup(&fresh.kid).is_none());

        // 2. rotate: valid proof but the new kid is already registered ->
        //    mid-closure key_exists BEFORE remove_key/put_key (spec 03
        //    section 3.1 order: arguments, new key, proof, existence).
        let proof = encode_b64url(
            &bob_signing
                .sign(rotate_proof_string(AUD, &alice.kid, &bob.kid, NOW).as_bytes())
                .to_bytes(),
        );
        let before = state.view();
        let err = call(
            TOOL_ROTATE_KEY,
            format!(r#"{{"public_key":"{}","proof":"{proof}"}}"#, bob.public_key),
            Some(&alice),
            &alice.kid,
        )
        .unwrap_err();
        assert_eq!(err.http_status, 409);
        assert_eq!(err.code, codes::KEY_EXISTS);
        assert_eq!(before, state.view());

        // 3. rotate with an invalid proof fails before the closure.
        let bad_proof = encode_b64url(&[0u8; 64]);
        let err = call(
            TOOL_ROTATE_KEY,
            format!(
                r#"{{"public_key":"{}","proof":"{bad_proof}"}}"#,
                bob.public_key
            ),
            Some(&alice),
            &alice.kid,
        )
        .unwrap_err();
        assert_eq!(err.http_status, 400);
        assert_eq!(err.code, codes::INVALID_PROOF);
        assert_eq!(before, state.view());

        // 4. user.create: escalation -> 403 scope_escalation (spec 03
        //    section 4 rule 1), unchanged.
        let esc = test_key("esc", "esc", &[]);
        let err = call(
            TOOL_ADMIN_USER_CREATE,
            format!(
                r#"{{"name":"esc","public_key":"{}","scopes":["lifecycle"]}}"#,
                esc.public_key
            ),
            Some(&root),
            &root.kid,
        )
        .unwrap_err();
        assert_eq!(err.http_status, 403);
        assert_eq!(err.code, codes::SCOPE_ESCALATION);
        assert_eq!(before, state.view());

        // 5. user.set_scopes: the sole admin demotes itself -> mid-closure
        //    last_admin AFTER grantable+forbidden, BEFORE put_key (spec 03
        //    section 4 rule 4), unchanged.
        let err = call(
            TOOL_ADMIN_USER_SET_SCOPES,
            format!(r#"{{"kid":"{}","scopes":["read"]}}"#, root.kid),
            Some(&root),
            &root.kid,
        )
        .unwrap_err();
        assert_eq!(err.http_status, 409);
        assert_eq!(err.code, codes::LAST_ADMIN);
        assert_eq!(before, state.view());

        // 6. user.revoke: the sole admin revokes itself -> mid-closure
        //    last_admin BEFORE remove_key, unchanged.
        let err = call(
            TOOL_ADMIN_USER_REVOKE,
            format!(r#"{{"kid":"{}"}}"#, root.kid),
            Some(&root),
            &root.kid,
        )
        .unwrap_err();
        assert_eq!(err.http_status, 409);
        assert_eq!(err.code, codes::LAST_ADMIN);
        assert_eq!(before, state.view());

        // 7. invite.create: escalation -> 403 scope_escalation, unchanged.
        let err = call(
            TOOL_ADMIN_INVITE_CREATE,
            r#"{"scopes":["lifecycle"]}"#.to_owned(),
            Some(&root),
            &root.kid,
        )
        .unwrap_err();
        assert_eq!(err.http_status, 403);
        assert_eq!(err.code, codes::SCOPE_ESCALATION);
        assert_eq!(before, state.view());

        // 8. invite.revoke: the invite expired at NOW -> 404 unknown_target
        //    BEFORE remove_invite, unchanged.
        let err = call(
            TOOL_ADMIN_INVITE_REVOKE,
            r#"{"invite_id":"expired"}"#.to_owned(),
            Some(&root),
            &root.kid,
        )
        .unwrap_err();
        assert_eq!(err.http_status, 404);
        assert_eq!(err.code, codes::UNKNOWN_TARGET);
        assert_eq!(before, state.view());

        // 9. bootstrap_admin: ttl 0 -> Err before any update, unchanged.
        assert!(bootstrap_admin(
            state.as_ref(),
            NOW,
            0,
            NativeOptions {
                random_bytes: Some(Arc::new(|n| Ok(vec![0xA5; n]))),
            },
        )
        .is_err());
        assert_eq!(before, state.view());
    }

    #[test]
    fn enroll_key_ttl_overflow_fails_closed() {
        let state = Arc::new(MemoryState::new());
        let invite = InviteRecord {
            invite_id: invite_id_of(&[0xA5; 32]),
            scopes: vec!["read".to_owned()],
            kind: KIND_HUMAN.to_owned(),
            created_by: "root".to_owned(),
            created_at: NOW,
            expires_at: NOW + 600,
            // An attacker-crafted (or corrupted) store could hold this; the
            // TTL math must fail closed, not wrap into an immortal key.
            key_ttl_seconds: Some(i64::MAX),
        };
        seed(&[], &[invite], state.as_ref());
        let before: crate::server::state::StateView = state.view();
        let fresh = test_key("fresh", "newcomer", &[]);
        let native = deterministic_native();
        let mut call = make_call(
            TOOL_ENROLL,
            raw_args(&format!(
                r#"{{"code":"{}","name":"newcomer","public_key":"{}"}}"#,
                encode_b64url(&[0xA5; 32]),
                fresh.public_key
            )),
            None,
            &fresh.kid,
            Arc::clone(&state) as Arc<dyn StateStore>,
        );
        let err = native.call(&mut call).unwrap_err();
        assert_eq!(err.http_status, 500);
        assert_eq!(err.code, "internal_error");
        // The invite was NOT consumed and no key was added.
        assert_eq!(before, state.view());
    }
}
