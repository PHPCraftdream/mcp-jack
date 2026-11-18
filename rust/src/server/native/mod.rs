//! Protocol-native tools: enrollment, rotation, users, invites (Go: server/native.go).

use std::sync::Arc;

use serde_json::json;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use super::state::{InviteRecord, RegistryEntry, StateEdit, StateStore};
use super::verify::{
    entry_active, NativeCall, NativeResult, NativeTools, TOOL_ADMIN_INVITE_CREATE,
    TOOL_ADMIN_INVITE_LIST, TOOL_ADMIN_INVITE_REVOKE, TOOL_ADMIN_USER_CREATE, TOOL_ADMIN_USER_GET,
    TOOL_ADMIN_USER_LIST, TOOL_ADMIN_USER_REVOKE, TOOL_ADMIN_USER_SET_ADMIN, TOOL_ENROLL,
    TOOL_ROTATE_KEY, TOOL_WHOAMI,
};
use crate::ed25519::{validate_public_key, verify};
use crate::encoding::{decode_b64url_fixed, encode_b64url, key_id};
use crate::error::{codes, JackError};
use crate::signing::rotate_proof_string;
use crate::syntax::valid_name;

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
                getrandom::fill(&mut b)
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
/// Go: BootstrapAdmin): one single-use invite with `admin: true` — the first
/// administrator's invite — valid for `ttl_seconds`. Returns the invite CODE,
/// which exists nowhere else. Not an MCP tool; never called from a network
/// handler.
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
        purge_expired_invites(e, now);
        e.put_invite(InviteRecord {
            invite_id: invite_id.clone(),
            admin: true,
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

fn admin_required() -> JackError {
    JackError::new(
        403,
        codes::ADMIN_REQUIRED,
        "the caller is not an administrator",
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

/// Decodes a present JSON boolean member: the member's raw JSON text must be
/// exactly a JSON boolean (parsed via serde into bool), so null, string and
/// number are all None. An ABSENT member is None too — the caller decides the
/// default (and `set_admin` requires it) (spec 03 sections 3.3 and 4).
fn bool_arg(args: &Args, key: &str) -> Option<bool> {
    let raw = args.get(key)?;
    serde_json::from_str::<bool>(raw.get()).ok()
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

/// The user.list/user.get view of an entry; `admin` is ALWAYS present
/// (spec 02 section 1, Go: viewOf).
fn entry_view(e: &RegistryEntry) -> serde_json::Value {
    json!({
        "kid": e.kid,
        "public_key": e.public_key,
        "name": e.name,
        "admin": e.admin,
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
        "admin": e.admin,
        "not_before": e.not_before,
        "not_after": e.not_after,
    })
}

/// The invite.list view; no key_ttl_seconds (Go: inviteView).
fn invite_view(i: &InviteRecord) -> serde_json::Value {
    json!({
        "invite_id": i.invite_id,
        "admin": i.admin,
        "created_by": i.created_by,
        "created_at": i.created_at,
        "expires_at": i.expires_at,
    })
}

/// Counts entries with admin=true that are active at now (spec 03 section 4
/// rule 4; Go: activeAdmins).
fn active_admins(keys: &[RegistryEntry], now: i64) -> usize {
    keys.iter()
        .filter(|k| k.admin && entry_active(k, now))
        .count()
}

/// Stored id of an invite: base64url(SHA-256(code)); the code itself is never
/// stored (Go: inviteIDOf).
pub(crate) fn invite_id_of(raw_code: &[u8]) -> String {
    encode_b64url(&Sha256::digest(raw_code))
}

/// Removes every invite no longer valid at `now` from the pending edit, so an
/// invite-editing update never keeps dead records (spec 03: expired invites
/// are not listed and need not be stored). Runs inside the same atomic
/// update; a later failure rolls it back with the whole edit (Go:
/// purgeExpiredInvites).
fn purge_expired_invites(e: &mut StateEdit, now: i64) {
    let expired: Vec<String> = e
        .invites()
        .into_iter()
        .filter(|i| now >= i.expires_at)
        .map(|i| i.invite_id)
        .collect();
    for invite_id in &expired {
        e.remove_invite(invite_id);
    }
}

/// Adds `seconds` to `now` without wrapping. The spec has no overflow case, so
/// an overflowing TTL fails closed as an internal error instead of wrapping
/// into an immortal key (Go's plain `+` could wrap — deliberate divergence).
fn ttl_at(now: i64, seconds: i64) -> Result<i64, JackError> {
    now.checked_add(seconds).ok_or_else(internal_error)
}

/// Re-reads the calling administrator inside a transaction, so a concurrent
/// demotion is honored: the admin gate is checked against the CURRENT
/// registry, so concurrent demotions serialize correctly (spec 03 section 4
/// rule 1, section 9; Go: currentAdmin).
fn current_admin(edit: &StateEdit, kid: &str) -> Result<RegistryEntry, JackError> {
    let caller = edit.key(kid).ok_or_else(unknown_key)?;
    if !caller.admin {
        return Err(admin_required());
    }
    Ok(caller)
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
            | TOOL_ADMIN_USER_SET_ADMIN
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
            purge_expired_invites(e, c.now);
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
                admin: invite.admin,
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
                "admin": enrolled.admin,
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
    /// spec 03 section 4: caller admin, arguments, key validity, target,
    /// rules, conflicts, last administrator, then the atomic change (Go:
    /// admin).
    fn admin(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        let Some(caller) = c.caller else {
            return Err(unknown_key());
        };
        // The admin gate precedes argument parsing: an argument error must
        // not leak anything to a non-admin caller (spec 03 sections 3.3
        // and 4).
        if !caller.admin {
            return Err(admin_required());
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
            TOOL_ADMIN_USER_SET_ADMIN => self.user_set_admin(c, &args),
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

    /// Creates a registry entry directly (Go: userCreate). Arguments are
    /// looked up by exact member name, so stale `scopes`/`kind` members in a
    /// request are inert (ignored) per spec 03 section 3. A create can never
    /// trip the last-admin rule: it ADDS an entry, so the active-admin count
    /// cannot drop (spec 03 section 4 rule 4).
    fn user_create(&self, c: &mut NativeCall, args: &Args) -> Result<NativeResult, JackError> {
        let Some(name) = str_arg(args, "name").filter(|n| valid_name(n)) else {
            return Err(invalid_params());
        };
        // Audit names the target even if the call fails from here on (spec 03
        // section 8: target is the name); a malformed name sets nothing.
        c.target = name.clone();
        // Optional strict boolean, default false; present-but-mistyped fails
        // closed (spec 03 sections 3 and 4).
        let admin = match args.get("admin") {
            // Absent: the documented default false (spec 03 section 3).
            None => false,
            // Present: must be a strict JSON boolean (spec 03 section 3);
            // null/string/number fail closed.
            Some(_) => bool_arg(args, "admin").ok_or_else(invalid_params)?,
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
            // Rules 1-3 of spec 03 section 4, against the CURRENT registry:
            // caller admin, then key validity (already done above), then
            // name unused, kid unregistered.
            current_admin(e, c.kid)?;
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
                admin,
                not_before,
                not_after,
            });
            Ok(())
        })?;
        Ok(NativeResult {
            structured: json!({ "kid": kid }),
        })
    }

    /// Sets an entry's admin flag (Go: userSetAdmin). `admin` is REQUIRED:
    /// absent, null, string and number are all invalid_params. The last-admin
    /// rule is evaluated against the registry AS IT WOULD BE after the
    /// change, so concurrent demotions serialize (spec 03 section 4 rule 4).
    fn user_set_admin(&self, c: &mut NativeCall, args: &Args) -> Result<NativeResult, JackError> {
        let Some(kid) = str_arg(args, "kid") else {
            return Err(invalid_params());
        };
        // Audit names the target even if the call fails from here on (spec 03
        // section 8: target is the kid).
        c.target = kid.clone();
        let Some(admin) = bool_arg(args, "admin") else {
            return Err(invalid_params());
        };

        let mut updated: Option<RegistryEntry> = None;
        c.state.update(&mut |e| {
            // Caller re-read + admin gate against the CURRENT registry, so a
            // concurrent demotion of the caller wins (spec 03 section 4).
            current_admin(e, c.kid)?;
            let mut target = e.key(&kid).ok_or_else(no_such_key)?;
            target.admin = admin;
            // Last-admin rule against the would-be registry.
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
            // Caller re-read + admin gate against the CURRENT registry.
            current_admin(e, c.kid)?;
            let target = e.key(&kid).ok_or_else(no_such_key)?;
            // Last-admin rule against the would-be registry without the kid.
            let rest: Vec<RegistryEntry> = e.keys().into_iter().filter(|k| k.kid != kid).collect();
            if active_admins(&rest, c.now) < 1 {
                return Err(last_admin());
            }
            e.remove_key(&target.kid);
            Ok(())
        })?;
        Ok(NativeResult {
            structured: json!({ "kid": kid }),
        })
    }

    /// Mints a single-use invite (Go: inviteCreate). Stale `scopes`/`kind`
    /// members are inert: arguments are looked up by exact member name (spec
    /// 03 section 3).
    fn invite_create(&self, c: &mut NativeCall, args: &Args) -> Result<NativeResult, JackError> {
        let admin = match args.get("admin") {
            // Absent: the documented default false (spec 03 section 3).
            None => false,
            // Present: must be a strict JSON boolean (spec 03 section 3);
            // null/string/number fail closed.
            Some(_) => bool_arg(args, "admin").ok_or_else(invalid_params)?,
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
            // Caller re-read + admin gate against the CURRENT registry.
            current_admin(e, c.kid)?;
            purge_expired_invites(e, c.now);
            e.put_invite(InviteRecord {
                invite_id: invite_id.clone(),
                admin,
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
            purge_expired_invites(e, c.now);
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
mod tests;
