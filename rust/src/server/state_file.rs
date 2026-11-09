//! Strict state-file loading and atomic persistence (Go: server/statefile.go).
//! See spec 02-authorization.md section 1 for the load-time entry rules and
//! spec 03 sections 3.3 and 10 for the invite record rules.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
// `.mode(0o600)` on the temp file comes from this unix-only trait.
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::encoding::{decode_b64url_fixed, key_id};
use crate::error::JackError;
use crate::syntax::valid_name;

use super::state::{InviteRecord, RegistryEntry, StateData, StateEdit, StateStore, StateView};

/// Code carried by every strict-load and validation failure, with
/// `http_status` 0: like Go's sentinel ErrStateCorrupt, a corrupt state file
/// is a startup/administrator problem and never becomes an HTTP response.
/// Read/IO failures map to `JackError::new(500, "internal", ...)` like the
/// audit sink. Messages include the file path (Go wraps errors with it).
pub const CODE_STATE_CORRUPT: &str = "state_corrupt";

/// Stored invite key_ttl_seconds bound (spec 03 sections 3.3 and 10).
const MAX_KEY_TTL_SECONDS: i64 = 31_536_000;

/// The on-disk document layout: version 1, keys sorted by kid, invites by
/// invite id. `serde_json::from_str` rejects trailing data after the JSON
/// document (Go's second Decode must return io.EOF); `deny_unknown_fields`
/// applies recursively to the nested entries like Go's
/// DisallowUnknownFields. LEGACY DIAGNOSTIC: a document, entry or invite
/// record containing legacy `kind` or `scopes` fails at decode, and serde's
/// unknown-field errors already NAME the offending member ("unknown field
/// `kind`"); the corrupt() wrapper embeds that message verbatim, satisfying
/// the obligation to name the member — the file is never migrated, stripped
/// or rewritten. The same decode rejects missing required invite members,
/// mistyped `admin`, and null or non-integer `key_ttl_seconds` (which is
/// omitted during serialization when absent).
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StateDocument {
    version: i64,
    keys: Vec<RegistryEntry>,
    invites: Vec<InviteRecord>,
}

/// File-backed [`StateStore`]. On-disk format is
/// `{"version":1,"keys":[...],"invites":[...]}`; writes are atomic (temp file
/// in the same directory, fsync, rename). Rollback semantics match
/// [`super::state::MemoryState`]: an update error leaves both disk and memory
/// untouched.
#[derive(Debug)]
pub struct FileState {
    path: PathBuf,
    data: Mutex<StateData>,
}

impl FileState {
    /// Loads the state file at `path`. A missing file yields an empty store
    /// (Go OpenFileState does exactly this); an existing file must decode
    /// strictly (unknown fields rejected, no trailing data, version 1, no
    /// duplicate kid or invite id, valid entries) or a corrupt error is
    /// returned.
    pub fn open(path: impl AsRef<Path>) -> Result<FileState, JackError> {
        let path = path.as_ref();
        let text = match std::fs::read(path) {
            Ok(bytes) => std::str::from_utf8(&bytes)
                .map_err(|e| corrupt(format!("state file {}: invalid utf-8: {e}", path.display())))?
                .to_owned(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(FileState {
                    path: path.to_path_buf(),
                    data: Mutex::new(StateData::empty()),
                });
            }
            Err(e) => {
                return Err(JackError::new(
                    500,
                    "internal",
                    format!("read state file {}: {e}", path.display()),
                ));
            }
        };

        let doc: StateDocument = serde_json::from_str(&text).map_err(|e| {
            JackError::new(
                0,
                CODE_STATE_CORRUPT,
                format!("state file {}: {e}", path.display()),
            )
        })?;

        // Same order as Go decodeState: version, duplicate kids, duplicate
        // invite ids, then the key and invite validation.
        if doc.version != 1 {
            return Err(corrupt(format!(
                "state file {}: unsupported version {}",
                path.display(),
                doc.version
            )));
        }
        let mut seen_keys = HashSet::with_capacity(doc.keys.len());
        for entry in &doc.keys {
            if !seen_keys.insert(entry.kid.as_str()) {
                return Err(corrupt(format!(
                    "state file {}: duplicate key {}",
                    path.display(),
                    entry.kid
                )));
            }
        }
        let mut seen_invites = HashSet::with_capacity(doc.invites.len());
        for invite in &doc.invites {
            if !seen_invites.insert(invite.invite_id.as_str()) {
                return Err(corrupt(format!(
                    "state file {}: duplicate invite {}",
                    path.display(),
                    invite.invite_id
                )));
            }
        }
        validate_keys(&doc.keys)
            .map_err(|e| corrupt(format!("state file {}: {e}", path.display())))?;
        validate_invites(&doc.invites)
            .map_err(|e| corrupt(format!("state file {}: {e}", path.display())))?;

        // StateData's fields are private, so load through the public edit/commit
        // path: an empty store that commits the decoded document in one swap.
        let mut edit = StateEdit::default();
        for entry in doc.keys {
            edit.put_key(entry);
        }
        for invite in doc.invites {
            edit.put_invite(invite);
        }
        let mut data = StateData::empty();
        data.commit(&edit);
        Ok(FileState {
            path: path.to_path_buf(),
            data: Mutex::new(data),
        })
    }

    /// Locks the store, recovering from a poisoned mutex: same poison policy
    /// as `MemoryState::lock_data` (a panic can only hit the private deep
    /// copy, never a committed invariant), see state.rs.
    fn lock_data(&self) -> MutexGuard<'_, StateData> {
        self.data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Builds a corrupt-load error: status 0, never an HTTP response.
fn corrupt(message: String) -> JackError {
    JackError::new(0, CODE_STATE_CORRUPT, message)
}

/// Enforces the load-time entry rules of spec 02 section 1: name shape and
/// uniqueness, validity intervals, kid = base64url(SHA-256(public_key)), and
/// the public-key validity rules of spec 03 section 2. `admin` is typed
/// `bool`, so decode already enforced strictness (null/string/number fail at
/// decode); no runtime check is needed.
fn validate_keys(keys: &[RegistryEntry]) -> Result<(), JackError> {
    let mut seen_names: HashSet<&str> = HashSet::with_capacity(keys.len());
    for entry in keys {
        if !valid_name(&entry.name) {
            return Err(corrupt(format!(
                "invalid name {} for key {}",
                entry.name, entry.kid
            )));
        }
        if !seen_names.insert(entry.name.as_str()) {
            return Err(corrupt(format!("duplicate name {}", entry.name)));
        }
        if entry.not_before.is_some_and(|t| t < 0) {
            return Err(corrupt(format!(
                "negative not_before for key {}",
                entry.kid
            )));
        }
        if entry.not_after.is_some_and(|t| t < 0) {
            return Err(corrupt(format!("negative not_after for key {}", entry.kid)));
        }
        if let (Some(before), Some(after)) = (entry.not_before, entry.not_after) {
            // Strict: equal timestamps are rejected too (Go: not_before >= not_after).
            if before >= after {
                return Err(corrupt(format!(
                    "not_before not before not_after for key {}",
                    entry.kid
                )));
            }
        }
        let public_key = decode_b64url_fixed(&entry.public_key, 32)
            .map_err(|_| corrupt(format!("invalid public key for key {}", entry.kid)))?;
        if key_id(&public_key) != entry.kid {
            return Err(corrupt(format!("kid mismatch for key {}", entry.kid)));
        }
        // A load failure is a corrupt file, not a protocol rejection, so the
        // key_rejected error itself is never returned; only its message.
        if let Err(e) = crate::ed25519::validate_public_key(&public_key) {
            return Err(corrupt(format!("key {}: {}", entry.kid, e.message)));
        }
    }
    Ok(())
}

/// Enforces the load-time invite rules of spec 03 sections 3.3 and 10:
/// non-empty invite_id and created_by, non-negative created_at/expires_at
/// with created_at <= expires_at, and key_ttl_seconds (when present) within
/// 1..=31536000. `admin` strictness is decode-enforced (typed bool); a null
/// key_ttl_seconds fails at decode, with a field-specific diagnostic
/// (skip_serializing_if keeps the written form absent, never null).
fn validate_invites(invites: &[InviteRecord]) -> Result<(), JackError> {
    for invite in invites {
        if invite.invite_id.is_empty() {
            return Err(corrupt("invite_id must be non-empty".to_owned()));
        }
        if invite.created_by.is_empty() {
            return Err(corrupt(format!(
                "created_by must be non-empty for invite {}",
                invite.invite_id
            )));
        }
        if invite.created_at < 0 || invite.expires_at < 0 {
            return Err(corrupt(format!(
                "negative timestamp for invite {}",
                invite.invite_id
            )));
        }
        if invite.created_at > invite.expires_at {
            return Err(corrupt(format!(
                "created_at after expires_at for invite {}",
                invite.invite_id
            )));
        }
        if let Some(ttl) = invite.key_ttl_seconds {
            if !(1..=MAX_KEY_TTL_SECONDS).contains(&ttl) {
                return Err(corrupt(format!(
                    "key_ttl_seconds out of range for invite {}",
                    invite.invite_id
                )));
            }
        }
    }
    Ok(())
}

impl StateStore for FileState {
    fn view(&self) -> StateView {
        self.lock_data().view()
    }

    fn lookup(&self, kid: &str) -> Option<RegistryEntry> {
        self.lock_data().lookup(kid)
    }

    fn update(
        &self,
        f: &mut dyn FnMut(&mut StateEdit) -> Result<(), JackError>,
    ) -> Result<(), JackError> {
        let mut data = self.lock_data();
        let mut edit = data.edit();
        // Err propagates: nothing is written and the edit copy is dropped,
        // so memory is untouched.
        f(&mut edit)?;
        // The file write must succeed BEFORE memory swaps in (Go does the
        // same), so disk and memory can never disagree about the committed
        // state.
        write_locked(&self.path, &edit)?;
        data.commit(&edit);
        Ok(())
    }
}

/// Marshals the given state deterministically and atomically replaces the
/// file. Called under the store lock. On any failure the temp file is removed
/// best-effort (Go does the same) and an internal error mentioning the target
/// path is returned; the in-memory state is left untouched.
fn write_locked(path: &Path, edit: &StateEdit) -> Result<(), JackError> {
    let doc = StateDocument {
        version: 1,
        keys: edit.keys(),
        invites: edit.invites(),
    };
    // to_string_pretty uses a two-space indent, the MarshalIndent equivalent
    // for this document shape; Go appends a trailing newline, so do we.
    let mut bytes = serde_json::to_string_pretty(&doc)
        .map_err(|e| JackError::new(500, "internal", format!("marshal state: {e}")))?
        .into_bytes();
    bytes.push(b'\n');

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut file = None;
    // Unpredictable temp names (getrandom is an existing dependency) defeat
    // symlink-on-predictable-name attacks; create_new makes collisions an
    // error we retry rather than a silent overwrite.
    for _ in 0..8 {
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix)
            .map_err(|e| JackError::new(500, "internal", format!("getrandom failed: {e}")))?;
        let tmp_path = dir.join(format!(
            ".mcp-jack-state-{}.tmp",
            suffix
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        // mode(0600) mirrors Go CreateTemp; std only exposes it on unix,
        // hence the cfg.
        #[cfg(unix)]
        let open = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path);
        #[cfg(not(unix))]
        let open = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path);
        match open {
            Ok(handle) => {
                file = Some((tmp_path, handle));
                break;
            }
            // Name collision: retry with a fresh suffix.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(JackError::new(
                    500,
                    "internal",
                    format!("create temp state file for {}: {e}", path.display()),
                ));
            }
        }
    }
    let Some((tmp_path, mut handle)) = file else {
        return Err(JackError::new(
            500,
            "internal",
            format!(
                "create temp state file for {}: exhausted retries",
                path.display()
            ),
        ));
    };

    let result = (|| -> Result<(), JackError> {
        handle
            .write_all(&bytes)
            .map_err(|e| JackError::new(500, "internal", format!("write state: {e}")))?;
        handle
            .sync_all()
            .map_err(|e| JackError::new(500, "internal", format!("sync state: {e}")))?;
        Ok(())
    })();
    drop(handle);
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    // std::fs::rename maps to MoveFileEx with MOVEFILE_REPLACE_EXISTING on
    // Windows, so rename-over-existing is cross-platform.
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(JackError::new(
            500,
            "internal",
            format!("rename state file {}: {e}", path.display()),
        ));
    }
    Ok(())
}
