//! In-memory registry/invite state store: JSON record shapes, immutable
//! views, atomic edits and the shared `StateStore` trait (Go: server/state.go).
//! See spec 02-authorization.md section 1 (registry entries) and
//! 03-user-management.md sections 3.3 and 10 (invites).

use std::sync::{Mutex, MutexGuard};

use crate::error::JackError;

/// One registered key in the server state. Field order matches the wire
/// tags (serde_json emits declaration order), pointer fields marshal as
/// `null` when absent (no `skip_serializing_if`). See spec 02 section 1.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    pub kid: String,
    pub public_key: String,
    pub name: String,
    /// Strict JSON boolean on decode: plain `bool` with `#[serde(default)]`
    /// IS the strict rule — serde rejects null, string and number for a bool
    /// field, and `default` applies only when the member is absent, so
    /// absent decodes as false (spec 02 section 1).
    #[serde(default)]
    pub admin: bool,
    #[serde(default)]
    pub not_before: Option<i64>,
    #[serde(default)]
    pub not_after: Option<i64>,
}

/// One pending invite. Field order matches the wire; see
/// spec 03 sections 3.3 and 10.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRecord {
    pub invite_id: String,
    /// Optional strict boolean, default false: same plain-`bool` reasoning as
    /// [`RegistryEntry::admin`] (spec 03 sections 3.3 and 10).
    #[serde(default)]
    pub admin: bool,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
    /// ABSENT on the wire when None, never null: a stored record with
    /// `"key_ttl_seconds": null` is invalid. The custom decoder preserves the
    /// i64-only wire type (serde's Option decoder would accept null).
    #[serde(
        default,
        deserialize_with = "deserialize_key_ttl_seconds",
        skip_serializing_if = "Option::is_none"
    )]
    pub key_ttl_seconds: Option<i64>,
}

fn deserialize_key_ttl_seconds<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <i64 as serde::Deserialize>::deserialize(deserializer)
        .map(Some)
        .map_err(|err| serde::de::Error::custom(format!("key_ttl_seconds: {err}")))
}

/// Immutable deep-copy snapshot of the store. Keys are sorted by `kid`,
/// invites by invite id; mutating a returned view never affects the store.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StateView {
    pub keys: Vec<RegistryEntry>,
    pub invites: Vec<InviteRecord>,
}

/// Mutable deep copy of the current state handed to a `StateStore::update`
/// callback. Getters return clones; edits accumulate here only and become
/// visible when the store swaps them in.
#[derive(Debug, Default)]
pub struct StateEdit {
    keys: Vec<RegistryEntry>,
    invites: Vec<InviteRecord>,
}

// Deep-copy obligation: every getter below returns clones of private data, so
// ownership gives for free what Go needed explicit cloneKeys/cloneInvites for.

impl StateEdit {
    /// Returns a copy of the entry with the given kid, if present.
    pub fn key(&self, kid: &str) -> Option<RegistryEntry> {
        self.keys.iter().find(|e| e.kid == kid).cloned()
    }

    /// Returns a copy of the entry with the given name, if present.
    pub fn key_by_name(&self, name: &str) -> Option<RegistryEntry> {
        self.keys.iter().find(|e| e.name == name).cloned()
    }

    /// Returns copies of all entries sorted by kid. Kids are unique by store
    /// contract (`put_key` replaces on the same kid), so stable sort order
    /// among equal kids is moot.
    pub fn keys(&self) -> Vec<RegistryEntry> {
        let mut out = self.keys.clone();
        out.sort_by(|a, b| a.kid.cmp(&b.kid));
        out
    }

    /// Returns a copy of the invite with the given id, if present.
    pub fn invite(&self, invite_id: &str) -> Option<InviteRecord> {
        self.invites
            .iter()
            .find(|i| i.invite_id == invite_id)
            .cloned()
    }

    /// Returns copies of all invites sorted by invite id (ids unique by
    /// store contract, see [`StateEdit::keys`]).
    pub fn invites(&self) -> Vec<InviteRecord> {
        let mut out = self.invites.clone();
        out.sort_by(|a, b| a.invite_id.cmp(&b.invite_id));
        out
    }

    /// Replaces any entry with the same kid, else appends. The entry is
    /// moved in, so the store never aliases caller data.
    pub fn put_key(&mut self, entry: RegistryEntry) {
        match self.keys.iter_mut().find(|e| e.kid == entry.kid) {
            Some(slot) => *slot = entry,
            None => self.keys.push(entry),
        }
    }

    /// Deletes the entry with the given kid and reports whether anything was
    /// removed (kids are unique, so at most one match).
    pub fn remove_key(&mut self, kid: &str) -> bool {
        match self.keys.iter().position(|e| e.kid == kid) {
            Some(i) => {
                self.keys.remove(i);
                true
            }
            None => false,
        }
    }

    /// Replaces any invite with the same invite id, else appends.
    pub fn put_invite(&mut self, invite: InviteRecord) {
        match self
            .invites
            .iter_mut()
            .find(|i| i.invite_id == invite.invite_id)
        {
            Some(slot) => *slot = invite,
            None => self.invites.push(invite),
        }
    }

    /// Deletes the invite with the given id and reports whether anything was
    /// removed.
    pub fn remove_invite(&mut self, invite_id: &str) -> bool {
        match self.invites.iter().position(|i| i.invite_id == invite_id) {
            Some(i) => {
                self.invites.remove(i);
                true
            }
            None => false,
        }
    }
}

/// The registry/invite state interface shared by the in-memory and
/// file-backed implementations (docs/design/rust-ts-server-sdks.md).
///
/// Design notes: the update callback is `&mut dyn FnMut` rather than a
/// generic `F: FnMut` to keep the trait dyn-compatible, so the verifier can
/// hold an `Arc<dyn StateStore>`; methods take `&self` with an internal
/// Mutex so stores stay cheaply clonable/shareable; the callback error type
/// is [`JackError`] so a failed update surfaces a spec-coded rejection.
pub trait StateStore: Send + Sync {
    /// Returns a deep-copy snapshot of the current state.
    fn view(&self) -> StateView;
    /// Returns a copy of the entry with the given kid. Request verification
    /// calls it once per request, so it must not copy the whole registry the
    /// way `view` does.
    fn lookup(&self, kid: &str) -> Option<RegistryEntry>;
    /// Runs the callback on a deep copy of the state; commits only if it
    /// returns `Ok`, otherwise nothing is applied (atomic with rollback).
    fn update(
        &self,
        f: &mut dyn FnMut(&mut StateEdit) -> Result<(), JackError>,
    ) -> Result<(), JackError>;
}

/// Shared private state data, mirroring the lookup/clone/sort helpers Go
/// shared between MemoryState and FileState.
#[derive(Debug)]
pub(crate) struct StateData {
    keys: Vec<RegistryEntry>,
    invites: Vec<InviteRecord>,
}

impl StateData {
    /// An empty store.
    pub(crate) fn empty() -> Self {
        Self {
            keys: Vec::new(),
            invites: Vec::new(),
        }
    }

    /// Deep-copy snapshot, keys sorted by kid, invites by invite id.
    pub(crate) fn view(&self) -> StateView {
        let edit = self.edit();
        StateView {
            keys: edit.keys(),
            invites: edit.invites(),
        }
    }

    /// Single-entry deep copy; must NOT clone the whole registry because
    /// lookup runs once per verification request.
    pub(crate) fn lookup(&self, kid: &str) -> Option<RegistryEntry> {
        self.keys.iter().find(|e| e.kid == kid).cloned()
    }

    /// Deep copy handed to an update callback.
    pub(crate) fn edit(&self) -> StateEdit {
        StateEdit {
            keys: self.keys.clone(),
            invites: self.invites.clone(),
        }
    }

    /// Swaps committed data for the (already validated) edit's deep copy.
    /// The ONLY place committed data is replaced.
    pub(crate) fn commit(&mut self, edit: &StateEdit) {
        self.keys = edit.keys.clone();
        self.invites = edit.invites.clone();
    }
}

/// In-memory [`StateStore`]. `update` takes a deep copy, runs the callback
/// while holding the store mutex (so concurrent updates are serialized), and
/// swaps it in only on `Ok`; on `Err` the copy is dropped and the error is
/// returned unchanged (rollback).
pub struct MemoryState {
    data: Mutex<StateData>,
}

impl MemoryState {
    /// Returns an empty in-memory state store.
    pub fn new() -> Self {
        Self {
            data: Mutex::new(StateData::empty()),
        }
    }

    /// Locks the store, recovering from a poisoned mutex. POISON POLICY: a
    /// panic can only originate inside the caller's closure editing the
    /// private deep copy, or in a `Clone` (allocation failure); committed
    /// `StateData` stays intact, so dropping the poison guard cannot expose
    /// a broken invariant, and a server must not panic because a handler
    /// panicked.
    fn lock_data(&self) -> MutexGuard<'_, StateData> {
        self.data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for MemoryState {
    fn default() -> Self {
        Self::new()
    }
}

impl StateStore for MemoryState {
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
        f(&mut edit)?;
        // Err above: nothing applied, the edit copy is just dropped.
        data.commit(&edit);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{encode_b64url, key_id};
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Test error helper: status 0 = never-an-HTTP sentinel.
    fn boom() -> JackError {
        JackError::new(0, "test_boom", "boom")
    }

    /// Builds a registry entry with a real Ed25519 public key derived from
    /// `id` (Go: stateTestKey), so seeded state would also pass strict file
    /// validation later.
    fn state_test_key(id: &str, name: &str) -> RegistryEntry {
        let seed = Sha256::digest(id.as_bytes());
        let signing = SigningKey::from_bytes(&seed.into());
        let public = signing.verifying_key().to_bytes();
        RegistryEntry {
            kid: key_id(&public),
            public_key: encode_b64url(&public),
            name: name.to_string(),
            admin: false,
            not_before: None,
            not_after: None,
        }
    }

    #[test]
    fn entry_admin_serializes_always_present() {
        let entry = RegistryEntry {
            kid: "k1".into(),
            public_key: "pk".into(),
            name: "alice".into(),
            admin: false,
            not_before: Some(1767225500),
            not_after: Some(1767229200),
        };
        assert_eq!(
            serde_json::to_string(&entry).unwrap(),
            r#"{"kid":"k1","public_key":"pk","name":"alice","admin":false,"not_before":1767225500,"not_after":1767229200}"#
        );
    }

    #[test]
    fn invite_key_ttl_absent_is_omitted_never_null() {
        let inv = InviteRecord {
            invite_id: "i1".into(),
            admin: false,
            created_by: "root".into(),
            created_at: 1767225500,
            expires_at: 1767228600,
            key_ttl_seconds: None,
        };
        let json = serde_json::to_string(&inv).unwrap();
        assert_eq!(
            json,
            r#"{"invite_id":"i1","admin":false,"created_by":"root","created_at":1767225500,"expires_at":1767228600}"#
        );
        // Absent on the wire (not null), and the record round-trips.
        assert!(!json.contains("key_ttl_seconds"), "json: {json}");
        let back: InviteRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, inv);
    }

    #[test]
    fn invite_ttl_absent_is_omitted_null_rejected_and_required_members_enforced() {
        let valid = r#"{"invite_id":"i1","created_by":"root","created_at":0,"expires_at":0}"#;
        let invite: InviteRecord = serde_json::from_str(valid).unwrap();
        assert!(!invite.admin, "omitted admin defaults to false");
        assert_eq!(invite.key_ttl_seconds, None);
        let serialized = serde_json::to_string(&invite).unwrap();
        assert!(
            !serialized.contains("key_ttl_seconds"),
            "json: {serialized}"
        );
        assert!(
            serialized.contains(r#""admin":false"#),
            "admin defaults to false: {serialized}"
        );
        let reopened: InviteRecord = serde_json::from_str(&serialized).unwrap();
        assert_eq!(reopened, invite);

        let null_ttl = valid.trim_end_matches('}').to_owned() + r#","key_ttl_seconds":null}"#;
        let err = serde_json::from_str::<InviteRecord>(&null_ttl).unwrap_err();
        assert!(err.to_string().contains("key_ttl_seconds"), "err: {err}");

        for member in ["invite_id", "created_by", "created_at", "expires_at"] {
            let missing = match member {
                "invite_id" => r#"{"created_by":"root","created_at":0,"expires_at":0}"#,
                "created_by" => r#"{"invite_id":"i1","created_at":0,"expires_at":0}"#,
                "created_at" => r#"{"invite_id":"i1","created_by":"root","expires_at":0}"#,
                "expires_at" => r#"{"invite_id":"i1","created_by":"root","created_at":0}"#,
                _ => unreachable!(),
            };
            let err = serde_json::from_str::<InviteRecord>(missing).unwrap_err();
            assert!(err.to_string().contains(member), "member {member}: {err}");
        }
    }

    #[test]
    fn invite_key_ttl_present_serializes_the_number() {
        let inv = InviteRecord {
            invite_id: "i1".into(),
            admin: true,
            created_by: "root".into(),
            created_at: 1767225500,
            expires_at: 1767228600,
            key_ttl_seconds: Some(3600),
        };
        assert_eq!(
            serde_json::to_string(&inv).unwrap(),
            r#"{"invite_id":"i1","admin":true,"created_by":"root","created_at":1767225500,"expires_at":1767228600,"key_ttl_seconds":3600}"#
        );
    }

    #[test]
    fn admin_bool_decode_table() {
        // Absent -> false.
        let entry: RegistryEntry =
            serde_json::from_str(r#"{"kid":"k1","public_key":"pk","name":"alice"}"#).unwrap();
        assert!(!entry.admin);
        // true and false decode.
        let entry: RegistryEntry =
            serde_json::from_str(r#"{"kid":"k1","public_key":"pk","name":"alice","admin":true}"#)
                .unwrap();
        assert!(entry.admin);
        // Null, string and number are all rejected (strict boolean).
        for admin in ["null", "\"true\"", "1"] {
            assert!(
                serde_json::from_str::<RegistryEntry>(&format!(
                    r#"{{"kid":"k1","public_key":"pk","name":"alice","admin":{admin}}}"#
                ))
                .is_err(),
                "admin {admin} must be rejected"
            );
        }
    }

    #[test]
    fn legacy_members_rejected_by_name() {
        // An entry carrying legacy `kind` or `scopes` is rejected and the
        // error NAMES the offending member (deny_unknown_fields diagnostic);
        // the file is never migrated or stripped (spec 02 section 1).
        let err = serde_json::from_str::<RegistryEntry>(
            r#"{"kid":"k1","public_key":"pk","name":"alice","scopes":["read"]}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("scopes"), "err: {err}");
        let err = serde_json::from_str::<RegistryEntry>(
            r#"{"kid":"k1","public_key":"pk","name":"alice","kind":"human"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("kind"), "err: {err}");
    }

    #[test]
    fn concurrent_last_writer_wins_on_shared_entry() {
        // Threads race read-modify-write updates of ONE entry's not_before
        // counter; the store serializes them under its mutex, so the value
        // must be exactly threads x iterations: any lost update leaves the
        // counter short (toggle parity alone cannot prove this).
        let store = MemoryState::new();
        let key = state_test_key("shared", "shared");
        store
            .update(&mut |e| {
                let mut seeded = key.clone();
                seeded.not_before = Some(0);
                e.put_key(seeded);
                Ok(())
            })
            .unwrap();
        const THREADS: usize = 8;
        const ITERS: usize = 25;
        std::thread::scope(|s| {
            let store = &store;
            let key = &key;
            for _ in 0..THREADS {
                s.spawn(move || {
                    for _ in 0..ITERS {
                        store
                            .update(&mut |e| {
                                let mut cur = e.key(&key.kid).expect("counter entry present");
                                cur.not_before = Some(cur.not_before.expect("seeded counter") + 1);
                                e.put_key(cur);
                                Ok(())
                            })
                            .unwrap();
                    }
                });
            }
        });
        assert_eq!(
            store.view().keys[0].not_before,
            Some((THREADS * ITERS) as i64),
            "a lost update would leave the counter short"
        );
    }

    #[test]
    fn edit_put_and_get_by_kid_and_name() {
        let store = MemoryState::new();
        let k = state_test_key("k1", "alice");
        store
            .update(&mut |e| {
                e.put_key(k.clone());
                Ok(())
            })
            .unwrap();
        store
            .update(&mut |e| {
                let got = e.key(&k.kid);
                assert_eq!(got.map(|g| g.name).as_deref(), Some("alice"));
                assert_eq!(e.key_by_name("alice").map(|g| g.kid), Some(k.kid.clone()));
                assert!(e.key("missing").is_none());
                assert!(e.key_by_name("nobody").is_none());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn edit_put_key_replaces_on_same_kid() {
        let store = MemoryState::new();
        let mut replaced = state_test_key("k1", "alice");
        let original = replaced.clone();
        replaced.name = "alice2".into();
        replaced.admin = true;
        store
            .update(&mut |e| {
                // FnMut closures cannot consume captures; the store clones internally anyway.
                e.put_key(original.clone());
                e.put_key(replaced.clone());
                Ok(())
            })
            .unwrap();
        let view = store.view();
        assert_eq!(view.keys.len(), 1);
        assert_eq!(view.keys[0].name, "alice2");
        assert!(view.keys[0].admin);
    }

    #[test]
    fn edit_remove_returns_false_when_absent() {
        let store = MemoryState::new();
        store
            .update(&mut |e| {
                assert!(!e.remove_key("ghost"));
                assert!(!e.remove_invite("ghost-invite"));
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn edit_getters_sorted() {
        let store = MemoryState::new();
        let kz = state_test_key("zz", "zoe");
        let ka = state_test_key("aa", "ann");
        let km = state_test_key("mm", "mel");
        store
            .update(&mut |e| {
                e.put_key(kz.clone());
                e.put_key(ka.clone());
                e.put_key(km.clone());
                e.put_invite(InviteRecord {
                    invite_id: "i9".into(),
                    created_by: "root".into(),
                    ..Default::default()
                });
                e.put_invite(InviteRecord {
                    invite_id: "i2".into(),
                    created_by: "root".into(),
                    ..Default::default()
                });
                e.put_invite(InviteRecord {
                    invite_id: "i5".into(),
                    created_by: "root".into(),
                    ..Default::default()
                });
                Ok(())
            })
            .unwrap();
        store
            .update(&mut |e| {
                let mut want = [ka.kid.clone(), km.kid.clone(), kz.kid.clone()];
                want.sort();
                let keys = e.keys();
                let kids: Vec<&str> = keys.iter().map(|k| k.kid.as_str()).collect();
                assert_eq!(kids, want.to_vec());
                let invites = e.invites();
                let ids: Vec<&str> = invites.iter().map(|i| i.invite_id.as_str()).collect();
                assert_eq!(ids, ["i2", "i5", "i9"]);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn edit_getters_are_deep_copies() {
        let store = MemoryState::new();
        let k = state_test_key("k1", "alice");
        store
            .update(&mut |e| {
                e.put_key(k.clone());
                Ok(())
            })
            .unwrap();
        store
            .update(&mut |e| {
                let mut got = e.key(&k.kid).unwrap();
                got.name = "MUTATED".into();
                got.admin = !got.admin;
                Ok(())
            })
            .unwrap();
        let view = store.view();
        assert_eq!(view.keys[0].name, "alice");
        assert!(!view.keys[0].admin);
    }

    #[test]
    fn enroll_flow() {
        let store = MemoryState::new();
        store
            .update(&mut |e| {
                e.put_invite(InviteRecord {
                    invite_id: "i1".into(),
                    admin: true,
                    created_by: "root".into(),
                    ..Default::default()
                });
                e.put_key(state_test_key("admin", "root"));
                Ok(())
            })
            .unwrap();
        let enrolled = state_test_key("k-new", "bob");
        store
            .update(&mut |e| {
                let inv = e
                    .invite("i1")
                    .ok_or_else(|| JackError::new(403, "invalid_invite", ""))?;
                e.remove_invite("i1");
                let mut entry = enrolled.clone();
                entry.admin = inv.admin;
                e.put_key(entry);
                Ok(())
            })
            .unwrap();
        let view = store.view();
        assert_eq!(view.keys.len(), 2);
        assert!(view.keys.iter().any(|k| k.kid == enrolled.kid));
        assert!(view.invites.is_empty());
    }

    #[test]
    fn rollback_on_error() {
        let store = MemoryState::new();
        store
            .update(&mut |e| {
                e.put_key(state_test_key("k1", "alice"));
                e.put_invite(InviteRecord {
                    invite_id: "i1".into(),
                    created_by: "root".into(),
                    ..Default::default()
                });
                Ok(())
            })
            .unwrap();
        let before = store.view();
        let got = store.update(&mut |e| {
            e.put_key(state_test_key("k2", "mallory"));
            e.remove_invite("i1");
            Err(boom())
        });
        assert_eq!(got, Err(boom()));
        assert_eq!(store.view(), before);
    }

    #[test]
    fn view_is_copy() {
        let store = MemoryState::new();
        store
            .update(&mut |e| {
                e.put_key(state_test_key("k1", "alice"));
                Ok(())
            })
            .unwrap();
        let mut view = store.view();
        view.keys[0].name = "MUTATED".into();
        view.keys[0].admin = !view.keys[0].admin;
        view.keys.push(state_test_key("k2", "mallory"));
        view.invites.push(InviteRecord {
            invite_id: "i1".into(),
            ..Default::default()
        });
        let after = store.view();
        assert_eq!(after.keys.len(), 1);
        assert_eq!(after.keys[0].name, "alice");
        assert!(!after.keys[0].admin);
        assert!(after.invites.is_empty());
    }

    #[test]
    fn put_key_input_isolation() {
        // Option<i64> is Copy, so Go's shared-*int64 aliasing hazards are
        // unrepresentable; the obligation left is Vec (heap) isolation.
        let store = MemoryState::new();
        let mut entry = state_test_key("k1", "alice");
        entry.not_before = Some(5);
        store
            .update(&mut |e| {
                e.put_key(entry.clone());
                Ok(())
            })
            .unwrap();
        // Mutate the caller's local copy after the commit.
        entry.name = "MUTATED".into();
        entry.admin = true;
        entry.not_before = Some(0);
        let got = store.view().keys.remove(0);
        assert_eq!(got.name, "alice");
        assert_eq!(got.not_before, Some(5));
    }

    #[test]
    fn failed_update_discards_edit_and_caller_mutation() {
        let store = MemoryState::new();
        let mut entry = state_test_key("k1", "alice");
        entry.not_before = Some(7);
        let got = store.update(&mut |e| {
            e.put_key(entry.clone());
            Err(boom())
        });
        assert_eq!(got, Err(boom()));
        assert!(store.view().keys.is_empty());
        // Caller mutates their local afterwards; store stays (empty).
        entry.name = "MUTATED".into();
        entry.admin = true;
        entry.not_before = Some(0);
        assert!(store.view().keys.is_empty());
    }

    #[test]
    fn retained_edit_cannot_corrupt() {
        // In Rust a &mut StateEdit cannot be retained past update: the
        // borrow checker forbids it (the closure's exclusive borrow of the
        // edit ends when update returns). Adapted: later updates see only
        // committed data, and a failed put cannot leak.
        let store = MemoryState::new();
        let k1 = state_test_key("k1", "alice");
        store
            .update(&mut |e| {
                e.put_key(k1.clone());
                Ok(())
            })
            .unwrap();
        store
            .update(&mut |e| {
                assert!(e.key(&k1.kid).is_some());
                Ok(())
            })
            .unwrap();
        let k2 = state_test_key("k2", "mallory");
        let got = store.update(&mut |e| {
            // FnMut capture cannot be consumed.
            e.put_key(k2.clone());
            Err(boom())
        });
        assert_eq!(got, Err(boom()));
        let view = store.view();
        assert_eq!(view.keys.len(), 1);
        assert_eq!(view.keys[0].name, "alice");
    }

    #[test]
    fn lookup_returns_copy() {
        // Holding the store as Arc<dyn StateStore> proves at compile time
        // that the trait is object-safe AND Send+Sync.
        let store: Arc<dyn StateStore> = Arc::new(MemoryState::new());
        let k = state_test_key("k1", "alice");
        store
            .update(&mut |e| {
                e.put_key(k.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store.lookup(&k.kid).map(|e| e.name).as_deref(),
            Some("alice")
        );
        assert!(store.lookup("missing").is_none());
        // Lookup returns an owned clone, so two lookups are equal values.
        assert_eq!(store.lookup(&k.kid), store.lookup(&k.kid));
    }

    #[test]
    fn concurrency_successful_and_failing_updates_interleave() {
        let store = MemoryState::new();
        const WRITERS: usize = 32;
        let failures = AtomicUsize::new(0);
        std::thread::scope(|s| {
            let store = &store;
            let failures = &failures;
            for idx in 0..WRITERS {
                s.spawn(move || {
                    let res = store.update(&mut |e| {
                        e.put_key(state_test_key(&format!("k-{idx}"), &format!("user-{idx}")));
                        Ok(())
                    });
                    if res.is_err() {
                        failures.fetch_add(1, Ordering::SeqCst);
                    }
                });
                s.spawn(move || {
                    if store.update(&mut |_| Err(boom())).is_err() {
                        failures.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(failures.load(Ordering::SeqCst), WRITERS);
        assert_eq!(store.view().keys.len(), WRITERS);
    }

    #[test]
    fn concurrency_serialized_toggles_keep_parity() {
        let store = MemoryState::new();
        const TOGGLERS: usize = 16;
        let shared = state_test_key("shared", "shared");
        std::thread::scope(|s| {
            for _ in 0..TOGGLERS {
                let store = &store;
                let shared = &shared;
                s.spawn(move || {
                    store
                        .update(&mut |e| {
                            if e.key(&shared.kid).is_some() {
                                e.remove_key(&shared.kid);
                            } else {
                                e.put_key(shared.clone());
                            }
                            Ok(())
                        })
                        .unwrap();
                });
            }
        });
        // 16 sequential toggles from absent end absent; a lost update breaks
        // the parity.
        assert!(store.view().keys.is_empty());
    }
}
