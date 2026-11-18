//! Integration tests for the file-backed state store (Go: server/statefile_test.go)
//! under the admin-only contract, plus the state-file-vectors.json runner
//! (spec tests README, 03-user-management section 10).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::common::fixtures::{
    load_load_vectors, load_registry, load_state_file_vectors, RegistryDocument,
};
use ed25519_dalek::SigningKey;
use mcp_jack::encoding::{encode_b64url, key_id};
use mcp_jack::error::JackError;
use mcp_jack::server::state::{InviteRecord, RegistryEntry, StateEdit, StateStore};
use mcp_jack::server::state_file::{FileState, CODE_STATE_CORRUPT};
use sha2::{Digest, Sha256};

/// Temp directory removed on Drop, so cleanup survives panicking asserts.
struct TempDirGuard(PathBuf);

static UNIQUE: AtomicUsize = AtomicUsize::new(0);

impl TempDirGuard {
    fn new(tag: &str) -> Self {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "mcp-jack-statefile-{tag}-{}-{}",
                std::process::id(),
                UNIQUE.fetch_add(1, Ordering::SeqCst)
            ));
        fs::create_dir_all(&dir).expect("create temp dir");
        TempDirGuard(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Replica of state.rs's cfg(test) helper: a registry entry whose public key
/// is a real, valid Ed25519 point derived from `id` (Go: stateTestKey).
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

/// Maps a fixture registry entry onto the store type.
fn fixture_entry(f: &crate::common::fixtures::RegistryEntry) -> RegistryEntry {
    RegistryEntry {
        kid: f.kid.clone(),
        public_key: f.public_key.clone(),
        name: f.name.clone(),
        admin: f.admin,
        not_before: f.not_before,
        not_after: f.not_after,
    }
}

fn write_file(path: &Path, content: &str) {
    fs::write(path, content).expect("write file");
}

fn read_file(path: &Path) -> String {
    fs::read_to_string(path).expect("read file")
}

/// Go fileTestDoc: a version-1 state document with the given keys.
fn doc_with_keys(entries: &[RegistryEntry]) -> String {
    let keys = entries
        .iter()
        .map(|e| serde_json::to_string(e).expect("marshal entry"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"version\":1,\"keys\":[{keys}],\"invites\":[]}}")
}

fn expect_corrupt(path: &Path) -> JackError {
    let before = fs::read(path).expect("read bytes before failed open");
    let err = FileState::open(path).expect_err("open must fail as corrupt");
    assert_eq!(err.code, CODE_STATE_CORRUPT, "error: {err}");
    assert!(
        err.message
            .contains(&path.file_name().unwrap().to_string_lossy().to_string()),
        "message must mention the file: {err}"
    );
    let after = fs::read(path).expect("read bytes after failed open");
    assert_eq!(before, after, "failed open must leave raw bytes unchanged");
    err
}

fn state_path(dir: &TempDirGuard) -> PathBuf {
    dir.path().join("state.json")
}

fn open_ok(path: &Path) -> FileState {
    FileState::open(path).expect("open state file")
}

/// A state document with the fixture's first registry key and the given
/// raw invite-record JSON (already comma-separated if plural).
fn doc_with_invites(invites_json: &str) -> String {
    let entry = fixture_base();
    format!(
        "{{\"version\":1,\"keys\":[{{\"kid\":{:?},\"public_key\":{:?},\"name\":{:?},\"admin\":{},\"not_before\":null,\"not_after\":null}}],\"invites\":[{}]}}",
        entry.kid, entry.public_key, entry.name, entry.admin, invites_json
    )
}

fn fixture_base() -> RegistryEntry {
    fixture_entry(&load_registry().expect("load registry.json").keys[0])
}

mod load_and_reject;
mod vectors_and_updates;
