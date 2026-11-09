//! Integration tests for the file-backed state store (Go: server/statefile_test.go)
//! under the admin-only contract, plus the state-file-vectors.json runner
//! (spec tests README, 03-user-management section 10).

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::fixtures::{
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
fn fixture_entry(f: &common::fixtures::RegistryEntry) -> RegistryEntry {
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

#[test]
fn missing_file_starts_empty() {
    let dir = TempDirGuard::new("missing-file");
    let path = state_path(&dir);
    let store = open_ok(&path);
    assert!(store.view().keys.is_empty());
    assert!(store.view().invites.is_empty());
    store
        .update(&mut |e: &mut StateEdit| {
            e.put_key(state_test_key("k1", "alice"));
            e.put_invite(InviteRecord {
                invite_id: "i1".into(),
                created_by: "root".into(),
                ..Default::default()
            });
            Ok(())
        })
        .expect("update");
    let doc: serde_json::Value =
        serde_json::from_str(&read_file(&path)).expect("parse written state");
    assert_eq!(doc["version"], 1);
    assert_eq!(doc["keys"].as_array().unwrap().len(), 1);
    assert_eq!(doc["invites"].as_array().unwrap().len(), 1);
}

#[test]
fn round_trip_sorted_indented_json() {
    let dir = TempDirGuard::new("round-trip");
    let path = state_path(&dir);
    let store = open_ok(&path);
    let kz = state_test_key("zz", "zoe");
    let ka = state_test_key("aa", "ann");
    store
        .update(&mut |e: &mut StateEdit| {
            e.put_key(kz.clone());
            e.put_key(ka.clone());
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
            Ok(())
        })
        .expect("update");
    let reopened = open_ok(&path);
    assert_eq!(reopened.view(), store.view());

    let text = read_file(&path);
    assert!(text.ends_with('\n'), "trailing newline required");
    assert!(text.contains("\n  \""), "two-space indent required");
    // Keys sorted by kid on disk (not by insertion order).
    let mut kids = [ka.kid.clone(), kz.kid.clone()];
    kids.sort();
    assert!(
        text.find(&kids[0]).expect("kid a") < text.find(&kids[1]).expect("kid z"),
        "keys must be sorted by kid"
    );
    assert!(
        text.find(r#""invite_id": "i2""#).expect("i2")
            < text.find(r#""invite_id": "i9""#).expect("i9"),
        "invites sorted by id (serde pretty emits `key: value` with a space)"
    );
}

#[test]
fn registry_fixture_document_loads() {
    let dir = TempDirGuard::new("fixture-doc");
    let doc: RegistryDocument = load_registry().expect("load registry.json");
    let entries: Vec<RegistryEntry> = doc.keys.iter().map(fixture_entry).collect();
    let text = doc_with_keys(&entries);
    let path = state_path(&dir);
    write_file(&path, &text);
    let store = open_ok(&path);
    let view = store.view();
    assert_eq!(view.keys.len(), doc.keys.len());
    // Positive control with real fixture keys: the first kid round-trips.
    assert!(view.keys.iter().any(|k| k.kid == doc.keys[0].kid));
}

/// Runs EVERY registries case of load-vectors.json through the FileState
/// loader. Adaptation: a registry document `{version, aud, keys}` becomes the
/// state document `{"version":...,"keys":[...],"invites":[]}` — `aud` is
/// dropped because the on-disk state format (Go stateDocument) has no aud
/// field: the audited audience is not part of the validated key material.
/// Every other top-level field and every entry field is copied verbatim, so
/// each case's rejection property (unknown fields, bad kinds, duplicate ids,
/// ...) survives the adaptation.
#[test]
fn load_vectors_registries_through_file_state() {
    let vectors = load_load_vectors().expect("load load-vectors.json");
    assert!(
        !vectors.registries.is_empty(),
        "the fixture must contain registry cases"
    );
    for case in &vectors.registries {
        let dir = TempDirGuard::new(&format!("loadvec-{}", case.id));
        let path = state_path(&dir);
        let doc = case
            .document
            .as_object()
            .expect("registry document is an object");
        let mut adapted = serde_json::Map::new();
        for (key, value) in doc {
            if key == "aud" {
                continue; // see fn doc
            }
            adapted.insert(key.clone(), value.clone());
        }
        adapted.insert("invites".to_string(), serde_json::Value::Array(Vec::new()));
        write_file(&path, &serde_json::Value::Object(adapted).to_string());
        match case.expect.as_str() {
            "valid" => {
                let store = open_ok(&path);
                assert_eq!(
                    store.view().keys.len(),
                    doc["keys"].as_array().expect("keys array").len(),
                    "case {}: valid registry must load completely",
                    case.id
                );
            }
            "invalid" => {
                let before = fs::read(&path).expect("read bytes before rejected vector open");
                let err = FileState::open(&path)
                    .expect_err(&format!("case {} must be rejected", case.id));
                assert_eq!(err.code, CODE_STATE_CORRUPT, "case {}", case.id);
                if case.id.contains("legacy") {
                    let member = if case.id.contains("kind") {
                        "kind"
                    } else {
                        "scopes"
                    };
                    assert!(
                        err.message.contains(member),
                        "case {}: {}",
                        case.id,
                        err.message
                    );
                }
                let after = fs::read(&path).expect("read bytes after rejected vector open");
                assert_eq!(before, after, "case {} must preserve the raw file", case.id);
            }
            other => panic!("case {}: unknown expect {other}", case.id),
        }
    }
}

fn fixture_base() -> RegistryEntry {
    fixture_entry(&load_registry().expect("load registry.json").keys[0])
}

#[test]
fn reject_kid_mismatch() {
    let dir = TempDirGuard::new("kid-mismatch");
    let mut base = fixture_base();
    base.kid = state_test_key("other", "x").kid;
    let path = state_path(&dir);
    write_file(&path, &doc_with_keys(&[base]));
    expect_corrupt(&path);
}

#[test]
fn reject_public_key_wrong_length() {
    let dir = TempDirGuard::new("pk-length");
    let mut base = fixture_base();
    base.public_key = encode_b64url(&[0u8; 16]);
    let path = state_path(&dir);
    write_file(&path, &doc_with_keys(&[base]));
    expect_corrupt(&path);
}

#[test]
fn reject_invalid_name_with_space() {
    let dir = TempDirGuard::new("name-space");
    let mut base = fixture_base();
    base.name = "bad name!".into();
    let path = state_path(&dir);
    write_file(&path, &doc_with_keys(&[base]));
    expect_corrupt(&path);
}

#[test]
fn reject_name_too_long() {
    let dir = TempDirGuard::new("name-long");
    let mut base = fixture_base();
    base.name = "a".repeat(65);
    let path = state_path(&dir);
    write_file(&path, &doc_with_keys(&[base]));
    expect_corrupt(&path);
}

#[test]
fn reject_duplicate_name() {
    let dir = TempDirGuard::new("dup-name");
    let path = state_path(&dir);
    write_file(
        &path,
        &doc_with_keys(&[state_test_key("k1", "same"), state_test_key("k2", "same")]),
    );
    expect_corrupt(&path);
}

/// Legacy `kind` inside a state-file entry is REJECTED, not migrated: the
/// file must name the member in the error and stay byte-identical on disk
/// (spec 03 section 10: never migrate/strip/reset/rewrite).
#[test]
fn reject_legacy_entry_kind() {
    let dir = TempDirGuard::new("legacy-entry-kind");
    let path = state_path(&dir);
    let mut doc = doc_with_keys(&[fixture_base()]);
    // Splice a legacy member into the (admin-shaped) entry.
    doc = doc.replace(r##""admin":false,"##, r##""admin":false,"kind":"agent","##);
    assert!(doc.contains(r##""kind":"agent""##), "splice must apply");
    write_file(&path, &doc);
    let err = expect_corrupt(&path);
    assert!(
        err.message.contains("kind"),
        "message must name the offending member: {}",
        err.message
    );
}

/// Legacy `scopes` inside a state-file entry is rejected and named.
#[test]
fn reject_legacy_entry_scopes() {
    let dir = TempDirGuard::new("legacy-entry-scopes");
    let path = state_path(&dir);
    let doc = doc_with_keys(&[fixture_base()])
        .replace(r#""admin":false,"#, r#""admin":false,"scopes":["read"],"#);
    write_file(&path, &doc);
    let err = expect_corrupt(&path);
    assert!(
        err.message.contains("scopes"),
        "message must name the offending member: {}",
        err.message
    );
}

/// Legacy `kind` inside a stored invite is rejected and named.
#[test]
fn reject_legacy_invite_kind() {
    let dir = TempDirGuard::new("legacy-invite-kind");
    let path = state_path(&dir);
    let doc = doc_with_invites(
        r#"{"invite_id":"i1","admin":false,"created_by":"root","created_at":1,"expires_at":2,"kind":"human"}"#,
    );
    write_file(&path, &doc);
    let err = expect_corrupt(&path);
    assert!(
        err.message.contains("kind"),
        "message must name the offending member: {}",
        err.message
    );
}

/// `admin` must be a strict JSON boolean in state-file entries (the string
/// variant is fixture case statefile-invalid-admin-string; number and null
/// are local pins of the same rule).
#[test]
fn reject_admin_string() {
    let dir = TempDirGuard::new("admin-string");
    let path = state_path(&dir);
    write_file(
        &path,
        &doc_with_keys(&[fixture_base()]).replace(r#""admin":false"#, r#""admin":"true""#),
    );
    expect_corrupt(&path);
}

#[test]
fn reject_admin_number() {
    let dir = TempDirGuard::new("admin-number");
    let path = state_path(&dir);
    write_file(
        &path,
        &doc_with_keys(&[fixture_base()]).replace(r#""admin":false"#, r#""admin":1"#),
    );
    expect_corrupt(&path);
}

#[test]
fn reject_admin_null() {
    let dir = TempDirGuard::new("admin-null");
    let path = state_path(&dir);
    write_file(
        &path,
        &doc_with_keys(&[fixture_base()]).replace(r#""admin":false"#, r#""admin":null"#),
    );
    expect_corrupt(&path);
}

/// `key_ttl_seconds: null` on a stored invite is invalid: the member is
/// absent when the key never expires, never null (spec 03 section 10).
#[test]
fn reject_invite_ttl_null() {
    let dir = TempDirGuard::new("invite-ttl-null");
    let path = state_path(&dir);
    write_file(
        &path,
        &doc_with_invites(
            r#"{"invite_id":"i1","admin":false,"created_by":"root","created_at":1,"expires_at":2,"key_ttl_seconds":null}"#,
        ),
    );
    let err = expect_corrupt(&path);
    assert!(
        err.message.contains("key_ttl_seconds"),
        "diagnostic: {}",
        err.message
    );
}

/// Boundary vector: a TTL below the minimum (0) and above the maximum
/// (31536001) is invalid; the minimum (1) and maximum (31536000) load.
#[test]
fn reject_invite_ttl_bounds() {
    for (ttl, ok) in [(0, false), (31536001, false), (1, true), (31536000, true)] {
        let dir = TempDirGuard::new(&format!("invite-ttl-{ttl}"));
        let path = state_path(&dir);
        write_file(
            &path,
            &doc_with_invites(&format!(
                r#"{{"invite_id":"i1","admin":false,"created_by":"root","created_at":1,"expires_at":2,"key_ttl_seconds":{ttl}}}"#,
            )),
        );
        if ok {
            open_ok(&path);
        } else {
            expect_corrupt(&path);
        }
    }
}

/// created_at > expires_at is invalid; created_at == expires_at is the
/// boundary and loads.
#[test]
fn reject_invite_timestamp_order() {
    for (created, expires, ok) in [(3, 2, false), (2, 2, true), (1, 2, true)] {
        let dir = TempDirGuard::new(&format!("invite-order-{created}-{expires}"));
        let path = state_path(&dir);
        write_file(
            &path,
            &doc_with_invites(&format!(
                r#"{{"invite_id":"i1","admin":false,"created_by":"root","created_at":{created},"expires_at":{expires}}}"#,
            )),
        );
        if ok {
            open_ok(&path);
        } else {
            expect_corrupt(&path);
        }
    }
}

/// An empty created_by is invalid (names are validated on invites too).
#[test]
fn reject_invite_empty_created_by() {
    let dir = TempDirGuard::new("invite-created-by");
    let path = state_path(&dir);
    write_file(
        &path,
        &doc_with_invites(
            r#"{"invite_id":"i1","admin":false,"created_by":"","created_at":1,"expires_at":2}"#,
        ),
    );
    expect_corrupt(&path);
}

#[test]
fn required_invite_members_are_required_and_strictly_typed() {
    let dir = TempDirGuard::new("invite-required");
    let path = state_path(&dir);
    let valid = serde_json::json!({
        "invite_id": "i1",
        "admin": false,
        "created_by": "root",
        "created_at": 0,
        "expires_at": 0
    });
    write_file(&path, &doc_with_invites(&valid.to_string()));
    open_ok(&path); // Positive control: all required members present, time zero/equal.

    for member in ["invite_id", "created_by", "created_at", "expires_at"] {
        for mutation in ["missing", "null", "wrong-type"] {
            let mut invite = valid.clone();
            let fields = invite.as_object_mut().expect("invite object");
            match mutation {
                "missing" => {
                    let _ = fields.remove(member);
                }
                "null" => {
                    let _ = fields.insert(member.to_owned(), serde_json::Value::Null);
                }
                "wrong-type" => {
                    let wrong = if matches!(member, "invite_id" | "created_by") {
                        serde_json::json!(7)
                    } else {
                        serde_json::json!("0")
                    };
                    let _ = fields.insert(member.to_owned(), wrong);
                }
                _ => unreachable!(),
            }
            let case_dir = TempDirGuard::new(&format!("invite-{member}-{mutation}"));
            let case_path = state_path(&case_dir);
            write_file(&case_path, &doc_with_invites(&invite.to_string()));
            let err = expect_corrupt(&case_path);
            if mutation == "missing" {
                assert!(
                    err.message.contains(member),
                    "missing {member}: {}",
                    err.message
                );
            }
        }
    }
}

#[test]
fn invite_id_and_creator_must_be_nonempty_strings() {
    for (member, value) in [("invite_id", ""), ("created_by", "")] {
        let dir = TempDirGuard::new(&format!("invite-empty-{member}"));
        let path = state_path(&dir);
        let mut invite = serde_json::json!({
            "invite_id": "i1",
            "admin": false,
            "created_by": "root",
            "created_at": 0,
            "expires_at": 0
        });
        invite[member] = serde_json::json!(value);
        write_file(&path, &doc_with_invites(&invite.to_string()));
        expect_corrupt(&path);
    }

    for (member, invalid) in [
        ("invite_id", serde_json::Value::Null),
        ("invite_id", serde_json::json!(7)),
        ("created_by", serde_json::Value::Null),
        ("created_by", serde_json::json!(7)),
    ] {
        let dir = TempDirGuard::new(&format!("invite-invalid-{member}"));
        let path = state_path(&dir);
        let mut invite = serde_json::json!({
            "invite_id": "i1",
            "admin": false,
            "created_by": "root",
            "created_at": 0,
            "expires_at": 0
        });
        invite[member] = invalid;
        write_file(&path, &doc_with_invites(&invite.to_string()));
        expect_corrupt(&path);
    }
}

#[test]
fn invite_timestamps_reject_invalid_json_number_types() {
    for member in ["created_at", "expires_at"] {
        for (label, invalid) in [
            ("negative", serde_json::json!(-1)),
            ("fraction", serde_json::json!(1.5)),
            ("string", serde_json::json!("1")),
            ("boolean", serde_json::json!(true)),
            ("null", serde_json::Value::Null),
        ] {
            let dir = TempDirGuard::new(&format!("invite-{member}-{label}"));
            let path = state_path(&dir);
            let mut invite = serde_json::json!({
                "invite_id": "i1",
                "admin": false,
                "created_by": "root",
                "created_at": 0,
                "expires_at": 0
            });
            invite[member] = invalid;
            write_file(&path, &doc_with_invites(&invite.to_string()));
            expect_corrupt(&path);
        }
    }

    // Zero and equal timestamps are valid boundaries.
    let dir = TempDirGuard::new("invite-zero-equal");
    let path = state_path(&dir);
    write_file(
        &path,
        &doc_with_invites(
            r#"{"invite_id":"i1","admin":false,"created_by":"root","created_at":0,"expires_at":0}"#,
        ),
    );
    open_ok(&path);
}

#[test]
fn invite_ttl_rejects_non_integer_json_types() {
    for (label, ttl) in [
        ("string", serde_json::json!("1")),
        ("boolean", serde_json::json!(true)),
        ("fraction", serde_json::json!(1.5)),
    ] {
        let dir = TempDirGuard::new(&format!("invite-ttl-{label}"));
        let path = state_path(&dir);
        let mut invite = serde_json::json!({
            "invite_id": "i1",
            "admin": false,
            "created_by": "root",
            "created_at": 0,
            "expires_at": 0,
            "key_ttl_seconds": 1
        });
        invite["key_ttl_seconds"] = ttl;
        write_file(&path, &doc_with_invites(&invite.to_string()));
        let err = expect_corrupt(&path);
        assert!(
            err.message.contains("key_ttl_seconds"),
            "diagnostic: {}",
            err.message
        );
    }
}

/// Two otherwise-valid records sharing one invite_id violate the unique-id
/// rule; the error message must name the duplicate rule.
#[test]
fn reject_duplicate_invite_id() {
    let dir = TempDirGuard::new("dup-invite-id");
    let path = state_path(&dir);
    write_file(
        &path,
        &doc_with_invites(
            r#"{"invite_id":"i1","admin":false,"created_by":"root","created_at":1,"expires_at":2},
               {"invite_id":"i1","admin":false,"created_by":"root","created_at":3,"expires_at":4}"#,
        ),
    );
    let err = expect_corrupt(&path);
    assert!(
        err.message.to_lowercase().contains("duplicate"),
        "message must name the duplicate rule: {}",
        err.message
    );
}

/// Persistence check (spec 03 section 10): an invite stored WITHOUT a TTL
/// must not serialize a `key_ttl_seconds` member at all (absent, never
/// null), and the file must reload to an equal view.
#[test]
fn default_invite_persists_without_ttl_member() {
    let dir = TempDirGuard::new("default-invite");
    let path = state_path(&dir);
    let store = open_ok(&path);
    store
        .update(&mut |e: &mut StateEdit| {
            e.put_invite(InviteRecord {
                invite_id: "i1".into(),
                created_by: "root".into(),
                created_at: 1,
                expires_at: 2,
                ..Default::default()
            });
            Ok(())
        })
        .expect("update");
    let text = read_file(&path);
    assert!(
        !text.contains("key_ttl_seconds"),
        "default invite must omit key_ttl_seconds, file: {text}"
    );
    let reopened = open_ok(&path);
    assert_eq!(reopened.view(), store.view());
}

#[test]
fn omitted_invite_defaults_survive_file_round_trip() {
    let dir = TempDirGuard::new("omitted-invite-defaults");
    let path = state_path(&dir);
    write_file(
        &path,
        &doc_with_invites(
            r#"{"invite_id":"i1","created_by":"root","created_at":0,"expires_at":0}"#,
        ),
    );
    let store = open_ok(&path);
    let view = store.view();
    let invite = &view.invites[0];
    assert!(!invite.admin);
    assert_eq!(invite.key_ttl_seconds, None);

    store
        .update(&mut |_edit: &mut StateEdit| Ok(()))
        .expect("persist normalized valid state");
    let text = read_file(&path);
    let doc: serde_json::Value = serde_json::from_str(&text).expect("parse persisted state");
    let saved_invite = &doc["invites"][0];
    assert!(!saved_invite["admin"].as_bool().expect("admin boolean"));
    assert!(saved_invite.get("key_ttl_seconds").is_none());
    let reopened = open_ok(&path);
    assert_eq!(reopened.view(), store.view());
}

/// Runs EVERY state-file-vectors.json case through FileState::open with the
/// document VERBATIM (these documents are already state-file shaped). A
/// valid case must open with key/invite counts equal to the document's
/// array lengths (positive control); an invalid case must fail as
/// CODE_STATE_CORRUPT (spec tests README, state-file vectors).
#[test]
fn state_file_vectors_run() {
    let vectors = load_state_file_vectors().expect("load state-file-vectors.json");
    assert!(!vectors.cases.is_empty(), "state-file vectors are empty");
    for case in &vectors.cases {
        let dir = TempDirGuard::new(&format!("sfvec-{}", case.id));
        let path = state_path(&dir);
        write_file(
            &path,
            &serde_json::to_string(&case.document).expect("serialize document"),
        );
        match case.expect.as_str() {
            "valid" => {
                let store = open_ok(&path);
                let doc = case.document.as_object().expect("document is an object");
                assert_eq!(
                    store.view().keys.len(),
                    doc["keys"].as_array().expect("keys array").len(),
                    "case {}: key count",
                    case.id
                );
                assert_eq!(
                    store.view().invites.len(),
                    doc["invites"].as_array().expect("invites array").len(),
                    "case {}: invite count",
                    case.id
                );
            }
            "invalid" => {
                let before = fs::read(&path).expect("read bytes before rejected vector open");
                let err = FileState::open(&path)
                    .expect_err(&format!("case {} must be rejected", case.id));
                assert_eq!(err.code, CODE_STATE_CORRUPT, "case {}", case.id);
                if case.id.contains("legacy") {
                    let member = if case.id.contains("kind") {
                        "kind"
                    } else {
                        "scopes"
                    };
                    assert!(
                        err.message.contains(member),
                        "case {}: {}",
                        case.id,
                        err.message
                    );
                }
                let after = fs::read(&path).expect("read bytes after rejected vector open");
                assert_eq!(before, after, "case {} must preserve the raw file", case.id);
            }
            other => panic!("case {}: unknown expect {other}", case.id),
        }
    }
}

#[test]
fn reject_identity_public_key() {
    let dir = TempDirGuard::new("identity-pk");
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut base = fixture_base();
    // kid matches the public key; the point is the curve-point check.
    base.public_key = encode_b64url(&identity);
    base.kid = key_id(&identity);
    let path = state_path(&dir);
    write_file(&path, &doc_with_keys(&[base]));
    expect_corrupt(&path);
}

#[test]
fn reject_negative_not_before() {
    let dir = TempDirGuard::new("neg-not-before");
    let mut base = fixture_base();
    base.not_before = Some(-1);
    let path = state_path(&dir);
    write_file(&path, &doc_with_keys(&[base]));
    expect_corrupt(&path);
}

#[test]
fn reject_not_before_not_before_not_after() {
    let dir = TempDirGuard::new("not-before-order");
    let mut base = fixture_base();
    base.not_before = Some(10);
    base.not_after = Some(10);
    let path = state_path(&dir);
    write_file(&path, &doc_with_keys(&[base]));
    expect_corrupt(&path);
}

#[test]
fn corrupt_not_json() {
    let dir = TempDirGuard::new("not-json");
    let path = state_path(&dir);
    write_file(&path, "not json at all");
    expect_corrupt(&path);
}

#[test]
fn corrupt_empty_file() {
    let dir = TempDirGuard::new("empty");
    let path = state_path(&dir);
    write_file(&path, "");
    expect_corrupt(&path);
}

#[test]
fn corrupt_unknown_field_top() {
    let dir = TempDirGuard::new("unknown-top");
    let path = state_path(&dir);
    write_file(&path, r#"{"version":1,"keys":[],"invites":[],"extra":1}"#);
    expect_corrupt(&path);
}

#[test]
fn corrupt_unknown_field_in_entry() {
    let dir = TempDirGuard::new("unknown-entry");
    let path = state_path(&dir);
    // deny_unknown_fields is recursive: one extra field inside a valid key
    // object must also fail the decode.
    let entry = fixture_base();
    write_file(
        &path,
        &format!(
            r#"{{"version":1,"keys":[{{"kid":{:?},"public_key":{:?},"name":{:?},"admin":{},"not_before":null,"not_after":null,"bogus":1}}],"invites":[]}}"#,
            entry.kid, entry.public_key, entry.name, entry.admin
        ),
    );
    expect_corrupt(&path);
}

#[test]
fn corrupt_wrong_version() {
    let dir = TempDirGuard::new("wrong-version");
    let path = state_path(&dir);
    write_file(&path, r#"{"version":2,"keys":[],"invites":[]}"#);
    expect_corrupt(&path);
}

#[test]
fn corrupt_duplicate_kid() {
    // Two entries share ONE valid kid and the same valid key material,
    // differing only in name: every other rule passes, so ONLY the
    // duplicate-kid rule can reject. Removing that rule makes this test fail
    // (open would succeed), unlike a doc whose keys are invalid anyway.
    let dir = TempDirGuard::new("dup-kid");
    let first = fixture_base();
    let mut second = first.clone();
    second.name = "alice-copy".into(); // a valid, distinct name
    let path = state_path(&dir);
    write_file(&path, &doc_with_keys(&[first, second]));
    assert!(expect_corrupt(&path).message.contains("duplicate key"));
}

#[test]
fn corrupt_wrong_shape() {
    let dir = TempDirGuard::new("wrong-shape");
    let path = state_path(&dir);
    write_file(&path, "[]");
    expect_corrupt(&path);
}

#[test]
fn error_message_mentions_file_name() {
    let dir = TempDirGuard::new("msg-filename");
    let path = state_path(&dir);
    write_file(&path, "not json");
    let err = expect_corrupt(&path);
    assert!(
        err.message.contains("state.json"),
        "message: {}",
        err.message
    );
}

#[test]
fn rollback_on_error() {
    let dir = TempDirGuard::new("rollback");
    let path = state_path(&dir);
    let store = open_ok(&path);
    let key = state_test_key("k1", "alice");
    store
        .update(&mut |e: &mut StateEdit| {
            e.put_key(key.clone());
            e.put_invite(InviteRecord {
                invite_id: "i1".into(),
                created_by: "root".into(),
                ..Default::default()
            });
            Ok(())
        })
        .expect("seed update");
    let before_view = store.view();
    let before_bytes = fs::read(&path).expect("read state");
    let err = store
        .update(&mut |e: &mut StateEdit| {
            e.put_key(state_test_key("k2", "bob"));
            e.remove_invite("i1");
            Err(JackError::new(0, "test_boom", "boom"))
        })
        .expect_err("callback error must propagate");
    assert_eq!(err.code, "test_boom");
    // Neither memory nor disk may show the failed edit.
    assert_eq!(store.view(), before_view);
    let after_bytes = fs::read(&path).expect("read state after failure");
    assert_eq!(after_bytes, before_bytes, "file must be byte-identical");
}

#[test]
fn failed_update_leaves_no_trace() {
    // Make persistence fail for real: the rename target becomes a directory.
    // rename(file -> existing directory) fails on Windows (MoveFileEx
    // REPLACE_EXISTING refuses to replace a directory) and on Unix (EISDIR),
    // so write_locked fails after the temp file was created. The update must
    // return an error, leave memory untouched, and leave no temp file.
    let dir = TempDirGuard::new("no-trace");
    let path = state_path(&dir);
    let store = open_ok(&path);
    store
        .update(&mut |e: &mut StateEdit| {
            e.put_key(state_test_key("k1", "alice"));
            Ok(())
        })
        .expect("seed");
    fs::remove_file(&path).expect("remove the state file");
    fs::create_dir(&path).expect("replace it with a directory");
    let before_view = store.view();
    let err = store
        .update(&mut |e: &mut StateEdit| {
            e.put_key(state_test_key("k2", "mallory"));
            Ok(())
        })
        .expect_err("persistence must fail when the target is a directory");
    assert_eq!(err.code, "internal");
    // The edit (k2) must NOT be visible in memory: memory swaps in only
    // after the file write succeeded.
    assert_eq!(store.view(), before_view);
    let names: Vec<String> = fs::read_dir(dir.path())
        .expect("read dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        names.iter().all(|n| !n.starts_with(".mcp-jack-state-")),
        "temp leftovers: {names:?}"
    );
}

#[test]
fn successful_update_clean() {
    let dir = TempDirGuard::new("clean");
    let path = state_path(&dir);
    let store = open_ok(&path);
    store
        .update(&mut |e: &mut StateEdit| {
            e.put_key(state_test_key("k1", "alice"));
            Ok(())
        })
        .expect("update");
    let names: Vec<String> = fs::read_dir(dir.path())
        .expect("read dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(names, vec!["state.json".to_string()], "dir: {names:?}");
}

#[test]
fn concurrent_updates_all_land() {
    let dir = TempDirGuard::new("concurrent");
    let path = state_path(&dir);
    let store = Arc::new(open_ok(&path));
    std::thread::scope(|s| {
        for idx in 0..16 {
            let store = Arc::clone(&store);
            s.spawn(move || {
                store
                    .update(&mut |e: &mut StateEdit| {
                        e.put_key(state_test_key(
                            &format!("k-{idx:02}"),
                            &format!("user-{idx}"),
                        ));
                        Ok(())
                    })
                    .expect("update");
            });
        }
    });
    let reopened = open_ok(&path);
    assert_eq!(reopened.view().keys.len(), 16);
}

#[test]
fn trait_object_usable() {
    let dir = TempDirGuard::new("trait-object");
    let path = state_path(&dir);
    let store: Arc<dyn StateStore> = Arc::new(open_ok(&path));
    let key = state_test_key("k1", "alice");
    store
        .update(&mut |e: &mut StateEdit| {
            e.put_key(key.clone());
            Ok(())
        })
        .expect("update via trait object");
    assert_eq!(store.view().keys.len(), 1);
}

#[test]
fn corrupt_invalid_utf8() {
    // State files are parsed as UTF-8 JSON; raw invalid bytes are corrupt,
    // not silently replaced (design doc: UTF-8 before JSON).
    let dir = TempDirGuard::new("invalid-utf8");
    let path = state_path(&dir);
    fs::write(&path, [0xFF, 0xFE, 0x00]).expect("write raw bytes");
    expect_corrupt(&path);
}

#[test]
fn concurrent_last_writer_wins_on_disk() {
    // Same counter race as state.rs's memory test, but every increment is a
    // full persisted write; the final value must be exactly
    // threads x iterations, in memory AND after reopening from disk.
    let dir = TempDirGuard::new("last-writer");
    let path = state_path(&dir);
    let store = Arc::new(open_ok(&path));
    let key = state_test_key("shared", "shared");
    store
        .update(&mut |e: &mut StateEdit| {
            let mut seeded = key.clone();
            seeded.not_before = Some(0);
            e.put_key(seeded);
            Ok(())
        })
        .expect("seed");
    const THREADS: usize = 4;
    const ITERS: usize = 10;
    std::thread::scope(|s| {
        for _ in 0..THREADS {
            let store = Arc::clone(&store);
            let kid = key.kid.clone();
            s.spawn(move || {
                for _ in 0..ITERS {
                    store
                        .update(&mut |e: &mut StateEdit| {
                            let mut cur = e.key(&kid).expect("counter entry present");
                            cur.not_before = Some(cur.not_before.expect("seeded counter") + 1);
                            e.put_key(cur);
                            Ok(())
                        })
                        .expect("update");
                }
            });
        }
    });
    assert_eq!(
        store.view().keys[0].not_before,
        Some((THREADS * ITERS) as i64),
        "a lost update would leave the counter short"
    );
    let reopened = open_ok(&path);
    assert_eq!(
        reopened.view().keys[0].not_before,
        Some((THREADS * ITERS) as i64)
    );
}
