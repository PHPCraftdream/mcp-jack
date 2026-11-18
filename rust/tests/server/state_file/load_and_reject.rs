use super::*;

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
