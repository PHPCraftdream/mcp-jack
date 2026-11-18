use super::*;

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
