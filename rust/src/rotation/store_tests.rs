use super::store_format::{self, Bundle};
use super::*;
use crate::client::{InMemorySigner, Signer};
use std::cell::Cell;
use std::fs;
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

thread_local! { static CRASH_ARMED: Cell<bool> = const { Cell::new(false) }; }

pub(super) fn crash_boundary(stage: &str) {
    if CRASH_ARMED.with(Cell::get)
        && std::env::var("JACK_STORE_CRASH_STAGE").as_deref() == Ok(stage)
    {
        std::process::exit(73);
    }
}

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "jack-rust-store-{}",
            crate::encoding::encode_b64url(&random)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("trust")
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn options() -> RotationStoreOptions {
    let signer = InMemorySigner::from_seed(&[31; 32]).unwrap();
    RotationStoreOptions {
        binding: OwnedBinding {
            endpoint: "https://example.test/mcp".into(),
            aud: "store-test".into(),
        },
        window: 30,
        checkpoint: Checkpoint {
            ordinal: 0,
            hash: "-".into(),
            kid: signer.kid().into(),
            public_key: signer.public_key(),
            published_at: 0,
        },
    }
}
fn next(previous: &TrustSnapshot, clock: &ClockTuple) -> TrustSnapshot {
    let old = InMemorySigner::from_seed(&[31; 32]).unwrap();
    let new = InMemorySigner::from_seed(&[32; 32]).unwrap();
    let record = create_record(
        Binding {
            endpoint: &previous.binding.endpoint,
            aud: &previous.binding.aud,
        },
        &previous.checkpoint,
        &old,
        &new,
        100,
    )
    .unwrap();
    let mut desired = previous.clone();
    desired.keys[0].known_cutoff = Some(record.activates_at);
    desired.keys.push(TrustKey {
        ordinal: 1,
        kid: record.new_kid.clone(),
        public_key: record.public_key,
        not_before: record.activates_at,
        known_cutoff: None,
    });
    desired.records.push(record.wire);
    desired.head = ResultCursor {
        ordinal: 1,
        hash: record.hash,
    };
    desired.clock = clock.clone();
    desired.revision += 1;
    desired
}
fn initialize(path: &Path) {
    RotationTrustStore::initialize_unused(path, options(), || Ok(100)).unwrap();
}
fn decoded_file(path: &Path) -> serde_json::Value {
    let outer: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    serde_json::from_str(outer["payload"].as_str().unwrap()).unwrap()
}

#[test]
fn explicit_creation_noncreating_open_exclusive_owner_and_reopen() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    let calls = Cell::new(0);
    assert!(RotationTrustStore::open(&path, options(), || {
        calls.set(calls.get() + 1);
        Ok(100)
    })
    .is_err());
    assert_eq!(calls.get(), 0);
    assert!(!path.exists());
    assert!(!sandbox.0.join("trust.owner").exists());
    RotationTrustStore::initialize_unused(&path, options(), || {
        let payload = decoded_file(&path);
        assert_eq!(payload["dirty"], true);
        assert!(sandbox.0.join("trust.owner").exists());
        Ok(100)
    })
    .unwrap();
    let original = fs::read(&path).unwrap();
    assert!(
        RotationTrustStore::initialize_unused(&path, options(), || panic!("must not sample"))
            .is_err()
    );
    assert_eq!(original, fs::read(&path).unwrap());
    let mut wrong = options();
    wrong.window = 29;
    assert!(RotationTrustStore::open(&path, wrong, || panic!("wrong profile")).is_err());
    let mut store = RotationTrustStore::open(&path, options(), || Ok(100)).unwrap();
    assert!(RotationTrustStore::open(&path, options(), || panic!("second owner")).is_err());
    let (snapshot, clock) = store.snapshot().unwrap();
    assert_eq!(clock.high_water, 100);
    assert_eq!(snapshot.revision, 1);
    store.close().unwrap();
    store.close().unwrap();
    assert!(!sandbox.0.join("trust.owner").exists());
    assert!(store.snapshot().is_err());
    let mut reopened = RotationTrustStore::open(&path, options(), || Ok(101)).unwrap();
    assert_eq!(reopened.snapshot().unwrap().1.high_water, 101);
    reopened.close().unwrap();
}

#[test]
fn exact_state_and_independent_guard_cas_positive_and_negative_controls() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    initialize(&path);
    let time = Rc::new(Cell::new(100));
    let callback = time.clone();
    let mut store = RotationTrustStore::open(&path, options(), move || Ok(callback.get())).unwrap();
    let (previous, captured) = store.snapshot().unwrap();
    let mut desired = next(&previous, &captured);
    time.set(101);
    let fresh = store.advance_and_check().unwrap();
    assert_eq!(
        store
            .compare_and_swap(&previous, &desired, &captured)
            .unwrap_err()
            .code,
        "rotation_state_changed"
    );
    assert_eq!(store.snapshot().unwrap().0.revision, 1);
    desired.clock = fresh.clone();
    let guard_before = decoded_file(&path)["clock"].clone();
    store.compare_and_swap(&previous, &desired, &fresh).unwrap();
    assert_eq!(decoded_file(&path)["clock"], guard_before);
    assert_eq!(store.snapshot().unwrap().0.revision, 2);
    assert_eq!(
        store
            .compare_and_swap(&previous, &desired, &fresh)
            .unwrap_err()
            .code,
        "rotation_state_changed"
    );
    time.set(102);
    assert_eq!(
        store.check_snapshot_clock(&previous).unwrap_err().code,
        "rotation_state_changed"
    );
    let (committed, guard) = store.snapshot().unwrap();
    assert_eq!(guard.high_water, 102);
    assert_eq!(committed.clock.high_water, 101);
    store.close().unwrap();
}

#[test]
fn rollback_and_invalid_time_latch_without_catchup_or_clean_close() {
    for bad in [99, MAX_TIMESTAMP + 1] {
        let sandbox = Sandbox::new();
        let path = sandbox.file();
        initialize(&path);
        let time = Rc::new(Cell::new(100));
        let callback = time.clone();
        let mut store =
            RotationTrustStore::open(&path, options(), move || Ok(callback.get())).unwrap();
        time.set(bad);
        assert_eq!(
            store.advance_and_check().unwrap_err().code,
            "rotation_clock_unsafe"
        );
        time.set(1000);
        assert_eq!(
            store.advance_and_check().unwrap_err().code,
            "rotation_clock_unsafe"
        );
        let clock: serde_json::Value =
            serde_json::from_str(decoded_file(&path)["clock"].as_str().unwrap()).unwrap();
        assert_eq!(clock["high_water"], 100);
        assert_eq!(clock["unsafe"], true);
        assert!(store.close().is_err());
        drop(store);
        assert!(RotationTrustStore::open(&path, options(), || panic!("unsafe startup")).is_err());
    }
}

#[test]
fn callback_errors_panics_and_drop_preserve_startup_gate() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    initialize(&path);
    let fail = Rc::new(Cell::new(false));
    let callback = fail.clone();
    let mut store = RotationTrustStore::open(&path, options(), move || {
        if callback.get() {
            panic!("test-only callback panic");
        }
        Ok(100)
    })
    .unwrap();
    fail.set(true);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.raw_clock())).is_err());
    assert!(store.close().is_err());
    drop(store);
    assert!(sandbox.0.join("trust.owner").exists());
    assert!(RotationTrustStore::open(&path, options(), || panic!("abandoned owner")).is_err());

    let other = Sandbox::new();
    let path = other.file();
    initialize(&path);
    let fail = Rc::new(Cell::new(false));
    let callback = fail.clone();
    let mut store = RotationTrustStore::open(&path, options(), move || {
        if callback.get() {
            Err(invalid("foreign_detail"))
        } else {
            Ok(100)
        }
    })
    .unwrap();
    fail.set(true);
    assert_eq!(
        store.advance_and_check().unwrap_err().code,
        "rotation_clock_unavailable"
    );
    assert!(store.close().is_err());
    assert!(other.0.join("trust.owner").exists());
}

#[test]
fn filesystem_profile_refuses_symlinks_hardlinks_modes_and_fifo() {
    for kind in ["symlink", "hardlink", "mode", "fifo"] {
        let sandbox = Sandbox::new();
        let path = sandbox.file();
        initialize(&path);
        match kind {
            "symlink" => {
                fs::rename(&path, sandbox.0.join("target")).unwrap();
                symlink("target", &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, sandbox.0.join("alias")).unwrap(),
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "fifo" => {
                fs::remove_file(&path).unwrap();
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &path,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                    0,
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            RotationTrustStore::open(&path, options(), || panic!("invalid filesystem object"))
                .is_err()
        );
    }
    let sandbox = Sandbox::new();
    fs::set_permissions(&sandbox.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        RotationTrustStore::initialize_unused(&sandbox.file(), options(), || panic!(
            "nonprivate parent"
        ))
        .is_err()
    );
}

#[test]
fn strict_bundle_schema_profile_checksum_and_copied_clock() {
    let options = options();
    let anchor = options.anchor().unwrap();
    let profile = crate::encoding::body_hash(options.encode(&anchor).unwrap().as_bytes());
    let bundle = Bundle::new(
        crate::encoding::encode_b64url(&[1; 16]),
        profile.clone(),
        &anchor,
        &options,
    )
    .unwrap();
    let bytes = bundle.pack().unwrap();
    assert!(store_format::unpack(bytes.clone(), &options, &profile).is_ok());
    for field in [
        "domain",
        "format_version",
        "store_id",
        "profile",
        "owner",
        "dirty",
        "fenced",
        "clock",
        "snapshot",
    ] {
        let seal: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut payload: serde_json::Value =
            serde_json::from_str(seal["payload"].as_str().unwrap()).unwrap();
        payload.as_object_mut().unwrap().remove(field);
        let payload = payload.to_string();
        let changed = serde_json::json!({"checksum":crate::encoding::body_hash(payload.as_bytes()),"payload":payload}).to_string().into_bytes();
        assert!(
            store_format::unpack(changed, &options, &profile).is_err(),
            "{field}"
        );
    }
    let mut corrupted = bytes.clone();
    let index = corrupted.len() / 2;
    corrupted[index] ^= 1;
    assert!(store_format::unpack(corrupted, &options, &profile).is_err());
    assert!(store_format::unpack(b"[]".to_vec(), &options, &profile).is_err());
    assert!(
        store_format::unpack(vec![b' '; MAX_TRUST_SNAPSHOT_BYTES + 1], &options, &profile).is_err()
    );
    let mut bundle = bundle;
    let mut ahead = anchor;
    ahead.clock.high_water = 1;
    bundle.snapshot = options.encode(&ahead).unwrap();
    assert!(store_format::unpack(bundle.pack().unwrap(), &options, &profile).is_err());
}

#[test]
fn crash_child() {
    let Ok(path) = std::env::var("JACK_STORE_CRASH_PATH") else {
        return;
    };
    let kind = std::env::var("JACK_STORE_CRASH_KIND").unwrap();
    let path = Path::new(&path);
    if kind == "initialize" {
        CRASH_ARMED.with(|armed| armed.set(true));
        RotationTrustStore::initialize_unused(path, options(), || Ok(100)).unwrap();
    } else {
        let time = Rc::new(Cell::new(100));
        let callback = time.clone();
        let mut store =
            RotationTrustStore::open(path, options(), move || Ok(callback.get())).unwrap();
        let (previous, clock) = store.snapshot().unwrap();
        CRASH_ARMED.with(|armed| armed.set(true));
        if kind == "clock" {
            time.set(101);
            store.advance_and_check().unwrap();
        } else {
            store
                .compare_and_swap(&previous, &next(&previous, &clock), &clock)
                .unwrap();
        }
    }
    panic!("crash boundary was not reached");
}

#[test]
fn real_child_pre_and_post_rename_unknown_outcomes_preserve_artifacts() {
    for kind in ["initialize", "clock", "trust"] {
        for stage in ["before-rename", "after-rename"] {
            let sandbox = Sandbox::new();
            let path = sandbox.file();
            if kind != "initialize" {
                initialize(&path);
            }
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "rotation::store_tests::crash_child",
                    "--nocapture",
                ])
                .env("JACK_STORE_CRASH_PATH", &path)
                .env("JACK_STORE_CRASH_KIND", kind)
                .env("JACK_STORE_CRASH_STAGE", stage)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(73),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(sandbox.0.join("trust.owner").exists());
            let payload = decoded_file(&path);
            let snapshot: serde_json::Value =
                serde_json::from_str(payload["snapshot"].as_str().unwrap()).unwrap();
            let clock: serde_json::Value =
                serde_json::from_str(payload["clock"].as_str().unwrap()).unwrap();
            assert_eq!(
                snapshot["trust_revision"],
                if kind == "trust" && stage == "after-rename" {
                    2
                } else {
                    1
                }
            );
            assert_eq!(
                clock["high_water"],
                if kind == "initialize" && stage == "before-rename" {
                    0
                } else if kind == "clock" && stage == "after-rename" {
                    101
                } else {
                    100
                }
            );
            let temporaries = fs::read_dir(&sandbox.0)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count();
            assert_eq!(temporaries, usize::from(stage == "before-rename"));
            assert!(
                RotationTrustStore::open(&path, options(), || panic!("uncertain startup")).is_err()
            );
            if payload["dirty"] == true {
                // Только test-owned evidence: отдельно доказываем dirty gate без marker.
                fs::rename(
                    sandbox.0.join("trust.owner"),
                    sandbox.0.join("archived-owner-evidence"),
                )
                .unwrap();
                assert!(RotationTrustStore::open(&path, options(), || panic!(
                    "dirty startup before clock"
                ))
                .is_err());
                assert_eq!(decoded_file(&path), payload);
            }
        }
    }
}

#[test]
fn private_file_inclusive_limit_and_exact_byte_conflict() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    let bytes = vec![b'x'; MAX_TRUST_SNAPSHOT_BYTES];
    let mut owner = super::private_file::FileOwner::create_unused(&path, &bytes).unwrap();
    assert_eq!(owner.read().unwrap(), bytes);
    assert_eq!(
        owner.replace(b"wrong", b"replacement").unwrap_err().code,
        "rotation_state_changed"
    );
    assert_eq!(owner.read().unwrap(), bytes);
    owner.replace(&bytes, b"replacement").unwrap();
    assert_eq!(owner.read().unwrap(), b"replacement");
    owner.close().unwrap();
    let oversized = sandbox.0.join("oversized");
    assert!(super::private_file::FileOwner::create_unused(
        &oversized,
        &vec![0; MAX_TRUST_SNAPSHOT_BYTES + 1]
    )
    .is_err());
    assert!(!oversized.exists());
    assert!(!sandbox.0.join("oversized.owner").exists());
}
