//! Integration tests for the candidate native tool `jack.server.key`
//! (`mcp_jack::server::server_key::ServerKeyTool`), driven DIRECTLY through
//! `NativeTools::call` — no HTTP stack, no tower. The rotation store and the
//! rotation provider are Linux-gated, so the whole file is too.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use mcp_jack::client::{InMemorySigner, Signer};
use mcp_jack::encoding::{encode_b64url, key_id};
use mcp_jack::error::JackError;
use mcp_jack::rotation::{
    Checkpoint, OwnedBinding, RotationError, RotationServerKey, RotationServerProvider,
    RotationServerStore, RotationServerStoreOptions,
};
use mcp_jack::server::server_key::ServerKeyTool;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{
    is_native_tool, NativeCall, NativeTools, TOOL_ENROLL, TOOL_SERVER_KEY,
};

/// Server audience signed into the store binding; the tool refuses any other.
const AUD: &str = "provider-test";

/// Temp directory removed on Drop, so cleanup survives panicking asserts.
struct TempDirGuard(PathBuf);

static UNIQUE: AtomicUsize = AtomicUsize::new(0);

impl TempDirGuard {
    fn new(tag: &str) -> Self {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "mcp-jack-serverkey-{tag}-{}-{}",
                std::process::id(),
                UNIQUE.fetch_add(1, Ordering::SeqCst)
            ));
        fs::create_dir_all(&dir).expect("create temp dir");
        // The rotation store requires a PRIVATE parent (mode 0700, owned by
        // this uid); a default-mode directory is refused before any I/O.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .expect("restrict temp dir to 0700");
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

/// Store, shared clock handle and ring keys of one test world.
struct Fixture<C: FnMut() -> Result<u64, RotationError> + Send + 'static> {
    store: Arc<Mutex<RotationServerStore<C>>>,
    now: Arc<AtomicU64>,
    keys: Vec<InMemorySigner>,
}

/// Store options: the checkpoint is the first ring key (seed 31) at ordinal 0
/// with the "-" sentinel hash, bound to the test audience.
fn store_options(keys: &[InMemorySigner]) -> RotationServerStoreOptions {
    RotationServerStoreOptions {
        binding: OwnedBinding {
            endpoint: "https://public.invalid/mcp".into(),
            aud: AUD.into(),
        },
        window: 30,
        checkpoint: Checkpoint {
            ordinal: 0,
            hash: "-".into(),
            kid: keys[0].kid().into(),
            public_key: keys[0].public_key(),
            published_at: 0,
        },
        anchor_reference: "anchor".into(),
    }
}

/// Go setup: seeds 31/32/33, one store initialized unused at t=1000 and
/// reopened with a shared monotone clock; the handle is shared with the
/// provider so both sides see the same committed ring.
fn fixture(dir: &Path) -> Fixture<impl FnMut() -> Result<u64, RotationError> + Send + 'static> {
    let keys: Vec<InMemorySigner> = [31u8, 32, 33]
        .iter()
        .map(|seed| InMemorySigner::from_seed(&[*seed; 32]).expect("test signer"))
        .collect();
    let path = dir.join("server-ring");
    RotationServerStore::initialize_unused(&path, store_options(&keys), || Ok(1000))
        .expect("initialize unused store");
    let now = Arc::new(AtomicU64::new(1000));
    let clock_now = Arc::clone(&now);
    let store = RotationServerStore::open(&path, store_options(&keys), move || {
        Ok(clock_now.load(Ordering::SeqCst))
    })
    .expect("open store");
    Fixture {
        store: Arc::new(Mutex::new(store)),
        now,
        keys,
    }
}

/// Preconfigured signer handles: anchor/current, next and tail.
fn inventory(keys: &[InMemorySigner]) -> Vec<RotationServerKey> {
    ["anchor", "next", "tail"]
        .iter()
        .zip(keys.iter())
        .map(|(reference, key)| RotationServerKey {
            reference: (*reference).to_owned(),
            signer: Arc::new(key.clone()),
        })
        .collect()
}

/// Provider over the fixture store with the given inventory.
fn provider_for<C: FnMut() -> Result<u64, RotationError> + Send + 'static>(
    f: &Fixture<C>,
    keys: Vec<RotationServerKey>,
) -> Arc<RotationServerProvider<C>> {
    Arc::new(
        RotationServerProvider::new(Arc::clone(&f.store), keys)
            .expect("rotation inventory is ready"),
    )
}

/// Locks the store, recovering from a poisoned mutex (crate-wide policy).
fn lock<C: FnMut() -> Result<u64, RotationError> + Send + 'static>(
    f: &Fixture<C>,
) -> MutexGuard<'_, RotationServerStore<C>> {
    f.store.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A fourth key (seed 35) acting as the authenticated caller. The signer is
/// not used further at this layer (no signature verification happens below
/// the verifier); it is kept on the stack like a real caller would be.
fn caller_entry() -> (InMemorySigner, RegistryEntry) {
    let signer = InMemorySigner::from_seed(&[35u8; 32]).expect("caller signer");
    let entry = RegistryEntry {
        kid: key_id(&signer.public_key()),
        public_key: encode_b64url(&signer.public_key()),
        name: "caller".into(),
        admin: false,
        not_before: None,
        not_after: None,
    };
    (signer, entry)
}

/// NativeCall builder: every call looks authenticated (kid "kid-x", ts/now
/// 1000) and carries its own empty in-memory state store.
fn call_req<'a>(
    tool: &'a str,
    arguments: Option<&'a str>,
    caller: Option<&'a RegistryEntry>,
    aud: &'a str,
) -> NativeCall<'a> {
    NativeCall {
        tool,
        arguments: arguments.map(|text| {
            serde_json::value::RawValue::from_string(text.to_owned())
                .expect("arguments are valid JSON")
        }),
        caller,
        kid: "kid-x",
        ts: 1000,
        now: 1000,
        aud,
        state: Arc::new(MemoryState::new()) as Arc<dyn StateStore>,
        target: String::new(),
    }
}

/// Every refusal of this tool carries the same collapsed message.
fn assert_refusal(err: JackError, status: u16, code: &str) {
    assert_eq!(err.http_status, status, "http status");
    assert_eq!(err.code, code, "code");
    assert_eq!(
        err.message, "server key request unavailable",
        "refusal message never leaks storage or signer details"
    );
}

#[test]
fn valid_cursor_returns_one_exact_page() {
    let dir = TempDirGuard::new("exact-page");
    let f = fixture(dir.path());
    let provider = provider_for(&f, inventory(&f.keys));
    let tool = ServerKeyTool::new(Arc::clone(&f.store), Arc::clone(&provider));
    let (_caller, caller) = caller_entry();
    let first = provider
        .announce("next", f.keys[1].kid())
        .expect("announcing the pending next key must succeed");

    let mut req = call_req(
        TOOL_SERVER_KEY,
        Some(r#"{"after_ordinal":0,"after_hash":"-"}"#),
        Some(&caller),
        AUD,
    );
    let page = NativeTools::call(&tool, &mut req).expect("a valid cursor must serve one page");
    let structured = &page.structured;
    // The pending next key is not yet eligible: the anchor stays current.
    assert_eq!(
        structured["current"]["kid"].as_str().expect("current.kid"),
        f.keys[0].kid(),
        "the anchor key is still the selected signer"
    );
    assert_eq!(
        structured["current"]["public_key"].as_str().expect("current.public_key"),
        encode_b64url(&f.keys[0].public_key()),
    );
    let records = structured["records"].as_array().expect("records is an array");
    assert_eq!(records.len(), 1, "exactly one record was announced");
    assert_eq!(records[0].as_str().expect("record wire"), first.record.wire);
    assert_eq!(
        structured["head"]["ordinal"].as_u64().expect("head.ordinal"),
        1,
        "the announced record is the new head"
    );
    assert_eq!(
        structured["head"]["hash"].as_str().expect("head.hash"),
        first.record.hash
    );
    assert!(structured["complete"].as_bool().expect("complete"));
    assert_eq!(
        f.now.load(Ordering::SeqCst),
        1000,
        "the page is served at the caller's fixed clock"
    );
}

#[test]
fn head_cursor_yields_empty_complete_page() {
    let dir = TempDirGuard::new("head-cursor");
    let f = fixture(dir.path());
    let provider = provider_for(&f, inventory(&f.keys));
    let tool = ServerKeyTool::new(Arc::clone(&f.store), Arc::clone(&provider));
    let (_caller, caller) = caller_entry();
    let first = provider
        .announce("next", f.keys[1].kid())
        .expect("announcing the pending next key must succeed");

    // A cursor anchored on the announced head has nothing left to serve.
    let arguments = format!(r#"{{"after_ordinal":1,"after_hash":"{}"}}"#, first.record.hash);
    let mut req = call_req(TOOL_SERVER_KEY, Some(&arguments), Some(&caller), AUD);
    let page = NativeTools::call(&tool, &mut req).expect("the head cursor must serve a page");
    let records = page.structured["records"].as_array().expect("records is an array");
    assert!(records.is_empty(), "the head cursor yields no records");
    assert!(
        page.structured["complete"].as_bool().expect("complete"),
        "an empty page at the head is complete"
    );
}

#[test]
fn argument_matrix_is_invalid_params() {
    let dir = TempDirGuard::new("arg-matrix");
    let f = fixture(dir.path());
    let provider = provider_for(&f, inventory(&f.keys));
    let tool = ServerKeyTool::new(Arc::clone(&f.store), Arc::clone(&provider));
    let (_caller, caller) = caller_entry();

    // Null payload, empty object, unknown member, duplicated members (the
    // derived struct rejects duplicates; the map-only wrapper rejects arrays
    // and scalars): all one refusal class, judged on the raw JSON text.
    let bad = [
        "null",
        "{}",
        r#"{"after_ordinal":0,"after_hash":"-","extra":true}"#,
        r#"{"after_ordinal":7,"after_ordinal":0,"after_hash":"-"}"#,
        r#"{"after_ordinal":0,"after_hash":"-","after_hash":"-"}"#,
    ];
    for text in bad {
        let mut req = call_req(TOOL_SERVER_KEY, Some(text), Some(&caller), AUD);
        let err = NativeTools::call(&tool, &mut req)
            .expect_err("undecodable arguments must refuse before any store access");
        assert_refusal(err, 400, "invalid_params");
    }

    // An absent `params.arguments` is invalid_params like any undecodable
    // payload.
    let mut req = call_req(TOOL_SERVER_KEY, None, Some(&caller), AUD);
    let err = NativeTools::call(&tool, &mut req)
        .expect_err("absent arguments must be invalid_params");
    assert_refusal(err, 400, "invalid_params");
}

#[test]
fn unknown_cursor_is_checkpoint_unavailable() {
    let dir = TempDirGuard::new("unknown-cursor");
    let f = fixture(dir.path());
    let provider = provider_for(&f, inventory(&f.keys));
    let tool = ServerKeyTool::new(Arc::clone(&f.store), Arc::clone(&provider));
    let (_caller, caller) = caller_entry();
    provider
        .announce("next", f.keys[1].kid())
        .expect("announcing the pending next key must succeed");
    let unknown_hash = "A".repeat(43); // canonical length, decodes, anchors nothing

    // Decodable but not anchored by its hash: 409, not a fault state.
    let arguments = format!(r#"{{"after_ordinal":1,"after_hash":"{unknown_hash}"}}"#);
    let mut req = call_req(TOOL_SERVER_KEY, Some(&arguments), Some(&caller), AUD);
    let err = NativeTools::call(&tool, &mut req)
        .expect_err("a cursor whose hash anchors nothing must refuse");
    assert_refusal(err, 409, "rotation_checkpoint_unavailable");

    // Decodable but outside the committed ring: 409 as well.
    let arguments = format!(r#"{{"after_ordinal":5,"after_hash":"{unknown_hash}"}}"#);
    let mut req = call_req(TOOL_SERVER_KEY, Some(&arguments), Some(&caller), AUD);
    let err = NativeTools::call(&tool, &mut req)
        .expect_err("a cursor beyond the head must refuse");
    assert_refusal(err, 409, "rotation_checkpoint_unavailable");

    // NOTE (deviation from the task text): `"after_hash":"-"` is only legal at
    // ordinal 0 by `decode_server_key_arguments`, so this cursor is decoded as
    // invalid_params (400) BEFORE the cursor can be validated against the
    // ring; it never reaches the 409 path.
    let mut req = call_req(
        TOOL_SERVER_KEY,
        Some(r#"{"after_ordinal":5,"after_hash":"-"}"#),
        Some(&caller),
        AUD,
    );
    let err = NativeTools::call(&tool, &mut req)
        .expect_err("the sentinel hash is reserved for ordinal 0");
    assert_refusal(err, 400, "invalid_params");
}

#[test]
fn wrong_route_or_caller_denied() {
    let dir = TempDirGuard::new("route-caller");
    let f = fixture(dir.path());
    let provider = provider_for(&f, inventory(&f.keys));
    let tool = ServerKeyTool::new(Arc::clone(&f.store), Arc::clone(&provider));
    let (_caller, caller) = caller_entry();

    // The tool serves ONLY the explicit candidate route.
    let mut req = call_req(
        TOOL_ENROLL,
        Some(r#"{"after_ordinal":0,"after_hash":"-"}"#),
        Some(&caller),
        AUD,
    );
    let err = NativeTools::call(&tool, &mut req)
        .expect_err("another tool name must be denied before anything else");
    assert_refusal(err, 403, "operation_denied");

    // An unauthenticated call is denied too, even on the right route.
    let mut req = call_req(
        TOOL_SERVER_KEY,
        Some(r#"{"after_ordinal":0,"after_hash":"-"}"#),
        None,
        AUD,
    );
    let err = NativeTools::call(&tool, &mut req)
        .expect_err("a call without a caller must be denied");
    assert_refusal(err, 403, "operation_denied");

    // The candidate route stays OUT of the closed current-v1 allowlist.
    assert!(
        !is_native_tool(TOOL_SERVER_KEY),
        "jack.server.key must not become a current-v1 native tool"
    );
}

#[test]
fn audience_checked_before_cursor() {
    let dir = TempDirGuard::new("audience");
    let f = fixture(dir.path());
    let provider = provider_for(&f, inventory(&f.keys));
    let tool = ServerKeyTool::new(Arc::clone(&f.store), Arc::clone(&provider));
    let (_caller, caller) = caller_entry();

    // Raw-argument decoding precedes the audience check: a NON-decodable
    // cursor is invalid_params even with a wrong audience.
    let mut req = call_req(
        TOOL_SERVER_KEY,
        Some(r#"{"after_ordinal":9,"after_hash":"x"}"#),
        Some(&caller),
        "other-aud",
    );
    let err = NativeTools::call(&tool, &mut req)
        .expect_err("undecodable arguments are judged before the audience");
    assert_refusal(err, 400, "invalid_params");

    // A cursor that decodes but cannot be validated hits the audience refusal
    // first: with the right audience this would be 409, so 503 proves the
    // audience is checked before the cursor.
    let unknown_hash = "A".repeat(43);
    let arguments = format!(r#"{{"after_ordinal":9,"after_hash":"{unknown_hash}"}}"#);
    let mut req = call_req(TOOL_SERVER_KEY, Some(&arguments), Some(&caller), "other-aud");
    let err = NativeTools::call(&tool, &mut req)
        .expect_err("a wrong audience must refuse before cursor validation");
    assert_refusal(err, 503, "rotation_state_unavailable");

    // Same refusal for a perfectly valid cursor: only the audience is wrong.
    let mut req = call_req(
        TOOL_SERVER_KEY,
        Some(r#"{"after_ordinal":0,"after_hash":"-"}"#),
        Some(&caller),
        "other-aud",
    );
    let err = NativeTools::call(&tool, &mut req)
        .expect_err("a valid cursor with a wrong audience must still refuse");
    assert_refusal(err, 503, "rotation_state_unavailable");
}

#[test]
fn closed_store_refuses_before_cursor() {
    let dir = TempDirGuard::new("closed-store");
    let f = fixture(dir.path());
    let provider = provider_for(&f, inventory(&f.keys));
    let tool = ServerKeyTool::new(Arc::clone(&f.store), Arc::clone(&provider));
    let (_caller, caller) = caller_entry();

    {
        let mut store = lock(&f);
        store.close().expect("clean close with no outstanding serving leases");
    }
    // The serving lease is taken before the cursor is validated, so even a
    // valid cursor collapses into the fault-state refusal.
    let mut req = call_req(
        TOOL_SERVER_KEY,
        Some(r#"{"after_ordinal":0,"after_hash":"-"}"#),
        Some(&caller),
        AUD,
    );
    let err = NativeTools::call(&tool, &mut req)
        .expect_err("a closed store must refuse before cursor validation");
    assert_refusal(err, 503, "rotation_state_unavailable");
}

#[test]
fn page_limit_and_explicit_next_cursor() {
    let dir = TempDirGuard::new("page-limit");
    let f = fixture(dir.path());
    // 18 ring keys; the anchor keeps the store reference, every later key gets "r{i}".
    let keys: Vec<InMemorySigner> = (31u8..=48)
        .map(|seed| InMemorySigner::from_seed(&[seed; 32]).expect("distinct test signer"))
        .collect();
    let ring: Vec<RotationServerKey> = (0..keys.len())
        .map(|i| RotationServerKey {
            reference: if i == 0 { "anchor".to_owned() } else { format!("r{i}") },
            signer: Arc::new(keys[i].clone()),
        })
        .collect();
    let provider = provider_for(&f, ring);
    let tool = ServerKeyTool::new(Arc::clone(&f.store), Arc::clone(&provider));
    let (_caller, caller) = caller_entry();

    let mut publications = Vec::new();
    for (i, key) in keys.iter().enumerate().skip(1) {
        publications.push(
            provider.announce(&format!("r{i}"), key.kid()).expect("sequential announcement"),
        );
    }
    assert_eq!(publications.len(), 17, "records 1..=17 are committed");

    // First page: capped at MAX_PAGE_RECORDS (16), not complete, head ahead.
    let mut req = call_req(
        TOOL_SERVER_KEY,
        Some(r#"{"after_ordinal":0,"after_hash":"-"}"#),
        Some(&caller),
        AUD,
    );
    let page = NativeTools::call(&tool, &mut req).expect("the first page must serve");
    let records = page.structured["records"].as_array().expect("records is an array");
    assert_eq!(records.len(), 16, "one page never exceeds MAX_PAGE_RECORDS");
    assert!(
        !page.structured["complete"].as_bool().expect("complete"),
        "17 committed records leave the first page incomplete"
    );
    assert_eq!(
        page.structured["head"]["ordinal"].as_u64().expect("head.ordinal"),
        17
    );
    assert_eq!(
        page.structured["head"]["hash"].as_str().expect("head.hash"),
        publications[16].record.hash
    );

    // The explicit next cursor continues the ring exactly after record 16.
    let arguments = format!(
        r#"{{"after_ordinal":16,"after_hash":"{}"}}"#,
        publications[15].record.hash
    );
    let mut req = call_req(TOOL_SERVER_KEY, Some(&arguments), Some(&caller), AUD);
    let tail_page = NativeTools::call(&tool, &mut req).expect("the next cursor must serve");
    let records = tail_page.structured["records"].as_array().expect("records is an array");
    assert_eq!(records.len(), 1, "exactly the 17th record remains");
    assert_eq!(
        records[0].as_str().expect("record wire"),
        publications[16].record.wire
    );
    assert!(tail_page.structured["complete"].as_bool().expect("complete"));
}
