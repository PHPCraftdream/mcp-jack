use super::store_tests::{options, Sandbox};
use super::*;
use crate::client::{ClientError, InMemorySigner, Signer};
use crate::ed25519::verify;
use crate::server::response_keys::{ResponseKeyRequest, ResponseKeys, ResponseSigner};
use crate::signing::response_signing_string;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

type Hook = Arc<dyn Fn() + Send + Sync>;

/// Signer с test hook: hook вызывается перед фактической подписью (Go signingHook).
struct HookSigner {
    inner: InMemorySigner,
    on_sign: Option<Hook>,
}

impl Signer for HookSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ClientError> {
        if let Some(on_sign) = &self.on_sign {
            on_sign();
        }
        self.inner.sign(message)
    }
    fn public_key(&self) -> [u8; 32] {
        self.inner.public_key()
    }
    fn kid(&self) -> &str {
        self.inner.kid()
    }
}

/// Next proof всегда невалиден: create_record отказывает до old authorization (Go faultyProof).
/// Паники callback в Rust сознательно не превращаются в Err — здесь проверяется только invalid proof.
struct InvalidProofSigner {
    inner: InMemorySigner,
}

impl Signer for InvalidProofSigner {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, ClientError> {
        Ok(vec![0; 64])
    }
    fn public_key(&self) -> [u8; 32] {
        self.inner.public_key()
    }
    fn kid(&self) -> &str {
        self.inner.kid()
    }
}

struct Fixture<C: FnMut() -> Result<u64, RotationError> + Send + 'static> {
    store: Arc<Mutex<RotationServerStore<C>>>,
    now: Arc<AtomicU64>,
    samples: Arc<AtomicU64>,
    keys: Vec<InMemorySigner>,
}

fn server_options() -> RotationServerStoreOptions {
    let base = options();
    RotationServerStoreOptions {
        binding: base.binding,
        window: base.window,
        checkpoint: base.checkpoint,
        anchor_reference: "anchor".into(),
    }
}

/// Go setup: seeds 31/32/33, init при 1000, store с shared clock; каждый sample считается,
/// чтобы тесты требовали ровно один sample на публикацию.
fn setup(
    sandbox: &Sandbox,
) -> Fixture<impl FnMut() -> Result<u64, RotationError> + Send + 'static> {
    let keys: Vec<InMemorySigner> = [31u8, 32, 33]
        .iter()
        .map(|seed| InMemorySigner::from_seed(&[*seed; 32]).unwrap())
        .collect();
    let path = sandbox.file();
    RotationServerStore::initialize_unused(&path, server_options(), || Ok(1000)).unwrap();
    let now = Arc::new(AtomicU64::new(1000));
    let samples = Arc::new(AtomicU64::new(0));
    let clock_now = Arc::clone(&now);
    let clock_samples = Arc::clone(&samples);
    let store = RotationServerStore::open(&path, server_options(), move || {
        clock_samples.fetch_add(1, Ordering::SeqCst);
        Ok(clock_now.load(Ordering::SeqCst))
    })
    .unwrap();
    Fixture {
        store: Arc::new(Mutex::new(store)),
        now,
        samples,
        keys,
    }
}

fn lock<C: FnMut() -> Result<u64, RotationError> + Send + 'static>(
    fixture: &Fixture<C>,
) -> MutexGuard<'_, RotationServerStore<C>> {
    fixture
        .store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn hook(counter: &Arc<AtomicU64>) -> Hook {
    let counter = Arc::clone(counter);
    Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    })
}

fn entry(
    keys: &[InMemorySigner],
    reference: &str,
    index: usize,
    on_sign: Option<Hook>,
) -> RotationServerKey {
    RotationServerKey {
        reference: reference.to_owned(),
        signer: Arc::new(HookSigner {
            inner: keys[index].clone(),
            on_sign,
        }),
    }
}

fn inventory(keys: &[InMemorySigner], hooks: [Option<Hook>; 3]) -> Vec<RotationServerKey> {
    let [anchor, next, tail] = hooks;
    vec![
        entry(keys, "anchor", 0, anchor),
        entry(keys, "next", 1, next),
        entry(keys, "tail", 2, tail),
    ]
}

fn new_provider<C: FnMut() -> Result<u64, RotationError> + Send + 'static>(
    fixture: &Fixture<C>,
    hooks: [Option<Hook>; 3],
) -> RotationServerProvider<C> {
    RotationServerProvider::new(Arc::clone(&fixture.store), inventory(&fixture.keys, hooks))
        .unwrap()
}

fn sign_counts(signs: &[Arc<AtomicU64>]) -> [u64; 3] {
    [
        signs[0].load(Ordering::SeqCst),
        signs[1].load(Ordering::SeqCst),
        signs[2].load(Ordering::SeqCst),
    ]
}

/// Не-key authority selector: page нет, как Go ResponseKeyRequest{}.
fn selector_request() -> ResponseKeyRequest<'static> {
    ResponseKeyRequest {
        status: 404,
        tool: "not-a-key-authority",
        request_signature: "",
        body: b"untrusted selector",
    }
}

/// Go expectIdentity: авторизация выбирает ожидаемый pinned identity по свежему sample,
/// подписывает точный response string и проходит final gate.
fn expect_identity<C: FnMut() -> Result<u64, RotationError> + Send + 'static>(
    fixture: &Fixture<C>,
    provider: &RotationServerProvider<C>,
    index: usize,
    timestamp: u64,
) {
    let authorization = provider.authorize_response(&selector_request()).unwrap();
    assert_eq!(authorization.timestamp, timestamp);
    assert_eq!(
        authorization.signer.public_key(),
        fixture.keys[index].public_key()
    );
    let message = response_signing_string(
        200,
        "request-signature",
        fixture.keys[index].kid(),
        i64::try_from(timestamp).unwrap(),
        b"exact body",
    );
    let signature = authorization.signer.sign(message.as_bytes()).unwrap();
    assert!(verify(
        &fixture.keys[index].public_key(),
        message.as_bytes(),
        &signature
    ));
    (authorization.final_gate)().unwrap();
    // Повторный Final структурно невозможен: Box<dyn FnOnce> потреблён первым вызовом.
    (authorization.release)();
}

#[test]
fn overlapping_pending_tail_and_equal_activation_ordinal() {
    let sandbox = Sandbox::new();
    let f = setup(&sandbox);
    let provider = new_provider(&f, [None, None, None]);
    let first = provider.announce("next", f.keys[1].kid()).unwrap();
    let second = provider.announce("tail", f.keys[2].kid()).unwrap();
    assert_eq!(first.revision, 2);
    assert_eq!(second.revision, 3);
    assert_eq!(
        first.record.activates_at, second.record.activates_at,
        "fixture must overlap in time"
    );
    assert_eq!(second.record.old_kid, first.record.new_kid);
    // Caller mutation inventory после new не меняет pinned identity provider.
    let mut caller = inventory(&f.keys, [None, None, None]);
    caller[0].reference = "mutated caller inventory".into();
    expect_identity(&f, &provider, 0, 1000);
    f.now.store(first.record.activates_at - 1, Ordering::SeqCst);
    expect_identity(&f, &provider, 0, first.record.activates_at - 1);
    // Равная активация eligible; cutoff anchor в той же точке retired строго.
    f.now.store(first.record.activates_at, Ordering::SeqCst);
    expect_identity(&f, &provider, 2, first.record.activates_at);
}

#[test]
fn missing_pending_or_current_signer_never_falls_back() {
    let sandbox = Sandbox::new();
    let f = setup(&sandbox);
    let provider = new_provider(&f, [None, None, None]);
    let first = provider.announce("next", f.keys[1].kid()).unwrap();
    // До активации pending handle обязателен.
    assert!(
        RotationServerProvider::new(Arc::clone(&f.store), vec![entry(&f.keys, "anchor", 0, None)])
            .is_err()
    );
    f.now.store(first.record.activates_at, Ordering::SeqCst);
    // После активации отсутствие текущего signer не откатывается на retired anchor.
    assert!(
        RotationServerProvider::new(Arc::clone(&f.store), vec![entry(&f.keys, "anchor", 0, None)])
            .is_err()
    );
    // Retired anchor handle необязателен.
    let provider =
        RotationServerProvider::new(Arc::clone(&f.store), vec![entry(&f.keys, "next", 1, None)])
            .unwrap();
    expect_identity(&f, &provider, 1, first.record.activates_at);
}

#[test]
fn final_gate_cutoff_freshness_rollback_publication_and_release() {
    for scenario in ["cutoff", "freshness", "rollback", "publication", "released"] {
        let sandbox = Sandbox::new();
        let f = setup(&sandbox);
        let provider = new_provider(&f, [None, None, None]);
        let first = provider.announce("next", f.keys[1].kid()).unwrap();
        if scenario == "cutoff" {
            f.now.store(first.record.activates_at - 1, Ordering::SeqCst);
        }
        let authorization = provider.authorize_response(&selector_request()).unwrap();
        match scenario {
            "cutoff" => f.now.store(first.record.activates_at, Ordering::SeqCst),
            "freshness" => f.now.store(1031, Ordering::SeqCst),
            "rollback" => f.now.store(999, Ordering::SeqCst),
            "publication" => {
                provider.announce("tail", f.keys[2].kid()).unwrap();
            }
            _ => (authorization.release)(),
        }
        let error = (authorization.final_gate)().unwrap_err();
        assert_eq!(error.code, "rotation_state_unavailable", "{scenario}");
    }
}

#[test]
fn freshness_equality_and_release_idempotence() {
    let sandbox = Sandbox::new();
    let f = setup(&sandbox);
    let provider = new_provider(&f, [None, None, None]);
    let authorization = provider.authorize_response(&selector_request()).unwrap();
    f.now.store(1030, Ordering::SeqCst);
    (authorization.final_gate)().expect("inclusive window equality must pass");
    (authorization.release)();
    // Повторный Release структурно невозможен: Box<dyn FnOnce> потреблён первым вызовом;
    // lease падает и при drop без вызова, поэтому leaked lease не создаётся.
    {
        let mut store = lock(&f);
        store.close().expect("lease must be released before clean close");
    }
    assert!(provider.authorize_response(&selector_request()).is_err());
}

#[test]
fn announce_single_fixed_sample_and_refusals() {
    let sandbox = Sandbox::new();
    let f = setup(&sandbox);
    let signs: Vec<Arc<AtomicU64>> = (0..3).map(|_| Arc::new(AtomicU64::new(0))).collect();
    let hooks = [
        Some(hook(&signs[0])),
        Some(hook(&signs[1])),
        Some(hook(&signs[2])),
    ];
    let provider = new_provider(&f, hooks);
    f.samples.store(0, Ordering::SeqCst);
    let first = provider.announce("next", f.keys[1].kid()).unwrap();
    assert_eq!(first.record.published_at, 1000);
    assert_eq!(first.revision, 2);
    assert_eq!(f.samples.load(Ordering::SeqCst), 1, "P is one fixed sample");
    let second = provider.announce("tail", f.keys[2].kid()).unwrap();
    assert_eq!(second.record.published_at, 1000);
    assert_eq!(second.revision, 3);
    assert_eq!(second.record.old_kid, first.record.new_kid);
    assert_eq!(f.samples.load(Ordering::SeqCst), 2);
    assert_eq!(sign_counts(&signs), [1, 2, 1]);
    // Retained kid отказывает до clock sample и до любого callback.
    assert!(provider.announce("next", &first.record.new_kid).is_err());
    assert_eq!(f.samples.load(Ordering::SeqCst), 2);
    assert_eq!(sign_counts(&signs), [1, 2, 1]);
    // Unknown inventory entry отказывает до store.
    assert!(provider.announce("unknown", &first.record.new_kid).is_err());
    assert_eq!(f.samples.load(Ordering::SeqCst), 2);
    assert_eq!(sign_counts(&signs), [1, 2, 1]);
    let mut store = lock(&f);
    let (snapshot, _) = store.snapshot().unwrap();
    assert_eq!(snapshot.public.revision, 3);
    assert_eq!(
        snapshot.public.records,
        [first.record.wire, second.record.wire]
    );
    store.close().unwrap();
}

#[test]
fn announce_delayed_proof_does_not_resample_or_move_p() {
    let sandbox = Sandbox::new();
    let f = setup(&sandbox);
    let delayed = Arc::clone(&f.now);
    let hooks = [
        None,
        Some(Arc::new(move || delayed.store(1100, Ordering::SeqCst)) as Hook),
        None,
    ];
    let provider = new_provider(&f, hooks);
    f.samples.store(0, Ordering::SeqCst);
    let publication = provider.announce("next", f.keys[1].kid()).unwrap();
    assert_eq!(publication.record.published_at, 1000);
    assert_eq!(publication.record.activates_at, 1000 + GRACE_SECONDS);
    assert_eq!(
        f.samples.load(Ordering::SeqCst),
        1,
        "delayed proof must not resample"
    );
}

#[test]
fn announce_concurrent_clock_conflict_does_not_retry_or_publish() {
    let sandbox = Sandbox::new();
    let f = setup(&sandbox);
    let proofs = Arc::new(AtomicU64::new(0));
    let authorizations = Arc::new(AtomicU64::new(0));
    let hook_store = Arc::clone(&f.store);
    let conflict_now = Arc::clone(&f.now);
    let proof_count = Arc::clone(&proofs);
    let hooks = [
        Some(hook(&authorizations)),
        Some(Arc::new(move || {
            proof_count.fetch_add(1, Ordering::SeqCst);
            conflict_now.store(1001, Ordering::SeqCst);
            // Возможен только потому, что announce не держит store lock во время callbacks.
            let mut store =
                hook_store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            store.advance_and_check().unwrap();
        }) as Hook),
        None,
    ];
    let provider = new_provider(&f, hooks);
    let error = provider.announce("next", f.keys[1].kid()).unwrap_err();
    assert_eq!(error.code, "rotation_state_changed");
    assert_eq!(proofs.load(Ordering::SeqCst), 1);
    assert_eq!(authorizations.load(Ordering::SeqCst), 1, "no retry");
    let mut store = lock(&f);
    let (snapshot, _) = store.snapshot().unwrap();
    assert_eq!(snapshot.public.revision, 1);
    assert_eq!(snapshot.public.records.len(), 0, "conflict must not publish");
}

#[test]
fn announce_invalid_proof_never_invokes_old_authorization() {
    let sandbox = Sandbox::new();
    let f = setup(&sandbox);
    let old_signs = Arc::new(AtomicU64::new(0));
    let mut mixed = inventory(&f.keys, [Some(hook(&old_signs)), None, None]);
    mixed[1] = RotationServerKey {
        reference: "next".into(),
        signer: Arc::new(InvalidProofSigner {
            inner: f.keys[1].clone(),
        }),
    };
    let provider = RotationServerProvider::new(Arc::clone(&f.store), mixed).unwrap();
    let error = provider.announce("next", f.keys[1].kid()).unwrap_err();
    assert_eq!(error.code, "rotation_state_unavailable");
    assert_eq!(old_signs.load(Ordering::SeqCst), 0, "old signer stays idle");
    let mut store = lock(&f);
    let (snapshot, _) = store.snapshot().unwrap();
    assert_eq!(snapshot.public.revision, 1);
    assert_eq!(snapshot.public.records.len(), 0);
    store.close().expect("failed proof must release the lease");
}

#[test]
fn constructor_inventory_validation() {
    let sandbox = Sandbox::new();
    let f = setup(&sandbox);
    assert!(RotationServerProvider::new(Arc::clone(&f.store), Vec::new()).is_err());
    // 1154 записи: length check срабатывает до identity work; клоны одного signer дёшевы.
    let shared = Arc::new(f.keys[0].clone());
    let oversized: Vec<RotationServerKey> = (0..=MAX_RETAINED_KEYS)
        .map(|index| RotationServerKey {
            reference: format!("key-{index}"),
            signer: Arc::clone(&shared),
        })
        .collect();
    assert_eq!(oversized.len(), MAX_RETAINED_KEYS + 1);
    assert!(RotationServerProvider::new(Arc::clone(&f.store), oversized).is_err());
    for reference in [String::new(), "x".repeat(MAX_SIGNER_REFERENCE_BYTES + 1)] {
        assert!(RotationServerProvider::new(
            Arc::clone(&f.store),
            vec![RotationServerKey {
                reference,
                signer: Arc::new(f.keys[0].clone()),
            }]
        )
        .is_err());
    }
    let duplicate = vec![
        RotationServerKey {
            reference: "anchor".into(),
            signer: Arc::new(f.keys[0].clone()),
        },
        RotationServerKey {
            reference: "anchor".into(),
            signer: Arc::new(f.keys[0].clone()),
        },
    ];
    assert!(RotationServerProvider::new(Arc::clone(&f.store), duplicate).is_err());
}
