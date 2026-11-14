//! HTTP-layer integration tests for the rotating response-signing profile and
//! its final gate (Go: server/rotation/native_linux_test.go and
//! server/rotation/http_linux_test.go, ported against
//! `JackLayer::rotating`). Every request enters the pipeline through tower,
//! the verifier clock is pinned at 1000, and the durable rotation store owns
//! the separate shared `AtomicU64` clock the provider samples. The suite pins
//! where each candidate `jack.server.key` call stops (403/400/409/503/200),
//! that signed pages carry exactly one committed snapshot record, that
//! forwarded application answers are signed while consumed replays are not,
//! and that a late final gate discards a computed signature instead of
//! emitting it (Go: writeAuthorized refuse path).
#![cfg(all(target_os = "linux", feature = "http"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use http_body_util::Full;
use tower::{Layer as _, ServiceExt};

use mcp_jack::auth_header::parse_response_auth;
use mcp_jack::client::auth::sign_request;
use mcp_jack::client::signer::{InMemorySigner, Signer};
use mcp_jack::client::ClientError;
use mcp_jack::ed25519::verify;
use mcp_jack::encoding::{decode_b64url_fixed, encode_b64url, key_id};
use mcp_jack::error::JackError;
use mcp_jack::rotation::{
    decode_result, Checkpoint, OwnedBinding, Record, RotationError, RotationServerKey,
    RotationServerProvider, RotationServerStore, RotationServerStoreOptions,
};
use mcp_jack::server::http::{HandlerConfig, JackLayer, JackService, RotatingHandlerConfig};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::response_keys::{ResponseKeyRequest, ResponseKeys};
use mcp_jack::server::server_key::ServerKeyTool;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{
    Clock, Config, NativeCall, NativeResult, NativeTools, Verifier,
};
use mcp_jack::signing::response_signing_string;

/// The boxed inner service behind every harness (same shape as http_layer.rs;
/// S::Error = String).
type InnerBox =
    tower::util::BoxCloneService<http::Request<Full<Bytes>>, http::Response<Full<Bytes>>, String>;

/// Audience and window of the rotation fixture (Go TrustOptions).
const AUD: &str = "provider-test";
const WINDOW_SECONDS: i64 = 30;
/// The verifier clock NEVER moves: every request/response timestamp is 1000
/// (Go http_linux_test `Now: func() int64 { return 1000 }`). Only the STORE
/// clock (the atomic) moves, in the signing-time tests.
const NOW: i64 = 1000;
/// Caller seed of the Go nativeHTTP/http_linux_test fixtures.
const CALLER_SEED: [u8; 32] = [35u8; 32];
/// Static-profile key of the pin test (chunk E2 test 10).
const STATIC_SEED: [u8; 32] = [7u8; 32];
/// The inner application's exact answer (Go http_linux_test).
const APPLICATION_BODY: &[u8] = b"exact application body";
const PING_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;

/// Process-wide nonce source: the first 8 bytes are zero, the last 8 encode a
/// never-repeating counter (http_layer.rs idiom), so nonces are unique across
/// tests in one run.
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

static UNIQUE: AtomicUsize = AtomicUsize::new(0);

/// Temp directory removed on Drop; private (0700) because the rotation store
/// refuses a parent that is group/world accessible (private_file.rs).
struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(tag: &str) -> Self {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join(
            format!(
                "mcp-jack-server-rotation-signing-{tag}-{}-{}",
                std::process::id(),
                UNIQUE.fetch_add(1, Ordering::SeqCst)
            ),
        );
        fs::create_dir_all(&dir).expect("create temp dir");
        // The rotation store requires EXACTLY 0700 on the parent directory.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .expect("restrict temp dir to owner-only");
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

/// Signer with a test hook fired before the actual signature (Go signingHook).
struct HookSigner {
    inner: InMemorySigner,
    on_sign: Option<Hook>,
}

/// Hook passed to the fixture: receives the shared store clock so a hook can
/// move signing time exactly when write_authorized signs (Go's onSign closure
/// capturing f.now).
type AnchorHook = Arc<dyn Fn(&AtomicU64) + Send + Sync>;
/// Wrapped hook: counts signs, then runs the anchor hook.
type Hook = Arc<dyn Fn() + Send + Sync>;

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

/// The ordinary protocol-native implementation behind the verifier (Go
/// nativeFunc): counts calls, answers null, NEVER handles jack.server.key.
struct CountingNative {
    calls: Arc<AtomicUsize>,
}

impl NativeTools for CountingNative {
    fn call(&self, _c: &mut NativeCall) -> Result<NativeResult, JackError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(NativeResult {
            structured: serde_json::Value::Null,
        })
    }
}

/// Which signing-time mutation the candidate wrapper performs after the inner
/// tool answered (Go TestNativeServerKeySigningTimeRejectsChangedHeadOrCurrent).
enum Mutation {
    /// Publish "tail" so the committed head moves under the assembled page.
    Head,
    /// Move the store clock to the announced record's activation time so the
    /// anchor retires strictly there and another key becomes current.
    Current,
}

/// Wraps `ServerKeyTool`: the inner tool answers FIRST and only a successful
/// inner answer is followed by the mutation (Go nativeFunc order).
struct MutatingTool<C: FnMut() -> Result<u64, RotationError> + Send + 'static> {
    inner: ServerKeyTool<C>,
    provider: Arc<RotationServerProvider<C>>,
    now: Arc<AtomicU64>,
    tail_kid: String,
    cutoff_at: u64,
    mode: Mutation,
}

impl<C: FnMut() -> Result<u64, RotationError> + Send + 'static> NativeTools for MutatingTool<C> {
    fn call(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        let result = self.inner.call(c)?;
        match self.mode {
            Mutation::Head => {
                self.provider
                    .announce("tail", &self.tail_kid)
                    .expect("signing-time head publication must succeed");
            }
            Mutation::Current => {
                self.now.store(self.cutoff_at, Ordering::SeqCst);
            }
        }
        Ok(result)
    }
}

/// Which response-signing profile the harness builds (Go HandlerConfig
/// ServerKey vs ResponseKeys; the Rust constructors make mixing
/// unrepresentable).
enum Profile {
    /// JackLayer::rotating (Go ResponseKeys set).
    Rotating {
        /// Pair the verifier with `Verifier::with_server_keys` (Go
        /// Config.ServerKeys).
        with_server_keys: bool,
        /// Register the mutating candidate wrapper instead of the plain tool.
        mutation: Option<Mutation>,
    },
    /// JackLayer::new (Go ServerKey set): pins the unchanged static wire.
    Static,
}

struct FixtureOptions {
    /// Publish the "next" record before the test runs (Go setup + Announce).
    announce_next: bool,
    /// Hook fired before the anchor signer signs (Go signingHook).
    anchor_hook: Option<AnchorHook>,
    profile: Profile,
}

/// One harness, built per test: the rotating layer over a counting inner
/// service, the durable store with its shared clock, and the fixture keys.
struct Harness<C: FnMut() -> Result<u64, RotationError> + Send + 'static> {
    service: JackService<InnerBox>,
    store: Arc<Mutex<RotationServerStore<C>>>,
    now: Arc<AtomicU64>,
    provider: Arc<RotationServerProvider<C>>,
    /// The "next" publication when `announce_next` was set (Go first).
    first_record: Option<Record>,
    /// Fixture keys: seeds 31/32/33 (anchor, next, tail).
    keys: Vec<InMemorySigner>,
    inner_calls: Arc<AtomicUsize>,
    ordinary_native_calls: Arc<AtomicUsize>,
    signs: Arc<AtomicU64>,
    caller: InMemorySigner,
    nonces: Arc<NonceStore>,
    _dir: TempDirGuard,
}

impl<C: FnMut() -> Result<u64, RotationError> + Send + 'static> Harness<C> {
    /// Locks the shared store (Go f.store).
    fn lock_store(&self) -> MutexGuard<'_, RotationServerStore<C>> {
        self.store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// One candidate `jack.server.key` call (Go nativeHTTP's returned
    /// closure): signs a fresh request, sends it through the layer, requires
    /// that the ordinary native implementation stayed idle, and — when the
    /// answer carries Jack-Auth — verifies the carrier signature.
    async fn candidate(&self, arguments: &str) -> Exchange {
        let body = server_key_body(arguments);
        let sent = signed_request(&self.caller, "POST", "/mcp", &body);
        let got = inspect(
            send(&self.service, build_request(&sent, "POST", "/mcp", &body))
                .await
                .expect("no inner error"),
        )
        .await;
        assert_eq!(
            self.ordinary_native_calls.load(Ordering::SeqCst),
            0,
            "candidate route reached the ordinary native implementation"
        );
        if !got.jack_auth.is_empty() {
            assert_carrier_signature(self, &got, &sent.request_sig);
        }
        Exchange { sent, got }
    }
}

/// Builds the fixture (Go setup + New + optional Announce) and the harness:
/// seeds 31/32/33, store initialized at 1000 with the shared clock, caller
/// seed 35 registered in MemoryState, verifier clock fixed at 1000.
fn new_harness(
    options: FixtureOptions,
) -> Harness<impl FnMut() -> Result<u64, RotationError> + Send + 'static> {
    let dir = TempDirGuard::new("harness");
    let keys: Vec<InMemorySigner> = [31u8, 32, 33]
        .iter()
        .map(|seed| InMemorySigner::from_seed(&[*seed; 32]).expect("fixture signer"))
        .collect();
    let server_options = RotationServerStoreOptions {
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
    };
    let path = dir.path().join("server.db");
    RotationServerStore::initialize_unused(&path, server_options.clone(), || Ok(1000))
        .expect("initialize rotation store");
    let now = Arc::new(AtomicU64::new(1000));
    let signs = Arc::new(AtomicU64::new(0));
    let clock_now = Arc::clone(&now);
    let store = Arc::new(Mutex::new(
        RotationServerStore::open(&path, server_options, move || {
            Ok(clock_now.load(Ordering::SeqCst))
        })
        .expect("open rotation store"),
    ));

    // Caller seed 35 registered under name "caller" (Go nativeHTTP).
    let caller = InMemorySigner::from_seed(&CALLER_SEED).expect("caller signer");
    let caller_pub = caller.public_key();
    let state = MemoryState::new();
    state
        .update(&mut |edit| {
            edit.put_key(RegistryEntry {
                kid: key_id(&caller_pub),
                public_key: encode_b64url(&caller_pub),
                name: "caller".into(),
                admin: false,
                not_before: None,
                not_after: None,
            });
            Ok(())
        })
        .expect("seed caller registry entry");

    // The anchor hook counts every sign and can move the store clock at
    // exactly the moment write_authorized signs (Go signingHook).
    let anchor_hook: Option<Hook> = options.anchor_hook.map(|hook| {
        let clock = Arc::clone(&now);
        let signs = Arc::clone(&signs);
        Arc::new(move || {
            signs.fetch_add(1, Ordering::SeqCst);
            hook(&clock);
        }) as Hook
    });
    let inventory = vec![
        RotationServerKey {
            reference: "anchor".into(),
            signer: Arc::new(HookSigner {
                inner: keys[0].clone(),
                on_sign: anchor_hook,
            }),
        },
        RotationServerKey {
            reference: "next".into(),
            signer: Arc::new(keys[1].clone()),
        },
        RotationServerKey {
            reference: "tail".into(),
            signer: Arc::new(keys[2].clone()),
        },
    ];
    let provider = RotationServerProvider::new(Arc::clone(&store), inventory)
        .expect("rotation provider ready");
    let first_record = if options.announce_next {
        Some(
            provider
                .announce("next", keys[1].kid())
                .expect("announce next")
                .record,
        )
    } else {
        None
    };
    let provider = Arc::new(provider);

    let nonces = Arc::new(NonceStore::new());
    let ordinary_native_calls = Arc::new(AtomicUsize::new(0));
    let now_clock: Clock = Arc::new(|| NOW);
    let verifier = Verifier::new(Config {
        aud: AUD.into(),
        state: Arc::new(state),
        nonces: Arc::clone(&nonces),
        audit: None,
        native: Some(Arc::new(CountingNative {
            calls: Arc::clone(&ordinary_native_calls),
        })),
        window_seconds: WINDOW_SECONDS,
        now: now_clock,
    })
    .expect("verifier");

    let layer = match options.profile {
        Profile::Rotating {
            with_server_keys,
            mutation,
        } => {
            let tool: Arc<dyn NativeTools> = match mutation {
                None => Arc::new(ServerKeyTool::new(Arc::clone(&store), Arc::clone(&provider))),
                Some(mode) => Arc::new(MutatingTool {
                    inner: ServerKeyTool::new(Arc::clone(&store), Arc::clone(&provider)),
                    provider: Arc::clone(&provider),
                    now: Arc::clone(&now),
                    tail_kid: keys[2].kid().to_owned(),
                    cutoff_at: first_record
                        .as_ref()
                        .map(|record| record.activates_at)
                        .expect("mutation requires the announced record"),
                    mode,
                }),
            };
            let verifier = Arc::new(if with_server_keys {
                verifier.with_server_keys(tool)
            } else {
                verifier
            });
            JackLayer::rotating(RotatingHandlerConfig {
                verifier,
                response_keys: provider.clone(),
                max_body_bytes: 0,
                max_response_bytes: 0,
            })
        }
        Profile::Static => JackLayer::new(HandlerConfig {
            verifier: Arc::new(verifier),
            server_key: SigningKey::from_bytes(&STATIC_SEED),
            max_body_bytes: 0,
            max_response_bytes: 0,
        }),
    };

    let inner_calls = Arc::new(AtomicUsize::new(0));
    let recorder = Arc::clone(&inner_calls);
    let service = layer.layer(tower::util::BoxCloneService::new(tower::service_fn(
        move |req: http::Request<Full<Bytes>>| {
            let calls = Arc::clone(&recorder);
            async move {
                // Full's error is Infallible; the body content is irrelevant
                // to the fixture, only the call itself is counted.
                let (_, body) = req.into_parts();
                let _ = http_body_util::BodyExt::collect(body)
                    .await
                    .expect("Full body always collects");
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, String>(
                    http::Response::builder()
                        .status(200)
                        .header("Content-Type", "application/json")
                        .header("X-Private-App", "not-on-refusal")
                        .body(Full::new(Bytes::from_static(APPLICATION_BODY)))
                        .expect("static response parts"),
                )
            }
        },
    )));

    Harness {
        service,
        store,
        now,
        provider,
        first_record,
        keys,
        inner_calls,
        ordinary_native_calls,
        signs,
        caller,
        nonces,
        _dir: dir,
    }
}

/// One signed request under test: keeps the request signature so responses
/// can be verified against it (Go's signedRequest result).
struct SentRequest {
    header_value: String,
    request_sig: String,
}

/// Signs like Go's signedRequest: unique nonce, verifier ts 1000, exact
/// target.
fn signed_request(signer: &InMemorySigner, method: &str, target: &str, body: &[u8]) -> SentRequest {
    let n = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let mut nonce = [0u8; 16];
    nonce[8..].copy_from_slice(&n.to_be_bytes());
    let signed = sign_request(signer, AUD, method, target, body, &nonce, NOW)
        .unwrap_or_else(|e| panic!("sign_request: {e}"));
    SentRequest {
        header_value: signed.header_value,
        request_sig: signed.auth.sig,
    }
}

fn build_request(
    signed: &SentRequest,
    method: &str,
    target: &str,
    body: &[u8],
) -> http::Request<Full<Bytes>> {
    http::Request::builder()
        .method(method)
        .uri(target)
        .header("Jack-Auth", signed.header_value.as_str())
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("static request parts")
}

/// Sends `req` through the layered service (http_layer.rs pattern).
async fn send(
    svc: &JackService<InnerBox>,
    req: http::Request<Full<Bytes>>,
) -> Result<http::Response<Full<Bytes>>, String> {
    svc.clone().oneshot(req).await
}

/// Response view: status, all Jack-Auth values, body bytes, X-Private-App.
struct GotResponse {
    status: u16,
    jack_auth: Vec<String>,
    body: Bytes,
    x_private_app: Option<String>,
}

async fn inspect(res: http::Response<Full<Bytes>>) -> GotResponse {
    let status = res.status().as_u16();
    let jack_auth = res
        .headers()
        .get_all("Jack-Auth")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    let x_private_app = res
        .headers()
        .get("X-Private-App")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let (_, body) = res.into_parts();
    let body = http_body_util::BodyExt::collect(body)
        .await
        .expect("Full body always collects")
        .to_bytes();
    GotResponse {
        status,
        jack_auth,
        body,
        x_private_app,
    }
}

/// A candidate exchange: the request signature and the layer's answer.
struct Exchange {
    sent: SentRequest,
    got: GotResponse,
}

fn server_key_body(arguments: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"jack.server.key","arguments":{arguments}}}}}"#
    )
    .into_bytes()
}

fn server_key_body_without_arguments() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.server.key"}}"#
        .to_vec()
}

fn error_code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"]["code"].as_str().map(str::to_owned))
        .unwrap_or_else(|| panic!("no error code in body {:?}", String::from_utf8_lossy(body)))
}

/// Go nativeHTTP's carrier check: a response that carries Jack-Auth must
/// verify under the inventory key its kid names (never assumed to be the
/// anchor), over the exact status, request signature, and body bytes.
fn assert_carrier_signature<C>(h: &Harness<C>, got: &GotResponse, request_sig: &str)
where
    C: FnMut() -> Result<u64, RotationError> + Send + 'static,
{
    let values: Vec<&str> = got.jack_auth.iter().map(String::as_str).collect();
    let auth = parse_response_auth(&values).expect("carrier Jack-Auth parses");
    let public = h
        .keys
        .iter()
        .find(|key| key.kid() == auth.kid)
        .map(|key| key.public_key())
        .unwrap_or_else(|| panic!("carrier signed by unknown kid {}", auth.kid));
    let sig = decode_b64url_fixed(&auth.sig, 64).expect("carrier sig decodes to 64 bytes");
    let message = response_signing_string(
        got.status as i64,
        request_sig,
        &auth.kid,
        auth.ts,
        &got.body,
    );
    assert!(
        verify(&public, message.as_bytes(), &sig),
        "native carrier signature invalid"
    );
}

/// Go TestNativeServerKeyExplicitDispatchStrictArgumentsAndImmutablePage,
/// page half: the selected signer signs exactly one committed record and the
/// candidate is never forwarded.
#[tokio::test]
async fn native_page_is_signed_by_selected_signer() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: None,
        },
    });
    let first = h.first_record.clone().expect("announce happened");
    let exchange = h.candidate(r#"{"after_ordinal":0,"after_hash":"-"}"#).await;
    let got = &exchange.got;
    assert_eq!(got.status, 200, "a valid native request must be answered");
    assert_eq!(got.jack_auth.len(), 1, "the candidate page is signed");
    let values: Vec<&str> = got.jack_auth.iter().map(String::as_str).collect();
    let response = parse_response_auth(&values).expect("Jack-Auth parses");
    assert_eq!(
        response.kid,
        h.keys[0].kid(),
        "the SELECTED (anchor) signer signs the page"
    );
    assert_eq!(response.ts, NOW, "the signing timestamp is the store clock");
    let sig = decode_b64url_fixed(&response.sig, 64).expect("sig decodes to 64 bytes");
    let message = response_signing_string(
        200,
        &exchange.sent.request_sig,
        &response.kid,
        response.ts,
        &got.body,
    );
    assert!(
        verify(&h.keys[0].public_key(), message.as_bytes(), &sig),
        "native page signature does not verify under the anchor key"
    );

    let page = decode_result(&got.body, b"1").expect("the page envelope decodes");
    assert_eq!(page.current_kid, h.keys[0].kid(), "current is the anchor");
    assert_eq!(
        page.records,
        vec![first.wire],
        "exactly one exact committed snapshot record"
    );
    assert_eq!(page.head_ordinal, 1);
    assert!(page.complete, "one record page is complete");
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 0, "the candidate is never forwarded");
}

/// Go page half, head cursor: the cursor anchored at the head yields an empty
/// but complete page.
#[tokio::test]
async fn head_cursor_yields_empty_complete_page() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: None,
        },
    });
    let first = h.first_record.clone().expect("announce happened");
    let arguments = format!(r#"{{"after_ordinal":1,"after_hash":"{}"}}"#, first.hash);
    let got = h.candidate(&arguments).await.got;
    assert_eq!(got.status, 200, "the head cursor is valid");
    let page = decode_result(&got.body, b"1").expect("the page envelope decodes");
    assert!(
        page.records.is_empty(),
        "the head cursor must yield an empty page"
    );
    assert!(page.complete, "the empty head page is complete");
}

/// Go strict-arguments half: every undecodable arguments form is a signed 400
/// invalid_params (the nonce was consumed), including a tools/call whose
/// params lack the `arguments` member entirely.
#[tokio::test]
async fn strict_argument_refusals_are_signed_400() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: None,
        },
    });
    let strict = [
        "null",
        "{}",
        r#"{"after_ordinal":0,"after_hash":"-","extra":true}"#,
        r#"{"after_ordinal":7,"after_ordinal":0,"after_hash":"-"}"#,
        r#"{"after_ordinal":0,"after_hash":"-","after_hash":"-"}"#,
    ];
    for arguments in strict {
        let got = h.candidate(arguments).await.got;
        assert_eq!(got.status, 400, "arguments {arguments} must be refused");
        assert_eq!(
            got.jack_auth.len(),
            1,
            "the nonce was consumed, so the refusal is signed"
        );
        assert_eq!(error_code(&got.body), "invalid_params");
    }
    // A tools/call WITHOUT the arguments member is invalid_params too
    // (Go: server decodes a missing member the same way).
    let body = server_key_body_without_arguments();
    let signed = signed_request(&h.caller, "POST", "/mcp", &body);
    let got = inspect(
        send(&h.service, build_request(&signed, "POST", "/mcp", &body))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 400, "absent arguments must be refused");
    assert_eq!(
        got.jack_auth.len(),
        1,
        "the absent-arguments call still consumed its nonce"
    );
    assert_eq!(error_code(&got.body), "invalid_params");
    assert_eq!(
        h.ordinary_native_calls.load(Ordering::SeqCst),
        0,
        "the candidate route must not reach the ordinary native implementation"
    );
}

/// Go unavailable-cursor half: a well-formed cursor whose hash anchors
/// nothing is a signed 409.
#[tokio::test]
async fn unavailable_cursor_is_signed_409() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: None,
        },
    });
    let arguments = format!(r#"{{"after_ordinal":1,"after_hash":"{}"}}"#, "A".repeat(43));
    let got = h.candidate(&arguments).await.got;
    assert_eq!(got.status, 409, "an unanchored cursor is unavailable");
    assert_eq!(
        got.jack_auth.len(),
        1,
        "the unavailable-cursor refusal is signed"
    );
    assert_eq!(error_code(&got.body), "rotation_checkpoint_unavailable");
}

/// Go TestNativeServerKeyExplicitDispatch... closed half: without
/// `with_server_keys` the candidate route is enabled by NEITHER the ordinary
/// native implementation NOR its absence — signed 403 operation_denied, and
/// nothing is forwarded or dispatched.
#[tokio::test]
async fn candidate_route_requires_server_keys() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: false,
            mutation: None,
        },
    });
    let got = h
        .candidate(r#"{"after_ordinal":0,"after_hash":"-"}"#)
        .await
        .got;
    assert_eq!(got.status, 403, "the route must stay closed");
    assert_eq!(error_code(&got.body), "operation_denied");
    assert_eq!(
        got.jack_auth.len(),
        1,
        "the nonce was consumed, so the denial is signed"
    );
    assert_eq!(
        h.ordinary_native_calls.load(Ordering::SeqCst),
        0,
        "ordinary Native must not enable the candidate route"
    );
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 0, "nothing is forwarded");
}

/// Go TestConcreteProviderThroughMiddlewareFinalBeforeWireAndConsumedReplay,
/// success branch: a forwarded ping answer is preserved byte for byte and
/// signed by the anchor; the replayed identical request is refused unsigned;
/// the middleware releases its serving lease (clean close).
#[tokio::test]
async fn forwarded_answer_is_signed_and_replay_is_unsigned() {
    let h = new_harness(FixtureOptions {
        announce_next: false,
        // Count-only hook (Go signs++ without the late store): makes the
        // sign-count assertions non-vacuous.
        anchor_hook: Some(Arc::new(|_: &AtomicU64| {})),
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: None,
        },
    });
    let sent = signed_request(&h.caller, "POST", "/mcp", PING_BODY);
    let got = inspect(
        send(&h.service, build_request(&sent, "POST", "/mcp", PING_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200, "a verified ping forwards");
    assert_eq!(
        got.body.as_ref(),
        APPLICATION_BODY,
        "the application answer is preserved byte for byte"
    );
    assert_eq!(
        got.x_private_app.as_deref(),
        Some("not-on-refusal"),
        "inner headers survive a signed forward"
    );
    assert_eq!(got.jack_auth.len(), 1);
    let values: Vec<&str> = got.jack_auth.iter().map(String::as_str).collect();
    let response = parse_response_auth(&values).expect("Jack-Auth parses");
    assert_eq!(
        response.kid,
        h.keys[0].kid(),
        "the pinned wire identity is the anchor kid"
    );
    assert_eq!(response.ts, NOW, "the pinned wire time is 1000");
    let sig = decode_b64url_fixed(&response.sig, 64).expect("sig decodes to 64 bytes");
    let message = response_signing_string(
        200,
        &sent.request_sig,
        &response.kid,
        response.ts,
        &got.body,
    );
    assert!(
        verify(&h.keys[0].public_key(), message.as_bytes(), &sig),
        "wire response signature invalid"
    );
    assert_eq!(h.signs.load(Ordering::SeqCst), 1, "exactly one sign");
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 1, "one dispatch");
    assert_eq!(h.nonces.len(), 1, "exactly one nonce reservation");

    // Replay the IDENTICAL request bytes: consumed, refused, unsigned.
    let replay = inspect(
        send(&h.service, build_request(&sent, "POST", "/mcp", PING_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(replay.status, 401, "a consumed request must not be redelivered");
    assert_eq!(error_code(&replay.body), "replayed_nonce");
    assert_eq!(
        replay.jack_auth,
        Vec::<String>::new(),
        "the replay answer is unsigned"
    );
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 1, "no second dispatch");
    assert_eq!(h.signs.load(Ordering::SeqCst), 1, "no second sign");

    // The middleware released its serving lease on every path.
    h.lock_store()
        .close()
        .expect("middleware leaked serving lease");
    // Go provider test parity: a closed owner never serves again.
    let dead = ResponseKeyRequest {
        status: 404,
        tool: "not-a-key-authority",
        request_signature: "",
        body: b"untrusted selector",
    };
    assert!(
        h.provider.authorize_response(&dead).is_err(),
        "closed owner served"
    );
}

/// Go success branch's twin, late-final: the anchor's on-sign hook moves the
/// store clock past the freshness window EXACTLY when write_authorized signs,
/// so the computed signature is discarded and the UNSIGNED 503 refusal leaks
/// neither the application body nor its headers.
#[tokio::test]
async fn late_final_gate_discards_signature() {
    let h = new_harness(FixtureOptions {
        announce_next: false,
        anchor_hook: Some(Arc::new(|clock: &AtomicU64| {
            clock.store(1031, Ordering::SeqCst);
        })),
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: None,
        },
    });
    let sent = signed_request(&h.caller, "POST", "/mcp", PING_BODY);
    let got = inspect(
        send(&h.service, build_request(&sent, "POST", "/mcp", PING_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 503, "the late final gate must fail the response");
    assert_eq!(
        got.jack_auth,
        Vec::<String>::new(),
        "the refusal is unsigned: no Jack-Auth"
    );
    assert_eq!(error_code(&got.body), "rotation_state_unavailable");
    let body = String::from_utf8_lossy(&got.body).into_owned();
    assert!(
        !body.contains("exact application body"),
        "the application body leaked into the refusal: {body}"
    );
    assert_eq!(
        got.x_private_app, None,
        "inner headers are discarded on refusal"
    );
    assert_eq!(h.now.load(Ordering::SeqCst), 1031, "the hook moved the clock");
    assert_eq!(h.signs.load(Ordering::SeqCst), 1, "the signature was computed once");
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 1, "the forward already happened");

    // Go shared tail: the replay is a consumed nonce, and the refusal path
    // released the lease, so the store closes cleanly.
    let replay = inspect(
        send(&h.service, build_request(&sent, "POST", "/mcp", PING_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(replay.status, 401, "a consumed request must not be redelivered");
    assert_eq!(h.signs.load(Ordering::SeqCst), 1, "no second sign");
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 1, "no second dispatch");
    h.lock_store()
        .close()
        .expect("middleware leaked serving lease");
}

/// Go TestNativeServerKeySigningTimeRejectsChangedHeadOrCurrent, head variant:
/// the committed head moves AFTER the page was assembled but BEFORE signing;
/// the response parity gate discards the stale page (never exposed).
#[tokio::test]
async fn signing_time_head_change_discards_page() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: Some(Mutation::Head),
        },
    });
    let got = h
        .candidate(r#"{"after_ordinal":0,"after_hash":"-"}"#)
        .await
        .got;
    assert_eq!(got.status, 503, "a mixed signing-time snapshot must refuse");
    assert_eq!(
        got.jack_auth,
        Vec::<String>::new(),
        "the stale page is never signed"
    );
    let body = String::from_utf8_lossy(&got.body).into_owned();
    assert!(
        body.contains("rotation_state_unavailable"),
        "unexpected refusal body: {body}"
    );
    assert!(
        !body.contains("structuredContent"),
        "the stale page leaked into the refusal: {body}"
    );
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 0, "never forwarded");
    assert_eq!(
        h.ordinary_native_calls.load(Ordering::SeqCst),
        0,
        "the wrapper must not reach the ordinary native implementation"
    );
}

/// Go current variant: the store clock moves to the announced record's
/// activation time AFTER the page was assembled, so the anchor retires
/// strictly there and another key is current at signing time; the stale page
/// is discarded unsigned.
#[tokio::test]
async fn signing_time_current_change_discards_page() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: Some(Mutation::Current),
        },
    });
    let first = h.first_record.clone().expect("announce happened");
    let got = h
        .candidate(r#"{"after_ordinal":0,"after_hash":"-"}"#)
        .await
        .got;
    assert_eq!(got.status, 503, "a changed current must refuse the page");
    assert_eq!(
        got.jack_auth,
        Vec::<String>::new(),
        "the stale page is never signed"
    );
    let body = String::from_utf8_lossy(&got.body).into_owned();
    assert!(
        body.contains("rotation_state_unavailable"),
        "unexpected refusal body: {body}"
    );
    assert!(
        !body.contains("structuredContent"),
        "the stale page leaked into the refusal: {body}"
    );
    assert_eq!(
        h.now.load(Ordering::SeqCst),
        first.activates_at,
        "the mutation moved the store clock to the cutoff"
    );
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 0, "never forwarded");
}

/// Pin that the static response-signing profile is untouched by the rotating
/// work: the same fixture behind `JackLayer::new` still signs with its own
/// static key.
#[tokio::test]
async fn static_profile_still_signs_with_static_key() {
    let h = new_harness(FixtureOptions {
        announce_next: false,
        anchor_hook: None,
        profile: Profile::Static,
    });
    let static_pub = SigningKey::from_bytes(&STATIC_SEED)
        .verifying_key()
        .to_bytes();
    let sent = signed_request(&h.caller, "POST", "/mcp", PING_BODY);
    let got = inspect(
        send(&h.service, build_request(&sent, "POST", "/mcp", PING_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200, "the static profile still forwards");
    assert_eq!(got.body.as_ref(), APPLICATION_BODY);
    assert_eq!(got.jack_auth.len(), 1, "the static profile still signs");
    let values: Vec<&str> = got.jack_auth.iter().map(String::as_str).collect();
    let response = parse_response_auth(&values).expect("Jack-Auth parses");
    assert_eq!(
        response.kid,
        key_id(&static_pub),
        "the static key signs, not a rotation key"
    );
    assert_eq!(response.ts, NOW, "the static profile signs at the verifier clock");
    let sig = decode_b64url_fixed(&response.sig, 64).expect("sig decodes to 64 bytes");
    let message = response_signing_string(
        200,
        &sent.request_sig,
        &response.kid,
        response.ts,
        &got.body,
    );
    assert!(
        verify(&static_pub, message.as_bytes(), &sig),
        "static profile signature invalid"
    );
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 1);
}
