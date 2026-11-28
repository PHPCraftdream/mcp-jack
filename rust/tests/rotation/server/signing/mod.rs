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
use http_body_util::Full;
use mcp_jack::user_key::ServerSigningKey;
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
use mcp_jack::server::http::{HandlerBuilder, JackService, RotatingHandlerBuilder};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::response_keys::{ResponseKeyRequest, ResponseKeys};
use mcp_jack::server::server_key::ServerKeyTool;
use mcp_jack::server::state::{MemoryState, RegistryEntry, StateStore};
use mcp_jack::server::verify::{Clock, NativeCall, NativeResult, NativeTools, VerifierBuilder};
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
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "mcp-jack-server-rotation-signing-{tag}-{}-{}",
                std::process::id(),
                UNIQUE.fetch_add(1, Ordering::SeqCst)
            ));
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
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
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
    let verifier_builder = VerifierBuilder::new(AUD, Arc::new(state))
        .nonces(nonces.clone())
        .native_tools(Some(Arc::new(CountingNative {
            calls: Arc::clone(&ordinary_native_calls),
        })))
        .window_seconds(WINDOW_SECONDS)
        .now(now_clock);

    let layer = match options.profile {
        Profile::Rotating {
            with_server_keys,
            mutation,
        } => {
            let tool: Arc<dyn NativeTools> = match mutation {
                None => Arc::new(ServerKeyTool::new(
                    Arc::clone(&store),
                    Arc::clone(&provider),
                )),
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
            let verifier_builder = if with_server_keys {
                verifier_builder.with_server_keys(tool)
            } else {
                verifier_builder
            };
            let verifier = Arc::new(verifier_builder.try_build().expect("verifier"));
            RotatingHandlerBuilder::new(verifier, provider.clone()).build()
        }
        Profile::Static => {
            let verifier = Arc::new(verifier_builder.try_build().expect("verifier"));
            HandlerBuilder::new(verifier, ServerSigningKey::from_bytes(&STATIC_SEED)).build()
        }
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

mod pages;
