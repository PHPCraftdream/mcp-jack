//! `--mode rotation-server` of interop-server: serves the trivial MCP handler
//! under the rotating response profile backed by a private-file rotation ring
//! store (interop/README.md rotation matrix). Announce commands arrive as one
//! JSON object per stdin line; stdout carries only the ready line and the
//! announce verdicts.

use std::io::{BufRead as _, Write as _};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use mcp_jack::client::signer::InMemorySigner;
use mcp_jack::encoding::{encode_b64url, key_id};
use mcp_jack::rotation::{
    Checkpoint, OwnedBinding, RotationError, RotationServerKey, RotationServerProvider,
    RotationServerStore, RotationServerStoreOptions,
};
use mcp_jack::server::http::{JackLayer, RotatingHandlerConfig};
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::server_key::ServerKeyTool;
use mcp_jack::server::state_file::FileState;
use mcp_jack::server::verify::{Clock, Config, Verifier};
use tower_layer::Layer as _;

use super::hex_decode_32;

/// Concrete clock-callback type unifying the store generics: one boxed
/// closure per store construction (init and open each get a fresh one).
type ClockFn = Box<dyn FnMut() -> Result<u64, RotationError> + Send>;

/// Builds one fresh store clock closure from the clock file.
fn clock_fn(clock: &ClockFile) -> ClockFn {
    let clock = clock.clone();
    Box::new(move || clock.sample())
}

/// Clock sampled from a driver-managed file, with a last-good cache. The
/// durable rotation store samples it fallibly and fails closed; the verifier
/// request clock is the only infallible consumer.
#[derive(Clone)]
struct ClockFile {
    path: String,
    cache: Arc<Mutex<Option<u64>>>,
}

impl ClockFile {
    fn new(path: &str) -> Self {
        Self {
            path: path.to_owned(),
            cache: Arc::new(Mutex::new(None)),
        }
    }

    fn sample(&self) -> Result<u64, RotationError> {
        let err = || RotationError {
            code: "rotation_clock_unavailable",
        };
        let raw = std::fs::read_to_string(&self.path).map_err(|_| err())?;
        let parsed = raw.trim().parse::<u64>().map_err(|_| err())?;
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        *cache = Some(parsed);
        Ok(parsed)
    }

    /// Infallible request clock for the verifier: a failed sample falls back
    /// to the cached value (or 0). The durable rotation store's samples are
    /// fallible and fail closed, so it is the real time gate.
    fn now_i64(&self) -> i64 {
        match self.sample() {
            Ok(now) => now as i64,
            Err(_) => {
                let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
                cached_option_to_i64(*cache)
            }
        }
    }
}

/// Cached-or-zero fallback (u64 timestamps fit i64 up to MAX_TIMESTAMP).
fn cached_option_to_i64(cached: Option<u64>) -> i64 {
    match cached {
        Some(v) => v as i64,
        None => 0,
    }
}

/// fail prints a startup error to stderr and exits nonzero, before any stdout.
fn fatal(msg: impl std::fmt::Display) -> ! {
    eprintln!("interop-server: {msg}");
    std::process::exit(1)
}

/// Parsed command line of rotation-server mode.
struct Flags {
    aud: String,
    url: String,
    state: String,
    seed_hex: String,
    rotation_store: String,
    clock_file: String,
    port: u16,
    ring_seeds: Vec<(String, [u8; 32])>,
}

/// Hand-rolled flag parsing, same style as the default interop-server mode.
fn parse_flags() -> Flags {
    let mut args = std::env::args().skip(1);
    let mut flags = Flags {
        aud: String::new(),
        url: String::new(),
        state: String::new(),
        seed_hex: String::new(),
        rotation_store: String::new(),
        clock_file: String::new(),
        port: 0,
        ring_seeds: Vec::new(),
    };
    while let Some(arg) = args.next() {
        if !arg.starts_with("--") {
            fatal(format!("unexpected positional argument: {arg}"));
        }
        let (name, inline) = match arg.strip_prefix("--").and_then(|r| r.split_once('=')) {
            Some((n, v)) => (n.to_owned(), Some(v.to_owned())),
            None => (arg[2..].to_owned(), None),
        };
        let mut value = |name: &str| -> String {
            match inline.clone() {
                Some(v) => v,
                None => match args.next() {
                    Some(v) => v,
                    None => fatal(format!("missing value for --{name}")),
                },
            }
        };
        match name.as_str() {
            "aud" => flags.aud = value("aud"),
            "url" => flags.url = value("url"),
            "state" => flags.state = value("state"),
            "server-seed-hex" => flags.seed_hex = value("server-seed-hex"),
            "rotation-store" => flags.rotation_store = value("rotation-store"),
            "clock-file" => flags.clock_file = value("clock-file"),
            "port" => {
                let raw = value("port");
                flags.port = match raw.parse::<u16>() {
                    Ok(p) => p,
                    Err(_) => fatal("--port must be a u16"),
                };
            }
            "ring-seed" => {
                // Split at the FIRST '=' only: the hex value never contains
                // '=' but the reference grammar is free-form.
                let kv = value("ring-seed");
                let (reference, hex) = match kv.split_once('=') {
                    Some((r, h)) => (r.to_owned(), h.to_owned()),
                    None => fatal("--ring-seed must be reference=hexseed"),
                };
                let seed = match hex_decode_32(&hex) {
                    Ok(s) => s,
                    Err(_) => fatal("--ring-seed hex must be 64 hex chars (32 bytes)"),
                };
                flags.ring_seeds.push((reference, seed));
            }
            _ => fatal(format!("unknown flag --{name}")),
        }
    }
    if flags.aud.is_empty()
        || flags.url.is_empty()
        || flags.state.is_empty()
        || flags.seed_hex.is_empty()
        || flags.rotation_store.is_empty()
        || flags.clock_file.is_empty()
    {
        fatal(
            "--aud, --url, --state, --server-seed-hex, --rotation-store and --clock-file \
             are required",
        );
    }
    flags
}

/// Readiness line: the first and only startup stdout output.
#[derive(serde::Serialize)]
struct Ready {
    ready: bool,
    port: u16,
    server_public_key: String,
    server_kid: String,
}

/// Entry point of rotation-server mode. Never returns; exits 0 after a clean
/// shutdown, 1 on any startup or serve failure (stderr only before the ready
/// line).
pub fn run() -> ! {
    let flags = parse_flags();
    let seed = match hex_decode_32(&flags.seed_hex) {
        Ok(seed) => seed,
        Err(_) => fatal("--server-seed-hex must be 64 hex chars (32 bytes)"),
    };
    let server_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let kid0 = key_id(server_key.verifying_key().as_bytes());
    let pub0: [u8; 32] = *server_key.verifying_key().as_bytes();
    let pub0_b64 = encode_b64url(&pub0);

    let clock = ClockFile::new(&flags.clock_file);
    let state = match FileState::open(&flags.state) {
        Ok(s) => s,
        Err(e) => fatal(format!("state file: {e}")),
    };

    let options = RotationServerStoreOptions {
        binding: OwnedBinding {
            endpoint: flags.url.clone(),
            aud: flags.aud.clone(),
        },
        window: 30,
        checkpoint: Checkpoint {
            ordinal: 0,
            hash: "-".to_owned(),
            kid: kid0.clone(),
            public_key: pub0,
            published_at: 0,
        },
        anchor_reference: "ring-0".to_owned(),
    };
    let store_path = Path::new(&flags.rotation_store);
    if !store_path.exists() {
        // Fresh closure per store construction; the generic C unifies per
        // call site.
        if let Err(e) = RotationServerStore::initialize_unused(
            store_path,
            options.clone(),
            clock_fn(&clock),
        ) {
            fatal(format!("rotation store: {}", e.code));
        }
    }
    let store = match RotationServerStore::open(store_path, options, clock_fn(&clock)) {
        Ok(store) => store,
        Err(e) => fatal(format!("rotation store: {}", e.code)),
    };
    let store = Arc::new(Mutex::new(store));

    // Inventory: the anchor key (same seed as the static profile key) plus
    // every --ring-seed handle.
    let base_signer = match InMemorySigner::from_seed(&seed) {
        Ok(signer) => signer,
        Err(e) => fatal(format!("signer: {e}")),
    };
    let mut keys = vec![RotationServerKey {
        reference: "ring-0".to_owned(),
        signer: Arc::new(base_signer),
    }];
    for (reference, ring_seed) in flags.ring_seeds {
        match InMemorySigner::from_seed(&ring_seed) {
            Ok(signer) => keys.push(RotationServerKey {
                reference,
                signer: Arc::new(signer),
            }),
            Err(e) => fatal(format!("ring signer: {e}")),
        }
    }

    let provider = match RotationServerProvider::new(Arc::clone(&store), keys) {
        Ok(provider) => Arc::new(provider),
        Err(e) => fatal(format!("rotation provider: {}", e.code)),
    };

    let verifier = match Verifier::new(Config {
        aud: flags.aud.clone(),
        // window 0: the spec default 30 s, same as the static profile.
        state: Arc::new(state),
        nonces: Arc::new(NonceStore::new()),
        audit: None,
        native: Some(Arc::new(Native::new(NativeOptions::default()))),
        window_seconds: 0,
        now: {
            let clock = clock.clone();
            let now: Clock = Arc::new(move || clock.now_i64());
            now
        },
    }) {
        Ok(verifier) => verifier,
        Err(e) => fatal(format!("verifier: {e}")),
    };
    let verifier = verifier
        .with_server_keys(Arc::new(ServerKeyTool::new(Arc::clone(&store), Arc::clone(&provider))));

    let layer = JackLayer::rotating(RotatingHandlerConfig {
        verifier: Arc::new(verifier),
        response_keys: provider.clone(),
        // 0 means the SDK default 1 MiB body/response limits.
        max_body_bytes: 0,
        max_response_bytes: 0,
    });
    let service = layer.layer(crate::mcp::TrivialService);

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => fatal(format!("runtime: {e}")),
    };

    let result: Result<(), String> = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", flags.port))
            .await
            .map_err(|e| format!("listen: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("listen: {e}"))?
            .port();

        // Ready line FIRST: the harness gates every later step on it.
        println!(
            "{}",
            serde_json::to_string(&Ready {
                ready: true,
                port,
                server_public_key: pub0_b64,
                server_kid: kid0.clone(),
            })
            .expect("static ready shape serializes")
        );
        let _ = std::io::stdout().flush();

        // Bounds concurrent connections; same admission guard as the static
        // profile.
        let semaphore = Arc::new(tokio::sync::Semaphore::new(64));
        let (serve_err_tx, mut serve_err_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::task::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        let _ = serve_err_tx.send(format!("accept: {e}"));
                        return;
                    }
                };
                let permit = match semaphore.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => return, // semaphore closed: never happens here
                };
                let service = service.clone();
                let _join = tokio::task::spawn(async move {
                    let _permit = permit;
                    let hyper_service = hyper_util::service::TowerToHyperService::new(service);
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), hyper_service)
                        .await
                    {
                        eprintln!("interop-server: connection: {e}");
                    }
                });
            }
        });

        // stdin control: one JSON object per line; EOF shuts down (oneshot,
        // same detached plain thread rationale as the default mode).
        let (stdin_tx, stdin_rx) = tokio::sync::oneshot::channel::<()>();
        let announce_provider = Arc::clone(&provider);
        std::thread::spawn(move || {
            let reader = std::io::BufReader::new(std::io::stdin());
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let value = match serde_json::from_str::<serde_json::Value>(line) {
                    Ok(v) => v,
                    Err(_) => {
                        eprintln!("interop-server: stdin: invalid JSON line");
                        continue;
                    }
                };
                let op = value.get("op").and_then(|v| v.as_str()).unwrap_or("");
                if op != "announce" {
                    eprintln!("interop-server: stdin: unknown op {op:?}");
                    continue;
                }
                let Some(reference) = value.get("reference").and_then(|v| v.as_str()) else {
                    eprintln!("interop-server: stdin: announce missing reference");
                    continue;
                };
                let Some(kid) = value.get("kid").and_then(|v| v.as_str()) else {
                    eprintln!("interop-server: stdin: announce missing kid");
                    continue;
                };
                // Synchronous durable publication on the stdin thread; brief
                // blocking is expected and safe here.
                let verdict = match announce_provider.announce(reference, kid) {
                    Ok(publication) => serde_json::json!({
                        "announced": true,
                        "ordinal": publication.record.ordinal,
                        "head_ordinal": publication.record.ordinal,
                        "head_hash": publication.record.hash,
                        "published_at": publication.record.published_at,
                        "activates_at": publication.record.activates_at,
                        "revision": publication.revision,
                    }),
                    Err(_) => serde_json::json!({
                        "announced": false,
                        "reason": "rotation_state_unavailable",
                    }),
                };
                println!("{verdict}");
                let _ = std::io::stdout().flush();
            }
            let _ = stdin_tx.send(());
        });

        #[cfg(unix)]
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| format!("signal: {e}"))?;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                #[cfg(unix)]
                sigterm.recv().await;
                #[cfg(not(unix))]
                std::future::pending::<()>().await;
            } => {}
            _ = stdin_rx => {}
            err = &mut serve_err_rx => {
                if let Ok(e) = err {
                    return Err(e);
                }
            }
        }
        Ok(())
    });

    if let Err(e) = result {
        eprintln!("interop-server: {e}");
    }
    // Best-effort clean close: a leftover dirty marker would block the next
    // open of this path, but the driver always uses fresh store paths.
    {
        let mut guard = store.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = guard.close();
    }
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(0);
}
