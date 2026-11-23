//! The `modern-server` executable (interop/modern/contract.md 3.1-3.6).
//! Mirrors src/bin/interop_server.rs: flag set, order of operations, one ready
//! line, listener accept loop, stdin/SIGTERM shutdown and explicit exit codes.
//! The SDK wrapper does the era handling; this module only wires it.

use std::sync::Arc;

use mcp_jack::encoding::{encode_b64url, key_id};
use mcp_jack::server::http::{HandlerConfig, JackLayer};
use mcp_jack::server::modern::Profile;
use mcp_jack::server::native::{Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::state_file::FileState;
use mcp_jack::server::verify::{Clock, Config, Verifier};
use tower_layer::Layer as _;

use super::handler::{DiscoverMode, ModernHandler};
use super::proto;

/// Contract 3.1: the defaults of the three optional flags.
const DEFAULT_SUPPORTED_VERSIONS: &str = "2026-07-28,2025-11-25";

/// fail prints a startup error to stderr and exits 1. Startup failures must
/// never touch stdout, so the driver never sees a partial ready line.
fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("modern-server: {msg}");
    std::process::exit(1)
}

/// Parsed command line (contract 3.1 plus the `--mode` dispatch selector that
/// interop/targets.json always passes to this binary).
struct Flags {
    profile: Profile,
    aud: String,
    state: String,
    seed_hex: String,
    clock_file: String,
    port: u16,
    request_log: Option<String>,
    supported_versions: Vec<String>,
    discover_mode: DiscoverMode,
}

/// Hand-rolled flag parsing like the existing bins: both `--flag value` and
/// `--flag=value`; unknown flags, missing values and positional arguments are
/// startup failures.
fn parse_flags() -> Flags {
    let mut args = std::env::args().skip(1);
    let mut profile: Option<String> = None;
    let mut aud: Option<String> = None;
    let mut state: Option<String> = None;
    let mut seed_hex: Option<String> = None;
    let mut clock_file: Option<String> = None;
    let mut port: Option<String> = None;
    let mut request_log: Option<String> = None;
    let mut supported_versions: Option<String> = None;
    let mut discover_mode: Option<String> = None;
    while let Some(arg) = args.next() {
        if !arg.starts_with("--") {
            fail(format!("unexpected positional argument: {arg}"));
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
                    None => fail(format!("missing value for --{name}")),
                },
            }
        };
        match name.as_str() {
            // The dispatch selector arrives in argv; mode_from_args already
            // decided the mode, so the value itself is not needed here.
            "mode" => {
                let _ = value("mode");
            }
            "profile" => profile = Some(value("profile")),
            "aud" => aud = Some(value("aud")),
            "state" => state = Some(value("state")),
            "server-seed-hex" => seed_hex = Some(value("server-seed-hex")),
            "clock-file" => clock_file = Some(value("clock-file")),
            "port" => port = Some(value("port")),
            "request-log" => request_log = Some(value("request-log")),
            "supported-versions" => supported_versions = Some(value("supported-versions")),
            "discover-version-mode" => discover_mode = Some(value("discover-version-mode")),
            _ => fail(format!("unknown flag --{name}")),
        }
    }

    let Some(profile) = profile else {
        fail("missing required --profile");
    };
    let profile = match profile.as_str() {
        "legacy" => Profile::Legacy,
        "modern" => Profile::Modern,
        "both" => Profile::Both,
        other => fail(format!("unknown --profile {other}")),
    };
    let Some(aud) = aud else {
        fail("missing required --aud");
    };
    let Some(state) = state else {
        fail("missing required --state");
    };
    let Some(seed_hex) = seed_hex else {
        fail("missing required --server-seed-hex");
    };
    let Some(clock_file) = clock_file else {
        fail("missing required --clock-file");
    };
    let Some(port) = port else {
        fail("missing required --port");
    };
    let port = port
        .parse::<u16>()
        .unwrap_or_else(|_| fail(format!("invalid --port {port}")));
    let discover_mode = match discover_mode.as_deref() {
        Some(value) => DiscoverMode::parse(value)
            .unwrap_or_else(|| fail(format!("unknown --discover-version-mode {value}"))),
        None => DiscoverMode::Supported,
    };
    let supported_versions = supported_versions
        .unwrap_or_else(|| DEFAULT_SUPPORTED_VERSIONS.to_owned())
        .split(',')
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .map(str::to_owned)
        .collect();
    // An empty path is not a usable log file, so it means "no log" like the
    // fake server's absent flag.
    let request_log = request_log.filter(|path| !path.is_empty());

    Flags {
        profile,
        aud,
        state,
        seed_hex,
        clock_file,
        port,
        request_log,
        supported_versions,
        discover_mode,
    }
}

/// Ready line: the first and only stdout output (contract 3.2).
#[derive(serde::Serialize)]
struct Ready {
    ready: bool,
    port: u16,
    server_public_key: String,
    server_kid: String,
    profile: &'static str,
}

/// Entry point of `--mode modern-server`. Never returns.
pub fn run() -> ! {
    let flags = parse_flags();
    // Contract 3.2: a bad clock or state file exits 1 before binding, and
    // before anything is written to stdout.
    proto::read_clock(&flags.clock_file).unwrap_or_else(|e| fail(format!("--clock-file: {e}")));
    let state = FileState::open(&flags.state).unwrap_or_else(|e| fail(format!("--state: {e}")));
    let seed = crate::interop::hex_decode_32(&flags.seed_hex)
        .unwrap_or_else(|_| fail("--server-seed-hex must be 64 hex chars (32 bytes)"));
    let server_key = ed25519_dalek::SigningKey::from_bytes(&seed);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => fail(format!("runtime: {e}")),
    };
    use std::io::Write as _;
    if let Err(e) = runtime.block_on(serve(flags, state, server_key)) {
        eprintln!("modern-server: {e}");
        let _ = std::io::stderr().flush();
        // Explicit exit skips Runtime::drop, whose blocking-pool shutdown
        // waits indefinitely; guarantees the error path exits 1 promptly.
        std::process::exit(1);
    }
    // Explicit exit (again skipping Runtime::drop): neither a still-blocked
    // stdin watcher thread nor runtime teardown can delay exit 0.
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(0);
}

async fn serve(
    flags: Flags,
    state: FileState,
    server_key: ed25519_dalek::SigningKey,
) -> Result<(), String> {
    let Flags {
        profile,
        aud,
        clock_file,
        port,
        request_log,
        supported_versions,
        discover_mode,
        ..
    } = flags;

    // Contract section 2: the clock file is read every time "now" is needed,
    // and a file that went bad after startup fails the process instead of
    // reusing a stale timestamp.
    let now: Clock = Arc::new(move || proto::clock_or_exit(&clock_file, "modern-server"));
    let verifier = Verifier::new(Config {
        aud,
        state: Arc::new(state),
        nonces: Arc::new(NonceStore::new()),
        audit: None,
        native: Some(Arc::new(Native::new(NativeOptions::default()))),
        // 0 selects the SDK default 30 s freshness window.
        window_seconds: 0,
        now,
    })
    .map_err(|e| format!("verifier: {e}"))?;

    let public_key = encode_b64url(server_key.verifying_key().as_bytes());
    let kid = key_id(server_key.verifying_key().as_bytes());
    let request_log = request_log.map(|path| Arc::new(std::path::PathBuf::from(path)));
    let handler = ModernHandler::new(profile, supported_versions, discover_mode, request_log);
    // Contract 3.6: the profile is the ONLY era switch; the wrapper owns the
    // era handling, mirror validation, refusals and forwarding.
    let layer = JackLayer::new(HandlerConfig {
        verifier: Arc::new(verifier),
        server_key,
        max_body_bytes: 0,
        max_response_bytes: 0,
    })
    .with_profile(profile);
    let service = layer.layer(handler);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("listen: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("listen: {e}"))?
        .port();

    println!(
        "{}",
        serde_json::to_string(&Ready {
            ready: true,
            port,
            server_public_key: public_key,
            server_kid: kid,
            profile: profile.as_str(),
        })
        .expect("static ready shape serializes")
    );
    // The driver blocks on this line, so it must not sit in the buffer.
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    // Bounds concurrent connections; the harness is localhost, but unbounded
    // accept admission is a known hazard.
    let semaphore = Arc::new(tokio::sync::Semaphore::new(64));
    // Serve failures reach the select below via this channel.
    let (serve_err_tx, mut serve_err_rx) = tokio::sync::oneshot::channel::<String>();
    // In-flight connection tasks, tracked so shutdown can drain them (each
    // entry bounded by the semaphore above). Finished entries are pruned on
    // push so the list never grows past the live connection count.
    let inflight: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::default();
    let accept_task = tokio::task::spawn({
        let inflight = Arc::clone(&inflight);
        async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        let _ = serve_err_tx.send(format!("accept: {e}"));
                        return;
                    }
                };
                // Acquired BEFORE spawning; the permit moves into the task and
                // is dropped at its end.
                let permit = match semaphore.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => return, // semaphore closed: never happens here
                };
                let service = service.clone();
                let inflight = Arc::clone(&inflight);
                let join = tokio::task::spawn(async move {
                    let _permit = permit;
                    let hyper_service = hyper_util::service::TowerToHyperService::new(service);
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), hyper_service)
                        .await
                    {
                        eprintln!("modern-server: connection: {e}");
                    }
                });
                {
                    let mut live = inflight.lock().unwrap_or_else(|e| e.into_inner());
                    live.retain(|handle| !handle.is_finished());
                    live.push(join);
                }
            }
        }
    });

    // Harness closes stdin to stop the server. A detached plain OS thread is
    // used on purpose: tokio's AsyncRead stdin performs an UNCANCELLABLE
    // blocking read on the runtime's blocking pool, and Runtime::drop waits
    // indefinitely for blocking work — a std::thread is not owned by the
    // runtime, so teardown never waits on it, and run's explicit exit
    // abandons it if stdin never closes. The thread is deliberately not joined.
    let (stdin_tx, stdin_rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break, // EOF
                // A read error is treated as EOF (logged to stderr only).
                Err(e) => {
                    eprintln!("modern-server: stdin: {e}");
                    break;
                }
                Ok(_) => {}
            }
        }
        let _ = stdin_tx.send(());
    });

    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| format!("signal: {e}"))?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            // SIGTERM is unix-only; other platforms just wait forever here.
            #[cfg(unix)]
            sigterm.recv().await;
            #[cfg(not(unix))]
            std::future::pending::<()>().await;
        } => {}
        _ = stdin_rx => {}
        err = &mut serve_err_rx => {
            // Serve failure: nonzero exit.
            if let Ok(e) = err {
                return Err(e);
            }
        }
    }

    // Shutdown order: stop accepting, then drain in-flight connections with a
    // per-connection bound so a stuck connection cannot delay exit.
    accept_task.abort();
    let _ = accept_task.await;
    let draining: Vec<tokio::task::JoinHandle<()>> = {
        let mut live = inflight.lock().unwrap_or_else(|e| e.into_inner());
        live.drain(..).collect()
    };
    for handle in draining {
        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), handle).await;
    }
    Ok(())
}
