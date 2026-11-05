#![forbid(unsafe_code)]
//! Command interop-server implements the interop-server contract of
//! interop/README.md section 4 on top of the mcp-jack server SDK. Mirrors
//! interop/go/server/main.go: flag set, order of operations, ready line,
//! verify-only steps and exit codes.

// The two binaries are separate crates; the server uses only part of the
// shared helper module, so the rest is dead here but not in interop-client.
#[allow(dead_code)]
#[path = "interop/mod.rs"]
mod interop;

#[path = "interop/mcp.rs"]
mod mcp;

use std::sync::Arc;

use mcp_jack::encoding::{decode_b64url, decode_b64url_fixed, encode_b64url, key_id};
use mcp_jack::server::http::{HandlerConfig, JackLayer};
use mcp_jack::server::native::{bootstrap_admin, Native, NativeOptions};
use mcp_jack::server::nonce::NonceStore;
use mcp_jack::server::policy::Policy;
use mcp_jack::server::state::StateStore as _;
use mcp_jack::server::state_file::FileState;
use mcp_jack::server::verify::{Clock, Config, Verifier};
use tower_layer::Layer as _;

/// The shared interop helpers re-exported for brevity.
use interop::{hex_decode_32, unix_now};

/// Parsed command line (Go's flag set).
struct Flags {
    aud: String,
    policy: String,
    state: String,
    seed_hex: String,
    bootstrap_ttl: Option<String>,
    verify_only: bool,
}

/// fail prints a startup error to stderr and exits nonzero. Startup failures
/// must never touch stdout so the harness never sees a partial ready line.
fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("interop-server: {msg}");
    std::process::exit(1)
}

/// Hand-rolled flag parsing (Go's flag package is not a dependency). Accepts
/// both `--flag value` and `--flag=value`; unknown flags, missing values and
/// positional arguments are startup failures.
fn parse_flags() -> Flags {
    let mut args = std::env::args().skip(1);
    let mut flags = Flags {
        aud: String::new(),
        policy: String::new(),
        state: String::new(),
        seed_hex: String::new(),
        bootstrap_ttl: None,
        verify_only: false,
    };
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
            "aud" => flags.aud = value("aud"),
            "policy" => flags.policy = value("policy"),
            "state" => flags.state = value("state"),
            "server-seed-hex" => flags.seed_hex = value("server-seed-hex"),
            "bootstrap-ttl" => flags.bootstrap_ttl = Some(value("bootstrap-ttl")),
            "verify-only" => flags.verify_only = true,
            _ => fail(format!("unknown flag --{name}")),
        }
    }
    if flags.aud.is_empty()
        || flags.policy.is_empty()
        || flags.state.is_empty()
        || flags.seed_hex.is_empty()
    {
        fail("--aud, --policy, --state and --server-seed-hex are required");
    }
    flags
}

/// stdin JSON object of --verify-only.
#[derive(serde::Deserialize)]
struct VerifyInput {
    method: String,
    target: String,
    jack_auth: String,
    body_b64u: String,
}

/// The single verdict line of --verify-only; omit-when-absent matches Go's
/// omitempty.
#[derive(serde::Serialize)]
struct Verdict<'a> {
    verify: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
}

/// Writes the single verdict line and exits 0 (both verdicts).
fn print_verdict(v: Verdict<'_>) -> ! {
    println!(
        "{}",
        serde_json::to_string(&v).expect("static verdict shape serializes")
    );
    std::process::exit(0)
}

/// --verify-only: performs request-auth steps 1-4 and 7 of spec 01 section 4
/// (Go: runVerifyOnly). Steps 5/6/8 are skipped: the sign cases use fixed ts
/// values 0 and 999999999999. Never returns; exits 0 either way.
fn run_verify_only(aud: &str, state: &FileState) -> ! {
    let mut data = Vec::new();
    use std::io::Read as _;
    if let Err(e) = std::io::stdin().read_to_end(&mut data) {
        fail(format!("read stdin: {e}"));
    }
    let Ok(input) = serde_json::from_slice::<VerifyInput>(&data) else {
        fail("stdin: invalid JSON");
    };
    let body = match decode_b64url(&input.body_b64u) {
        // "" decodes to empty — valid.
        Ok(b) => b,
        Err(e) => fail(format!("body_b64u: {e}")),
    };

    // Steps 1-3: header grammar and version.
    let auth = match mcp_jack::auth_header::parse_request_auth(&[input.jack_auth.as_str()]) {
        Ok(auth) => auth,
        Err(err) => print_verdict(Verdict {
            verify: "reject",
            kid: None,
            code: Some(&err.code),
        }),
    };
    // Step 4: kid lookup.
    let Some(entry) = state.lookup(&auth.kid) else {
        print_verdict(Verdict {
            verify: "reject",
            kid: None,
            code: Some(mcp_jack::error::codes::UNKNOWN_KEY),
        });
    };
    // Unreachable: the state loader validated every entry's public key.
    let pub_bytes = match decode_b64url_fixed(&entry.public_key, 32) {
        Ok(k) => k,
        Err(e) => fail(format!("registry public key: {e}")),
    };
    // Unreachable: the parser validated the sig encoding; kept mirroring Go.
    let sig = match decode_b64url_fixed(&auth.sig, 64) {
        Ok(s) => s,
        Err(_) => print_verdict(Verdict {
            verify: "reject",
            kid: None,
            code: Some(mcp_jack::error::codes::BAD_SIGNATURE),
        }),
    };
    // Step 7: strict Ed25519 over the canonical signing string.
    let signing = mcp_jack::signing::request_signing_string(
        &input.method,
        &input.target,
        aud,
        &auth.kid,
        auth.ts,
        &auth.nonce,
        &body,
    );
    if mcp_jack::ed25519::verify(&pub_bytes, signing.as_bytes(), &sig) {
        print_verdict(Verdict {
            verify: "accept",
            kid: Some(&auth.kid),
            code: None,
        });
    }
    print_verdict(Verdict {
        verify: "reject",
        kid: None,
        code: Some(mcp_jack::error::codes::BAD_SIGNATURE),
    })
}

fn main() {
    // Sync setup (flags, files, verify-only) never touches the runtime.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => fail(format!("runtime: {e}")),
    };
    use std::io::Write as _;
    if let Err(e) = rt.block_on(run()) {
        eprintln!("interop-server: {e}");
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

/// Readiness line: the first and only stdout output of serve mode.
#[derive(serde::Serialize)]
struct Ready {
    ready: bool,
    port: u16,
    server_public_key: String,
    server_kid: String,
}

/// stderr line of --bootstrap-ttl.
#[derive(serde::Serialize)]
struct BootstrapLine {
    bootstrap_invite: String,
}

async fn run() -> Result<(), String> {
    // Order of operations mirrors Go main().
    let flags = parse_flags();
    let seed = match hex_decode_32(&flags.seed_hex) {
        Ok(seed) => seed,
        Err(_) => fail("--server-seed-hex must be 64 hex chars (32 bytes)"),
    };
    let server_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let kid = key_id(server_key.verifying_key().as_bytes());
    let pub_b64 = encode_b64url(server_key.verifying_key().as_bytes());

    let state = match FileState::open(&flags.state) {
        Ok(s) => s,
        Err(e) => fail(format!("state file: {e}")),
    };
    let policy_data = match std::fs::read(&flags.policy) {
        Ok(d) => d,
        Err(e) => fail(format!("policy file: {e}")),
    };
    // The policy is parsed even in verify-only mode, mirroring Go.
    let policy = match Policy::parse(&policy_data) {
        Ok(p) => p,
        Err(e) => fail(format!("policy file: {e}")),
    };

    if flags.verify_only {
        // Bootstrap-ttl is ignored in this mode (Go returns before it).
        run_verify_only(&flags.aud, &state);
    }

    if let Some(ttl_raw) = &flags.bootstrap_ttl {
        let ttl = match ttl_raw.parse::<i64>() {
            Ok(t) => t,
            Err(_) => fail("--bootstrap-ttl must be an integer number of seconds"),
        };
        let code = match bootstrap_admin(&state, unix_now(), ttl, NativeOptions::default()) {
            Ok(c) => c,
            Err(e) => fail(format!("--bootstrap-ttl: {e}")),
        };
        let line = BootstrapLine {
            bootstrap_invite: code,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&line).expect("static bootstrap shape serializes")
        );
    }

    let clock: Clock = Arc::new(unix_now);
    let verifier = match Verifier::new(Config {
        aud: flags.aud.clone(),
        // window 0: the spec default 30 s (interop README section 4).
        state: Arc::new(state),
        nonces: Arc::new(NonceStore::new()),
        policy: Arc::new(policy),
        audit: None,
        native: Some(Arc::new(Native::new(NativeOptions::default()))),
        window_seconds: 0,
        now: clock,
    }) {
        Ok(v) => v,
        Err(e) => fail(format!("verifier: {e}")),
    };
    let layer = JackLayer::new(HandlerConfig {
        verifier: Arc::new(verifier),
        server_key,
        // 0 means the SDK default 1 MiB body limit.
        max_body_bytes: 0,
    });
    let service = layer.layer(mcp::TrivialService);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
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
            server_public_key: pub_b64,
            server_kid: kid,
        })
        .expect("static ready shape serializes")
    );

    // Bounds concurrent connections; the harness is localhost, but unbounded
    // accept admission is a known hazard.
    let semaphore = Arc::new(tokio::sync::Semaphore::new(64));
    // Serve failures reach the select below via this channel.
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
            // Acquired BEFORE spawning; the permit moves into the task and is
            // dropped at its end.
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => return, // semaphore closed: never happens here
            };
            let service = service.clone();
            // Fire-and-forget by design: the harness kills the process to stop
            // us; connection errors are logged to stderr only, never stdout.
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

    // Harness closes stdin to stop the server. A detached plain OS thread is
    // used on purpose: tokio's AsyncRead stdin performs an UNCANCELLABLE
    // blocking read on the runtime's blocking pool, and Runtime::drop waits
    // indefinitely for blocking work — a std::thread is not owned by the
    // runtime, so teardown never waits on it, and main's explicit exit
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
                    eprintln!("interop-server: stdin: {e}");
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
            // Serve failure: nonzero exit, mirroring Go's serveErr branch.
            if let Ok(e) = err {
                return Err(e);
            }
        }
    }
    // No graceful drain required; the process exits 0.
    Ok(())
}
