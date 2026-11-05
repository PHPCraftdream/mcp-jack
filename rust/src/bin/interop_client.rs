#![forbid(unsafe_code)]
//! Command interop-client (interop README sections 5-7). Prints exactly one
//! JSON result line on stdout; harness-level failures go to stderr with
//! exit code 1. Mirrors interop/go/client/main.go: flag set, sign-only
//! mode, seeds file, one shared raw and one shared signed transport, then
//! the scenario.

mod interop; // src/bin/interop/: shared helpers, net transport, scenarios

use std::collections::HashMap;

use mcp_jack::client::signer::{InMemorySigner, Signer as _};
use mcp_jack::client::transport::SigningTransport;
use mcp_jack::encoding::{decode_b64url, decode_b64url_fixed};

use interop::{fatal, hex_decode_32, unix_now, Outcome, SeedKey, SeedsFile, StepResult};

/// Parsed command line (Go's flag set).
struct Flags {
    url: String,
    seed_hex: String,
    pub_key: String,
    aud: String,
    scenario: String,
    seeds: String,
    /// Presence matters: ts=0 is a valid sign-case value, so Option<i64>,
    /// not a defaulted integer (Go: tsFlag).
    ts: Option<i64>,
    nonce: String,
    args: HashMap<String, String>,
}

/// Hand-rolled flag parsing (Go's flag package is not a dependency). Accepts
/// both `--flag value` and `--flag=value`; unknown flags, missing values and
/// positional arguments are startup failures.
fn parse_flags() -> Flags {
    let mut args = std::env::args().skip(1);
    let mut flags = Flags {
        url: String::new(),
        seed_hex: String::new(),
        pub_key: String::new(),
        aud: String::new(),
        scenario: String::new(),
        seeds: String::new(),
        ts: None,
        nonce: String::new(),
        args: HashMap::new(),
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
            "url" => flags.url = value("url"),
            "seed-hex" => flags.seed_hex = value("seed-hex"),
            "server-public-key" => flags.pub_key = value("server-public-key"),
            "aud" => flags.aud = value("aud"),
            "scenario" => flags.scenario = value("scenario"),
            "seeds" => flags.seeds = value("seeds"),
            "ts" => {
                let raw = value("ts");
                match raw.parse::<i64>() {
                    Ok(v) => flags.ts = Some(v),
                    Err(_) => fatal("--ts must be an integer unix timestamp"),
                }
            }
            "nonce" => flags.nonce = value("nonce"),
            "arg" => {
                let kv = value("arg");
                // Split at the FIRST '=' only: a value may contain '='; no
                // '=' means an empty value (Go strings.Cut).
                let (k, v) = match kv.split_once('=') {
                    Some((k, v)) => (k.to_owned(), v.to_owned()),
                    None => (kv, String::new()),
                };
                flags.args.insert(k, v);
            }
            _ => fatal(format!("unknown flag --{name}")),
        }
    }
    if flags.scenario.is_empty() {
        fatal("--scenario is required");
    }
    if flags.seed_hex.is_empty() {
        fatal("--seed-hex is required");
    }
    flags
}

/// sign-only: reproduces the sign-cases oracle bytes without any network
/// I/O; --url/--server-public-key are ignored (Go: runSignOnly). Never
/// returns; emits and exits 0.
fn run_sign_only(flags: &Flags, primary: &InMemorySigner) -> ! {
    let method = flags.args.get("method").map(|s| s.as_str()).unwrap_or("");
    let target = flags.args.get("target").map(|s| s.as_str()).unwrap_or("");
    if method.is_empty() || target.is_empty() {
        fatal("sign-only requires --arg method=... and --arg target=...");
    }
    let Some(ts) = flags.ts else {
        fatal("sign-only requires --ts");
    };
    if flags.nonce.is_empty() {
        fatal("sign-only requires --nonce");
    }
    let nonce_vec = match decode_b64url_fixed(&flags.nonce, 16) {
        Ok(n) => n,
        Err(e) => fatal(format!("--nonce must decode to 16 bytes: {e}")),
    };
    let nonce: [u8; 16] = nonce_vec
        .try_into()
        .expect("decode_b64url_fixed(_, 16) yields 16 bytes");
    // Empty body-b64u is valid and means an empty body.
    let body = match flags
        .args
        .get("body-b64u")
        .map(|s| s.as_str())
        .unwrap_or("")
    {
        "" => Vec::new(),
        b64 => match decode_b64url(b64) {
            Ok(b) => b,
            Err(e) => fatal(format!("body-b64u: {e}")),
        },
    };
    let signed = match mcp_jack::client::sign_request(
        primary, &flags.aud, method, target, &body, &nonce, ts,
    ) {
        Ok(s) => s,
        Err(e) => fatal(format!("SignRequest: {e}")),
    };
    // Keys are written in the order Go's map-literal-independent JSON shows:
    // the harness compares parsed JSON, so alphabetical map order is fine.
    let data = serde_json::json!({
        "signing_string": signed.signing_string,
        "jack_auth": signed.header_value,
        "kid": primary.kid(),
    });
    let data = match serde_json::value::RawValue::from_string(data.to_string()) {
        Ok(d) => d,
        Err(e) => fatal(format!("marshal result: {e}")),
    };
    interop::emit(
        &flags.scenario,
        // Direct struct literal: sign-only reports http_status null.
        StepResult {
            kind: Outcome::Ok,
            status: None,
            code: None,
            data: Some(data),
        },
    )
}

fn main() {
    let flags = parse_flags();
    let seed = match hex_decode_32(&flags.seed_hex) {
        Ok(s) => s,
        Err(_) => fatal("--seed-hex must be 64 hex chars decoding to 32 bytes"),
    };
    let primary = match InMemorySigner::from_seed(&seed) {
        Ok(p) => p,
        Err(e) => fatal(format!("signer: {e}")),
    };

    // sign-only never touches the network and ignores --url/--server-public-key.
    if flags.scenario == "sign-only" {
        run_sign_only(&flags, &primary);
    }

    if flags.url.is_empty() {
        fatal("--url is required");
    }
    if flags.pub_key.is_empty() {
        fatal("--server-public-key is required");
    }
    if flags.aud.is_empty() {
        fatal("--aud is required");
    }
    if flags.seeds.is_empty() {
        fatal("--seeds is required");
    }
    let server_key_vec = match decode_b64url_fixed(&flags.pub_key, 32) {
        Ok(k) => k,
        Err(e) => fatal(format!("--server-public-key must decode to 32 bytes: {e}")),
    };
    let server_key: [u8; 32] = server_key_vec
        .try_into()
        .expect("decode_b64url_fixed(_, 32) yields 32 bytes");

    let raw = match std::fs::read(&flags.seeds) {
        Ok(r) => r,
        Err(e) => fatal(format!("reading --seeds: {e}")),
    };
    let sf: SeedsFile = match serde_json::from_slice(&raw) {
        Ok(sf) => sf,
        Err(e) => fatal(format!("parsing --seeds: {e}")),
    };
    let mut seeds = HashMap::new();
    // Case-insensitive seed match (Go strings.EqualFold).
    let mut primary_name: Option<String> = None;
    for k in sf.keys {
        if k.seed_hex.eq_ignore_ascii_case(&flags.seed_hex) {
            primary_name = Some(k.name.clone());
        }
        seeds.insert(
            k.name.clone(),
            SeedKey {
                name: k.name,
                seed_hex: k.seed_hex,
                kid: k.kid,
            },
        );
    }

    let transport = std::sync::Arc::new(interop::net::TcpTransport::new());
    let raw_typed = SigningTransport {
        transport: std::sync::Arc::clone(&transport),
        aud: flags.aud.clone(),
        // Per-request signer overrides in the SDK call path (enroll/rotate)
        // still apply on top of the default primary.
        signer: std::sync::Arc::new(primary.clone()),
        server_key,
        now: std::sync::Arc::new(unix_now),
        nonce: std::sync::Arc::new(|| mcp_jack::client::random_nonce().map(|n| n.to_vec())),
        // 0 means the SDK default window.
        window_seconds: 0,
    };
    let env = interop::scenarios::Env {
        scenario: flags.scenario.clone(),
        base_url: flags.url.clone(),
        aud: flags.aud.clone(),
        server_key,
        args: flags.args.clone(),
        seeds,
        primary: std::sync::Arc::new(primary),
        primary_name,
        transport,
        raw_typed,
    };
    interop::scenarios::run(&env, &flags.scenario);
}
