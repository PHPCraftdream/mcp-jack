//! Durable nonce store helpers for interop-server (linux-only; the durable
//! modules of the SDK are `#[cfg(target_os = "linux")]`). All functions are
//! synchronous: store open/initialize is plain file I/O, no await needed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use mcp_jack::server::durable_admission::{BoxedDurableClock, SharedDurableNonceStore};
use mcp_jack::server::durable_store::{DurableNonceStore, DurableStoreOptions};

use crate::fail;
use crate::interop::unix_now;

/// An opened durable store plus its immutable window W (also used as the
/// verifier's `window_seconds`).
pub struct Setup {
    pub store: Arc<SharedDurableNonceStore>,
    pub window: i64,
}

/// Store FILE path: the durable dir joined with "nonces".
pub fn store_path(dir: &str) -> PathBuf {
    Path::new(dir).join("nonces")
}

/// Parses and validates `--durable-window` (default "30"); 1..120 seconds.
pub fn parse_window(raw: Option<&str>) -> i64 {
    let raw = raw.unwrap_or("30");
    match raw.parse::<i64>() {
        Ok(w) if (1..=120).contains(&w) => w,
        _ => fail("--durable-window must be an integer number of seconds in 1..120"),
    }
}

fn options(aud: &str, window: i64) -> DurableStoreOptions {
    DurableStoreOptions {
        deployment_id: aud.to_owned(),
        window,
    }
}

fn boxed_clock() -> BoxedDurableClock {
    Box::new(unix_now)
}

/// `--durable-init`: explicit out-of-band initialization of a never-used
/// store, then the single stdout line; exits 0. Any error is a startup
/// failure (stderr diagnostic, nonzero exit, nothing on stdout).
pub fn init_and_print(dir: &str, window_raw: Option<&str>, aud: &str) -> ! {
    let window = parse_window(window_raw);
    let path = store_path(dir);
    let opts = options(aud, window);
    if let Err(e) = DurableNonceStore::initialize_unused(&path, &opts, boxed_clock()) {
        fail(format!("durable init: {e}"));
    }
    println!("{{\"durable_initialized\":true}}");
    std::process::exit(0)
}

/// Opens the existing store for serve mode; any Err (e.g. RecoveryRequired
/// after a crash) is a startup failure before the ready line.
pub fn setup(dir: &str, window_raw: Option<&str>, aud: &str) -> Setup {
    let window = parse_window(window_raw);
    let path = store_path(dir);
    let opts = options(aud, window);
    match DurableNonceStore::open(&path, &opts, boxed_clock()) {
        Ok(store) => Setup {
            store: Arc::new(store),
            window,
        },
        Err(e) => fail(format!("durable nonce store: {e}")),
    }
}
