//! Linux durable nonce-store setup for the stream interop server.
use std::{path::Path, sync::Arc};

use mcp_jack::server::{
    durable_admission::{BoxedDurableClock, SharedDurableNonceStore},
    durable_store::{DurableNonceStore, DurableStoreOptions},
};

pub const WINDOW_SECONDS: i64 = 30;

pub struct Setup {
    pub store: Arc<SharedDurableNonceStore>,
    pub window: i64,
}

fn clock(path: String) -> BoxedDurableClock {
    Box::new(move || {
        let Ok(bytes) = std::fs::read(&path) else {
            return 0;
        };
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        parsed
            .as_i64()
            .or_else(|| parsed.get("clock").and_then(serde_json::Value::as_i64))
            .or_else(|| std::str::from_utf8(&bytes).ok()?.trim().parse().ok())
            .unwrap_or(0)
    })
}

fn options(audience: &str) -> DurableStoreOptions {
    DurableStoreOptions {
        deployment_id: audience.to_owned(),
        window: WINDOW_SECONDS,
    }
}

pub fn initialize_if_requested(
    dir: Option<&str>,
    requested: bool,
    audience: &str,
    clock_file: &str,
) {
    if requested {
        if let Some(dir) = dir {
            initialize(dir, audience, clock_file).unwrap_or_else(|error| {
                eprintln!("stream server: {error}");
                std::process::exit(1)
            });
            println!("{{\"durable_initialized\":true}}");
            std::process::exit(0);
        }
    }
}

pub fn initialize(dir: &str, audience: &str, clock_file: &str) -> Result<(), String> {
    DurableNonceStore::initialize_unused(
        &Path::new(dir).join("nonces"),
        &options(audience),
        clock(clock_file.to_owned()),
    )
    .map_err(|e| format!("durable init: {e:?}"))
}

pub fn open_optional(dir: Option<&str>, audience: &str, clock_file: &str) -> Option<Setup> {
    dir.map(|dir| {
        open(dir, audience, clock_file).unwrap_or_else(|error| {
            eprintln!("stream server: {error}");
            std::process::exit(1)
        })
    })
}

pub fn open(dir: &str, audience: &str, clock_file: &str) -> Result<Setup, String> {
    let store = DurableNonceStore::open(
        &Path::new(dir).join("nonces"),
        &options(audience),
        clock(clock_file.to_owned()),
    )
    .map_err(|e| format!("durable nonce store: {e:?}"))?;
    Ok(Setup {
        store: Arc::new(store),
        window: WINDOW_SECONDS,
    })
}

pub fn close_optional(setup: Option<&Setup>) {
    if let Some(setup) = setup {
        close(setup);
    }
}

pub fn close(setup: &Setup) {
    if let Err(error) = setup.store.close() {
        eprintln!("stream server: durable store close: {error:?}");
    }
}
