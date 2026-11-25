//! Signed-stream interop modes. Signing, SSE parsing and stream verification are delegated to the SDK.
use mcp_jack::stream::{StreamStep, StreamVerifier, StreamVerifierConfig};
use std::io::Write;
use std::sync::Arc;

pub fn mode_from_args() -> Option<String> {
    std::env::args()
        .skip(1)
        .find_map(|a| a.strip_prefix("--mode=").map(str::to_owned))
        .or_else(|| {
            let a: Vec<_> = std::env::args().skip(1).collect();
            a.windows(2)
                .find(|w| w[0] == "--mode")
                .map(|w| w[1].clone())
        })
}
fn args() -> Vec<String> {
    std::env::args().skip(1).collect()
}
fn flag(a: &[String], key: &str) -> Option<String> {
    for (i, x) in a.iter().enumerate() {
        if x == key {
            return a.get(i + 1).cloned();
        } else if let Some(v) = x.strip_prefix(&format!("{key}=")) {
            return Some(v.into());
        }
    }
    None
}
fn fail(s: impl std::fmt::Display) -> ! {
    eprintln!("stream interop: {s}");
    std::process::exit(1)
}
fn read_clock(path: &str) -> Result<i64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("clock file: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("clock JSON: {e}"))?;
    v.as_i64()
        .or_else(|| v.get("clock").and_then(serde_json::Value::as_i64))
        .or_else(|| std::str::from_utf8(&bytes).ok()?.trim().parse().ok())
        .ok_or_else(|| "invalid clock value".into())
}
fn emit(v: &serde_json::Value) {
    let mut o = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut o, v);
    let _ = o.write_all(b"\n");
    let _ = o.flush();
}
fn b64(b: &[u8]) -> String {
    mcp_jack::encoding::encode_b64url(b)
}
fn code(c: mcp_jack::stream::StreamCode) -> &'static str {
    c.as_str()
}
pub fn run_server() -> ! {
    server::run()
}
pub fn run_client() -> ! {
    client::run()
}
#[allow(dead_code)]
pub struct VerifiedWire {
    pub open: Option<mcp_jack::stream::OpenAuth>,
    pub frames: Vec<mcp_jack::stream::JackFrame>,
    pub delivered: Vec<String>,
    pub terminal: Option<mcp_jack::stream::StreamFailure>,
}
#[allow(dead_code)]
pub fn verify_wire(
    status: u16,
    headers: &[(String, String)],
    chunks: &[Vec<u8>],
    kid: String,
    public_key: [u8; 32],
    request_sig: String,
    now: mcp_jack::client::Clock,
) -> VerifiedWire {
    use mcp_jack::stream::SseReader;
    let mut cfg = StreamVerifierConfig::pinned(kid, public_key, request_sig);
    cfg.now = now;
    let mut v = StreamVerifier::new(cfg);
    let open = v.open(status, headers).ok().cloned();
    let Some(_) = open else {
        return VerifiedWire {
            open,
            frames: vec![],
            delivered: vec![],
            terminal: None,
        };
    };
    let mut reader = SseReader::new();
    let mut frames = Vec::new();
    let mut delivered = Vec::new();
    let mut terminal = None;
    for (i, c) in chunks.iter().enumerate() {
        let es = reader.push(c, i as i64 + 1);
        let before = v.frames_verified();
        let s: StreamStep = v.push(c, i as i64 + 1);
        delivered.extend(s.messages);
        terminal = s.terminal;
        for e in es.into_iter().take(v.frames_verified() - before) {
            if let Ok(f) = mcp_jack::stream::parse_frame(&e.lines) {
                frames.push(f)
            }
        }
        if terminal.is_some() {
            break;
        }
    }
    if terminal.is_none() {
        let s = v.finish(None);
        delivered.extend(s.messages);
        terminal = s.terminal;
    }
    VerifiedWire {
        open,
        frames,
        delivered,
        terminal,
    }
}
#[path = "client.rs"]
mod client;
#[cfg(target_os = "linux")]
#[path = "durable.rs"]
mod durable;
#[cfg(target_os = "linux")]
#[path = "rotation.rs"]
mod rotation;
#[path = "server.rs"]
mod server;

#[path = "wrapper.rs"]
mod wrapper;
