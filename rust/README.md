This crate is the Rust SDK for mcp-jack, the secure transport protocol wrapping MCP with authentication, authorization and audit: server verifier and tower layer (feature `http`), client and native tools, mirroring the Go SDK. It is checked against the same conformance vectors in spec/fixtures. Its fixture-loading tests read ../spec/fixtures in place rather than embedding copies.

## Tower HTTP adapter (feature `http`)

`JackLayer` (Go: `server.NewHandler`) wraps an existing tower `Service`, buffers each request body up to `max_body_bytes` (default 1 MiB), verifies it and answers protocol-native `jack.*` tools itself. Everything else is forwarded to the inner service; the inner response is buffered and signed, so `text/event-stream` responses are refused with 501 (v0.1 cannot sign streams). The inner response is buffered up to `max_response_bytes` (default 1 MiB, independent of `max_body_bytes`; exactly the limit passes). Beyond it the answer is a signed 502 `response_too_large`: upstream status, headers and partial body are discarded, and the answer is a fresh JSON response with its own `Content-Type` plus the `Jack-Auth` signature header (no upstream header survives); the inner body is dropped. Limits of the cap: it bounds bytes read, not time. A body that never yields a frame, or yields only empty frames, is not stopped by it (empty frames add no bytes and are not retained, but the adapter keeps awaiting). A deadline on the inner service covers only obtaining the response (headers + body handle), not the later body consumption, which happens in the adapter's future; a deadline covering body consumption must wrap the whole `JackService` produced by `JackLayer` (tower timeout or `tokio::time::timeout` around the call; the caller's responsibility, this crate has no timeout option). The inner service's own allocations before it returns its response are not bounded. Inner service errors propagate unchanged. The inner service must accept `http::Request<http_body_util::Full<bytes::Bytes>>` — wrap a hyper/axum-style service accordingly (this crate does not depend on axum).

```rust,ignore
use bytes::Bytes;
use http_body_util::Full;
use mcp_jack::server::http::{HandlerConfig, JackLayer};
use tower::Layer as _;
use mcp_jack::server::verify::{Config, Verifier};
use std::sync::Arc;

let verifier = Verifier::new(Config {
    aud: "https://mcp.example/mcp".to_owned(),
    state: Arc::new(state_store),
    nonces: Arc::new(nonce_store),
    policy: Arc::new(policy),
    audit: None,
    native: Some(Arc::new(native_tools)),
    window_seconds: 0,
    now: Arc::new(|| unix_seconds()),
})?;
let layer = JackLayer::new(HandlerConfig {
    verifier: Arc::new(verifier),
    server_key,
    max_body_bytes: 0,
    max_response_bytes: 0,
});
let service = layer.layer(tower::service_fn(
    |req: http::Request<Full<Bytes>>| async move {
        Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(Bytes::new())))
    },
));
```

## Interop executables (feature `interop`)

`cargo build --release --features interop` builds the harness executables `interop-server` and `interop-client` (`--features interop,http` also works, since `interop` enables `http`); the feature gates the optional HTTP dependencies (hyper/tokio) so the default library build is unaffected. The interop harness (`interop/targets.json`) expects the release paths below, with `.exe` appended automatically on Windows by the harness (interop/README.md section 2). Run `node interop/run.mjs` to drive them, or `node interop/run.mjs --clients rust --servers rust` for just the Rust pair (interop/README.md section 3); the `--verify-only` and `--bootstrap-ttl` contract lives in interop/README.md section 4.

```text
rust/target/release/interop-server
rust/target/release/interop-client
```
