This crate is the server-side Rust SDK for mcp-jack, the secure transport protocol wrapping MCP with authentication, authorization and audit. It mirrors the Go SDK and is checked against the same conformance vectors in spec/fixtures. Its fixture-loading tests read ../spec/fixtures in place rather than embedding copies.

## Tower HTTP adapter (feature `http`)

`JackLayer` (Go: `server.NewHandler`) wraps an existing tower `Service`, buffers each request body up to `max_body_bytes` (default 1 MiB), verifies it and answers protocol-native `jack.*` tools itself. Everything else is forwarded to the inner service; the inner response is buffered in full and signed, so `text/event-stream` responses are refused with 501 (v0.1 cannot sign streams). Inner service errors propagate unchanged. The inner service must accept `http::Request<http_body_util::Full<bytes::Bytes>>` — wrap a hyper/axum-style service accordingly (this crate does not depend on axum).

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
});
let service = layer.layer(tower::service_fn(
    |req: http::Request<Full<Bytes>>| async move {
        Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(Bytes::new())))
    },
));
```
