# Embedding rmcp behind mcp-jack

**Status:** source-inspected design; no implementation, compilation, or runtime compatibility claim. **Reviewed:** 2026-11-28. **Pin:** `rmcp = "=3.9.0"`, confirmed by `tools/mcp-e2e/rust/Cargo.lock:690-693` (`[[package]] name = "rmcp"`, version `3.9.0`). Upstream references below use the `rmcp-v3.9.0` tag; tags are not immutable commit receipts. Local pointers refer to repository source. This is a proposal, not an API or CI change.

## Verdict

**Direct embedding is source-compatible in principle:** rmcp's `StreamableHttpService` accepts a Tower service over `Request<Full<Bytes>>`; Jack accepts that request type and its response body/error bounds fit rmcp's `BoxBody<Bytes, Infallible>`. No request/response adapter is indicated by the inspected signatures. A Hyper edge has a different request-body type (`Incoming`), which Jack's generic incoming-body bounds accept. This is a source-level fit, not a compiled or exercised integration.

The bounded first profile should be legacy MCP **2025-11-25**, stateless JSON responses, no sessions, no required intermediate notifications or tool-produced SSE. Jack refuses `text/event-stream` with a signed 501, so rmcp's default stateful initialize/session path is not viable through Jack: it may create an upstream session and emit SSE, which Jack rejects before the response (and session id) reaches the caller. Use explicit rmcp configuration and enforce the handler restriction. Defer modern protocol pairing until Jack's modern profile is selected and tested. No mcp-jack identity API change is justified before the API freeze: identity can already flow through request extensions.

## 1. Service wiring and body types

Local `JackService` accepts `S: Service<Request<Full<Bytes>>, Response=Response<ResBody>> + Clone + Send + 'static`; its error and future are `Send + 'static`, and `ResBody: BodyExt + Send + 'static` with error convertible to `BoxError`. Its own response is `Response<Full<Bytes>>` and its error is `S::Error`. Incoming body `B` requires `BodyExt + Send + 'static`, `B::Data: Send`, and `B::Error: Into<BoxError>` (`rust/src/server/http/mod.rs:285-308`).

At the pinned tag, rmcp implements Tower `Service<Request<RequestBody>>` where `RequestBody: Body + Send + 'static`, `S: ServerHandler + Send + 'static`, `M: SessionManager`, and `RequestBody::Data: Send + 'static`; its response is `BoxResponse`, error is `Infallible`, and future is boxed (rmcp v3.9.0, `crates/rmcp/src/transport/streamable_http_server/tower.rs:1494-1504`). `BoxResponse` is `Response<BoxBody<Bytes, Infallible>>` (rmcp v3.9.0, `crates/rmcp/src/transport/common/server_side_http.rs:21`); the service is Clone (explicit implementation, rmcp v3.9.0, `crates/rmcp/src/transport/streamable_http_server/tower.rs:1483-1492`). `Full<Bytes>` is the request body Jack itself supplies to rmcp. The boxed response body satisfies Jack's body bounds; `Infallible` converts to the boxed error type. These signature observations indicate direct composition without an adapter.

For a network listener, Hyper's `Incoming` is the incoming body type and Jack's generic accepts it under its declared bounds. The repository's existing Hyper/Tower pattern wraps a Tower service in `TowerToHyperService` and serves through `TokioIo` (`interop/rust/src/bin/interop_server.rs:441-448`). Illustrative only:

```rust
let rmcp = StreamableHttpService::new(
    || Ok(MyHandler::new()),
    Arc::new(MySessionManager::new()),
    config,
);
let jack = JackLayer::new(handler_config).layer(rmcp);
let hyper_service = hyper_util::service::TowerToHyperService::new(jack);
// Serve hyper_service over Hyper using TokioIo.
```

Here `MyHandler`, `MySessionManager`, and the configuration values are illustrative concrete types; this sketch is not compiled. `mcp-jack`'s feature dependency list is at `rust/Cargo.toml:16-19`; Tokio is optional through the client-http feature (`rust/Cargo.toml:19,38-41`). A fixture that embeds HTTP must explicitly declare its runtime and Hyper/Hyper-util dependencies and features rather than assume mcp-jack enables them.

## 2. Response limits, streams, and bounded behavior

`HandlerConfig.max_response_bytes` documents a response cap (`rust/src/server/http/mod.rs:116-124`); the HTTP wrapper's limits and defaults are described at `rust/src/server/http/mod.rs:3-20`. `buffer_body` enforces buffering/capping (`rust/src/server/http/mod.rs:575-606`). The forwarding path checks SSE before buffering and signs a 501 refusal for `text/event-stream` without polling the body (`rust/src/server/http/forward.rs:164-205`, especially `:167-196`). Thus an rmcp SSE response is refused, not converted into JSON or delivered as a stream. The no-SSE GET refusal is distinct: operations documentation maps Go's 501 `streaming_unsupported` to upstream SSE, and notes TypeScript initialize may use SSE even in JSON mode (`docs/operations.md:294-307`).

The byte cap is not a time bound: a body not labeled event-stream that never emits a frame, or emits only empty frames, can still wait indefinitely (`rust/src/server/http/mod.rs:11-18`). The Jack wrapper itself has no built-in deadline. A deployment should wrap the whole service with an explicit deadline and align request body caps. rmcp's default request body cap is 4 MiB (rmcp v3.9.0, `crates/rmcp/src/transport/streamable_http_server/tower.rs:226-235`); Jack's default request limit is 1 MiB (`rust/src/server/http/mod.rs:83-90,113-124`). Configure them coherently and retain the smaller security boundary unless the owner approves another limit.

## 3. Protocol mode and request/response behavior

rmcp v3.9.0 supports legacy and modern versions; `LATEST` is 2026-07-28 (`crates/rmcp/src/model.rs:168-209`). Its server config defaults to stateful legacy mode, non-JSON responses, localhost/127.0.0.1/::1 allowed hosts, empty/disabled allowed origins, and a 4 MiB request cap (`crates/rmcp/src/transport/streamable_http_server/tower.rs:226-235,336-347`). Configuration methods include `with_legacy_session_mode`, `with_json_response`, and host/origin configuration (`crates/rmcp/src/transport/streamable_http_server/tower.rs:364-410`). All ranges are rmcp v3.9.0.

For the bounded example, choose legacy 2025-11-25, `legacy_session_mode: false`, and `json_response: true`. The existing fixture explicitly selects `ProtocolVersion::V_2025_11_25` (`tools/mcp-e2e/rust/src/bin/server.rs:48-53`) and configures `.with_legacy_session_mode(false).with_json_response(true).with_allowed_hosts(["upstream"])` (`tools/mcp-e2e/rust/src/bin/server.rs:123-131`). The fixture README and compatibility design describe it as no-session JSON mode (`tools/mcp-e2e/README.md:3-19`; `docs/design/mcp-compatibility.md:73-92`). This is evidence for the chosen configuration, not proof that this fixture's gateway path is same-process Jack embedding.

Behavioral constraints from pinned source:

- In stateless JSON mode, terminal-first tool output can be JSON; if a notification precedes the terminal result, rmcp falls back to SSE. Subscriptions/listen remain streaming. Require tools in this profile to return terminal-first results without required intermediate notifications and prohibit subscriptions/listen (rmcp v3.9.0, `crates/rmcp/src/transport/streamable_http_server/tower.rs:1678-1698,2425-2455`; verify exact runtime behavior in the proposed fixture).
- Stateless GET with no event store returns 405; a stateful GET asking for SSE reaches Jack's signed 501 path (rmcp v3.9.0, `crates/rmcp/src/transport/streamable_http_server/tower.rs:1950-1965`; local SSE path above).
- POST `Accept: text/event-stream` alone is insufficient and rmcp returns 406; POST must advertise both `application/json` and `text/event-stream` (rmcp v3.9.0, `crates/rmcp/src/transport/streamable_http_server/tower.rs:2130-2145`). With the required dual Accept header, JSON-response mode selects a terminal-first JSON response. It does not prevent a tool from producing SSE; Jack then refuses that `text/event-stream` response with signed 501 (`rust/src/server/http/forward.rs:167-196`; rmcp response behavior at `crates/rmcp/src/transport/streamable_http_server/tower.rs:2425-2455`, v3.9.0). POST JSON content type is required or rmcp returns 415 (rmcp v3.9.0, `crates/rmcp/src/transport/streamable_http_server/tower.rs:2148-2165`).
- The default stateful legacy initialize path creates a session and emits SSE; Jack refuses that response, so the caller does not receive the session id. This follows from rmcp's stateful/session branch (rmcp v3.9.0, `crates/rmcp/src/transport/streamable_http_server/tower.rs:2170-2295`) and Jack's content-type refusal (`rust/src/server/http/forward.rs:167-196`).

Jack defaults to its legacy profile (`rust/src/server/http/mod.rs:183-213,242-249`); compatibility documentation describes profile behavior (`docs/compatibility.md:7-18,23-27`). rmcp's modern default/latest is not evidence of a tested pairing with Jack's default legacy profile. Modern use requires explicitly selecting Jack `Modern` or `Both`, and a separate compatibility gate.

## 4. Verified identity in tool handlers

The forwarder inserts verified identity into request extensions after verification (`rust/src/server/http/forward.rs:96-105,149-150`). `VerifiedIdentity` exposes identity/admin accessors while its constructor is crate-private (`rust/src/server/identity.rs:4-49`); there is no public constructor for forged identity. rmcp documents insertion of `http::request::Parts` into MCP request extensions (rmcp v3.9.0, `crates/rmcp/src/transport/streamable_http_server/tower.rs:1397-1450`). It copies request extensions into `RequestContext.extensions` (rmcp v3.9.0, `crates/rmcp/src/service.rs:1597-1604`); `RequestContext` exposes extensions (`crates/rmcp/src/service.rs:1212-1218`) and `Extension<T>` is an extractor (`crates/rmcp/src/handler/server/common.rs:200-217`), all from rmcp v3.9.0. The request-parts injection sites distinguish paths: stateless request handling injects parts at `tower.rs:1678-1685` and `2425-2455`; stateful session request handling injects parts at `tower.rs:2218-2230` and `2303-2311` (rmcp v3.9.0). These are the source paths for stateless and stateful tool request context.

A tool can therefore extract parts and inspect `parts.extensions.get::<VerifiedIdentity>()`, or use `RequestContext<RoleServer>` and inspect `ctx.extensions.get::<http::request::Parts>()`. The identity lookup and authorization example below are sketches, **UNVERIFIED** until compiled and tested:

```text
UNVERIFIED pseudocode; not compiled.
identity = parts.extensions.get::<VerifiedIdentity>()
for each state-changing tool:
    if identity is missing OR identity.admin() is false: return MCP error
for each read-only tool:
    admin is not required
```

The extractor and error/result types are illustrative and **UNVERIFIED**; no compilation or runtime behavior is claimed.

## 5. Host, origin, protocol, and header guards

rmcp validates Host against allowed hosts and validates Origin when an allowlist is configured (rmcp v3.9.0, `crates/rmcp/src/transport/streamable_http_server/tower.rs:1339-1384`, called from request handling at `:1950-1965`). Defaults allow only loopback hostnames and leave Origin validation disabled because the origins list is empty (rmcp v3.9.0, `tower.rs:226-235,336-347`). Configure exact approved onion/custom host authorities (including intended ports), and explicit origins where required; do not broadly allow arbitrary hosts.

`MCP-Protocol-Version`, session, and content rules remain rmcp guards. A supplied version must be known; absent header on legacy requests defaults to 2025-03-26, and initialize version signals must agree (rmcp v3.9.0, `crates/rmcp/src/transport/streamable_http_server/tower.rs:428-460,680-715`). Stateful legacy follow-up requests require the session id issued at initialize; stateless mode does not require a session (rmcp v3.9.0, `tower.rs:2170-2295`). The stateless-required toggle defaults false (rmcp v3.9.0, `tower.rs:297-326`).

No blanket unknown-header rejection was found in the inspected request paths; rmcp preserves request parts in extensions (source paths in §4). `Jack-Auth` and related headers are not rmcp standard headers. Jack signs method, target, audience, key id, timestamp, nonce and body hash, not Host, Origin, Accept, protocol version or session headers (`spec/01-authentication.md:41-64`). Treat those headers only as routing/SDK guards, not authenticated identity. Authorization must use the inserted `VerifiedIdentity`, never a client-supplied identity header.

## 6. Existing evidence and limits of transfer

The existing Rust E2E fixture pins rmcp 3.9.0 and selects 2025-11-25 (`tools/mcp-e2e/rust/src/bin/server.rs:48-53`); its README describes no-session JSON mode (`tools/mcp-e2e/README.md:3-19`). But it runs rmcp behind the Go gateway over a Unix socket, not same-process/TCP/in-process Jack embedding, and excludes SSE, sessions, cancellation, and modern protocol (`tools/mcp-e2e/README.md:74-103`). It proves none of those embedding paths. Treat the constructor/bounds analysis in §1 as source inspection only.

## 7. Proposed implementation and validation plan (not authorized edits)

1. Add a new isolated fixture crate under `tools/`, with its own `Cargo.lock`; depend on `rmcp = "=3.9.0"` with the `transport-streamable-http-server` feature (as `tools/mcp-e2e/rust/Cargo.toml:17-21` does) and local mcp-jack by path. Pin its runtime, Hyper/Hyper-util, and any other direct dependencies exactly. Do not modify existing fixture or production manifests as part of this design.
2. Create a minimal server using `StreamableHttpService`, Jack `JackLayer`, and a Hyper listener. Configure legacy 2025-11-25, stateless JSON, exact allowed Host entries, coherent body caps, and a whole-service deadline. Offer one read-only tool and one state-changing admin-only tool; prohibit SSE-producing/subscription tools in this profile.
3. Add an isolated CI fixture gate. Prefer a dedicated `mcp-rmcp-embedding` job, modeled on `.github/workflows/ci.yml:468-516`'s isolated `mcp-compat-e2e` fixture/locked release build and `:582-604`'s separately packaged consumer pattern. Do not put it in `consumer-rust`: this is an SDK server + HTTP embedding fixture, not a package consumer test. Alternative: add a separate isolated step to `mcp-compat-e2e`; keep its lockfile/build distinct and explain the ownership choice.
4. Test over in-process TCP with a signed client request reaching the read tool; unsigned request refused; non-admin changing-tool call rejected; replay refused. Exercise POST with both required Accept media types and verify JSON terminal result. Verify stateful/SSE initialize or GET receives signed 501, stateless GET without event store receives 405, and SSE-producing tool behavior cannot be mistaken for JSON success. Record status, content type, signature, tool invocation counts and bounded deadlines. These are future assertions, not results.
5. Keep modern profile, sessions, cancellation, SSE delivery, and broader SDK interoperability out of the first acceptance claim. Expand only with separate tests and explicit profile decisions.

The repository's current `mcp-compat-e2e` workflow is at `.github/workflows/ci.yml:468-516`; consumer-rust packaging/testing is at `:582-604`. Neither supplies evidence for this same-process embedding proposal.

## Owner questions (plain language; recommendations)

1. **Should the first fixture lock rmcp 3.9.0 and MCP 2025-11-25, with no sessions and no tool SSE?** Recommendation: yes; this is the bounded JSON profile supported by the inspected fixture and avoids Jack's SSE refusal.
2. **May the deployment use onion or custom Host names?** Recommendation: yes, only by explicitly adding approved authorities (including intended ports) to rmcp `allowed_hosts`; keep defaults otherwise.
3. **Should each changing tool enforce the verified identity's admin flag?** Recommendation: yes; missing identity or non-admin must return an MCP error. Do not add a Jack API for this.
4. **What deadline and response-size cap should apply?** Recommendation: wrap the whole Jack service in a deadline and align rmcp's request cap with Jack's 1 MiB default; the byte cap alone does not bound time.
5. **Where should the fixture run in CI: a dedicated job or an isolated step in `mcp-compat-e2e`?** Recommendation: dedicated `mcp-rmcp-embedding` job, for clear ownership and isolation; a separate step is acceptable only if it retains its own crate/lock/build boundary.
6. **Should Jack add a public identity-bridge API before API freeze?** Recommendation: no; request-parts extensions already expose verified identity to rmcp tools on the inspected paths.

## UNVERIFIED

- The Rust wiring sketch, exact constructors/imports/features, Hyper listener, and direct service composition have not been compiled or run.
- `Incoming` acceptance follows Jack's generic bounds; its concrete trait-bound satisfaction in the proposed dependency versions has not been compiled.
- Extraction of `VerifiedIdentity` through rmcp `Extension` or `RequestContext`, and the sample authorization policy, have not been compiled or exercised.
- The complete end-to-end request path, replay behavior, signatures, timeout enforcement, and stateful/stateless HTTP outcomes in an embedded fixture have not been tested.
- Exact 2025-11-25 pairing and tool policy are design recommendations, not conformance certification; no modern Jack/rmcp pairing is validated.
- Hyper/runtime feature selection, dependency resolution, MSRV, isolated CI cost, and workflow ownership remain to be decided and tested.
- How rmcp 3.9.0 selects between its legacy and modern protocol eras at runtime (a version constant versus a mode switch such as the legacy-session flag), and which modern guarantees `with_profile` on Jack's side adds, is not established here; only the legacy 2025-11-25 stateless JSON profile is proposed.
- No compilation, tests, package operations, generators or downloads were run for this document. The layout lint (`node tools/layout/check-layout.mjs --root .`) was run once after it was written and reported `layout ok: 1129 code files checked`.
