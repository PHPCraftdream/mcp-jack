# Rust API: target shape before the first release

## Premise and scope

`mcp-jack` is unpublished (`rust/Cargo.toml:1-5`); there are no external users or semver promise to preserve yet (task premise). Make the breaking public-API changes now, within unpublished 0.1.0, to reduce avoidable breaks after first release. This is an API-shape proposal only: no wire-format, signature-byte, fixture, or protocol changes. The document-only task did not change source.

## Compatibility classes and inventory

A declaration's visibility does not alone prove default-feature/root-export reachability. The following declaration audit summarizes relevant public consumers and implementors observed in Rust source; feature/export completeness is **UNVERIFIED**. Input means callers construct/configure it; SDK output means SDK returns it; enums are matched; traits are implemented by downstream code.

| Class | Examples and source locations | Compatibility rule to target |
|---|---|---|
| Input/config struct | The 11 in-scope structs in the next table. Other examples: `NativeCall`/`NativeResult` (`rust/src/server/verify/mod.rs:104,131`), `StreamVerifierConfig` (`rust/src/stream/verifier.rs:42`), `SenderConfig` (`rust/src/webhook/http/sender.rs:123`). | `#[non_exhaustive]` prevents downstream struct literals (and requires a constructor/builder); it does not make existing literals legal. Pair it with a usable `new`/builder. Private fields plus builder likewise require call-site migration now. |
| SDK output struct | `VerifyResult` (`rust/src/server/verify/mod.rs:668`), `PendingRequest` (`rust/src/server/verify/pending.rs:40`), `VerifiedIdentity` (`rust/src/server/identity.rs:22`), `HttpResponse` (`rust/src/client/transport.rs:70`), `ToolCatalog` (`rust/src/client/modern/projection.rs:222`), `DurableReceipt` (`rust/src/server/durable/durable_format.rs:76`). | Non-exhaustive output prevents downstream exhaustive destructuring; expose accessors, not an assumption all output values are non-constructible. Per-item annotations still require confirming actual consumption/export. |
| Matched enum | `Authentication`, `Profile`, `RefusalReason`, `ModernOutcome` (`rust/src/server/verify/pending.rs:17`; `rust/src/server/modern/mod.rs:15,76,211`); `PipeStop` (`rust/src/server/stream/pipe.rs:20`); `ClientError` (`rust/src/client/error.rs:197`); `StreamCode` (`rust/src/stream/mod.rs:60`). | A downstream exhaustive match can break on a new variant. `#[non_exhaustive]` requires wildcard matches and must be chosen per enum now; it does not prevent constructing existing variants. |
| Implementor trait | `NativeTools` (`rust/src/server/verify/mod.rs:139-141`), `StateStore` (`rust/src/server/registry/state.rs:166-189`), `Transport` (`rust/src/client/transport.rs:203-220`), `Signer` (`rust/src/client/request_signing/signer.rs:18-27`), `ResponseKeys` (`rust/src/server/response_keys.rs:86`), `AuditSink` (`rust/src/server/audit.rs:41`). | Adding a required method breaks implementors. Use a semantically sound default method or companion trait; sealing forecloses downstream implementations and is a deliberate policy choice, not a blanket fix. Preserve object safety where trait objects are used. |

This is a relevant-item audit, not a claim that every public type is exhaustive. Draft's broad inventory includes many public values but no use-site proof for each; complete generated/exported/feature-gated inventory remains **UNVERIFIED**.

| Input type | Declaration / actual fields / documented Go name or default | `#[non_exhaustive]` now? |
|---|---|---|
| `server::verify::Config` | `rust/src/server/verify/mod.rs:143-164`; `aud`, `state`, `nonces`, `audit`, `native`, `window_seconds`, `now`; docs map window to Go `Config.Window`, audience to `Config.Aud`. `window_seconds == 0` becomes default 30; allowed nonzero 1..=120. | Yes. Caller input; add constructor/builder in same breaking API migration. |
| `HandlerConfig` | `rust/src/server/http/mod.rs:106-126`; `verifier`, `server_key`, `max_body_bytes`, `max_response_bytes`; Go `HandlerConfig`; each byte limit zero means 1 MiB. | Yes; new builder/constructor, avoid forcing literals after release. |
| `RotatingHandlerConfig` | `rust/src/server/http/mod.rs:128-156`; `verifier`, `response_keys`, `max_body_bytes`, `max_response_bytes`; Go `HandlerConfig.ResponseKeys`; both limits zero mean 1 MiB. | Yes; separate rotating construction remains clear. |
| `StreamConfig` | `rust/src/server/http/stream_layer.rs:30-37`; `verifier`, `server_key`, `max_body_bytes`, `max_response_bytes`, `streams`; no explicit Go name/default comment at declaration. HTTP limit meanings as above. | Yes; pair with builder. |
| `RotatingStreamConfig` | `rust/src/server/http/stream_layer.rs:39-47`; `verifier`, `response_keys`, `max_body_bytes`, `max_response_bytes`, `streams`; no explicit Go name/default comment. | Yes; preserve static/rotating distinction. |
| `StreamPipeConfig` | `rust/src/server/stream/pipe.rs:36-58`; `sid`, `open_sig`, `open_ts`, `limits`, `request_id`, `method`, `cutoff`, `started_ms`, `signer`; docs associate stream IDs/signature/limits with spec clauses, no Go field name/default documented. | Yes; internal-looking low-level public input still warrants evolution room, with constructor/builder. |
| `StreamVerifierConfig` | `rust/src/stream/verifier.rs:40-58`; `keys`, `request_sig`, `window_seconds`, `frame_max_bytes`, `stream_idle_ms`, `consumer`, `now`; documented defaults: window <=0 means 30, frame cap 0 means default cap, idle <=0 means default. | Yes; constructor plus builder options. |
| `client::rpc::Config` | `rust/src/client/rpc.rs:14-36`; `base_url`, `aud`, `signer`, `server_key`, `transport`, `now`, `nonce`, `window_seconds`; no Go `Config` name cited. `now` and `nonce` default to system time and OS randomness; response tolerance <=0 selects default window. | Yes; builder/new API instead of literals. |
| `SenderConfig` | `rust/src/webhook/http/sender.rs:121-134`; `allowed_ranges`, `max_body_bytes`, `verification_ttl_ms`; no Go name/default specified there. | Yes; builder. |
| `ReceiverConfig` | `rust/src/webhook/receiver/config.rs:87-148`; `window`, `max_body`, `dedup_retention`, `enforce_server_identity`, `mcp_server_kid`, `mcp_server_public_key`, `keys`, `key_source`, `require_webhook_key_check`, `webhook_key_tool`, `jack`, `secrets`, `routed`; defaults 300s, 262144 bytes, 1200s; others false/empty/None (`:150-169`). | Yes; `Default` plus builder retains those defaults. |
| `JackConfig` | `rust/src/webhook/receiver/config.rs:36-56`; `aud`, `window`, `callback_urls`; default empty audience, 30s window, no callback URLs (`:58-67`). | Yes; builder preserves `Default`. |

### Target API alternatives and recommendation

**A — public fields + `#[non_exhaustive]` + `new(required...)` + setters:** consumers cannot use literals; constructors/setters must cover every field and invalid combinations. Downstream field reads remain possible, but the API still exposes field-level evolution and is awkward for required trait objects / numerous settings. **B — private fields + builder + `build`/`try_build`:** explicit, discoverable configuration, coherent validation and easier later evolution; requires migrating field reads/writes and construction now. Recommend B for all 11; use `try_build` where validation can fail and `build` otherwise. Do not layer new escape hatches onto obsolete literals: `with_server_keys`, `with_webhook_keys`, Linux `with_durable_nonces`, and `with_profile` become ordinary verifier/layer builder options. Keep existing semantics and static/rotating distinction. Also reconcile the existing proposal signature sketches below with those APIs before coding.

Document-only signature sketch; aliases such as `Clock`, `StreamOptions`, `StreamLimits`, and `RotationResponseKey` retain the exact existing source types:

```rust
// Builder type names and field-level methods remain proposal-specific; current calls remain the source reference.
pub struct VerifierBuilder { /* private */ }
impl VerifierBuilder {
    pub fn new(aud: impl Into<String>, state: Arc<dyn StateStore>) -> Self;
    pub fn nonces(self, v: Arc<dyn NonceAdmission>) -> Self;
    pub fn audit(self, v: Option<Arc<dyn AuditSink>>) -> Self;
    pub fn native_tools(self, v: Option<Arc<dyn NativeTools>>) -> Self;
    pub fn window_seconds(self, v: i64) -> Self; // 0 => 30; valid 0 or 1..=120
    pub fn now(self, v: Clock) -> Self;
    pub fn server_keys(self, v: Arc<dyn NativeTools>) -> Self;
    pub fn webhook_keys(self, v: Arc<dyn NativeTools>) -> Self;
    #[cfg(target_os = "linux")] pub fn durable_nonces(self, v: Arc<SharedDurableNonceStore>) -> Self;
    pub fn try_build(self) -> Result<Verifier, VerifierConfigError>;
}
impl Verifier {
    pub fn new(config: Config) -> Result<Self, VerifierConfigError>;
}
pub struct HandlerBuilder { /* verifier, static signer, limits private */ }
impl HandlerBuilder { pub fn new(verifier: Arc<Verifier>, server_key: ServerSigningKey) -> Self;
    pub fn max_body_bytes(self, n: usize) -> Self; // 0 => 1 MiB
    pub fn max_response_bytes(self, n: usize) -> Self; // 0 => 1 MiB
    pub fn build(self) -> JackLayer; }
pub struct RotatingHandlerBuilder { /* private */ }
impl RotatingHandlerBuilder { pub fn new(verifier: Arc<Verifier>, keys: Arc<dyn ResponseKeys>) -> Self;
    pub fn max_body_bytes(self, n: usize) -> Self; pub fn max_response_bytes(self, n: usize) -> Self;
    pub fn build(self) -> JackLayer; }
pub struct StreamLayerBuilder { /* static/rotating profile, verifier, signer/provider, limits, streams */ }
impl StreamLayerBuilder { pub fn new(verifier: Arc<Verifier>, key: ServerSigningKey) -> Self;
    pub fn rotating(verifier: Arc<Verifier>, keys: Arc<dyn ResponseKeys>) -> Self;
    pub fn max_body_bytes(self, n: usize) -> Self; pub fn max_response_bytes(self, n: usize) -> Self;
    pub fn streams(self, v: StreamOptions) -> Self; pub fn profile(self, v: Profile) -> Self;
    pub fn build(self) -> StreamLayer; }
pub struct StreamPipeBuilder { /* private */ }
impl StreamPipeBuilder { pub fn new(sid: String, open_sig: String, open_ts: i64,
    limits: StreamLimits, method: String, started_ms: i64, signer: Arc<dyn StreamSigner>) -> Self;
    pub fn request_id(self, v: Option<String>) -> Self; pub fn cutoff(self, v: Option<i64>) -> Self;
    pub fn build(self) -> StreamPipe; }
pub struct StreamVerifierBuilder { /* keys, request_sig required; other fields private */ }
impl StreamVerifierBuilder { pub fn new(keys: BTreeMap<String, RotationResponseKey>, request_sig: impl Into<String>) -> Self;
    pub fn window_seconds(self, v: i64) -> Self; pub fn frame_max_bytes(self, v: usize) -> Self;
    pub fn stream_idle_ms(self, v: i64) -> Self; pub fn consumer(self, v: StreamConsumer) -> Self;
    pub fn now(self, v: Clock) -> Self; pub fn build(self) -> StreamVerifier; }
pub struct RpcClientBuilder { /* private */ }
impl RpcClientBuilder { pub fn new(base_url: impl Into<String>, aud: impl Into<String>, signer: Arc<dyn Signer>,
    server_key: [u8; 32], transport: Arc<dyn Transport>) -> Self;
    pub fn now(self, v: Clock) -> Self; pub fn nonce(self, v: NonceSource) -> Self;
    pub fn window_seconds(self, v: i64) -> Self; pub fn try_build(self) -> Result<Client, ClientError>; }
pub struct SenderBuilder { /* private */ }
impl SenderBuilder { pub fn new(transport: Arc<dyn WebhookTransport>, resolver: Arc<dyn HostResolver>,
    clock: Arc<dyn Clock>, gate: Arc<dyn EndpointVerifier>) -> Self; pub fn allowed_ranges(self, v: Vec<String>) -> Self;
    pub fn max_body_bytes(self, v: usize) -> Self; pub fn verification_ttl_ms(self, v: Option<i64>) -> Self;
    pub fn build(self) -> Sender; }
pub struct ReceiverBuilder { /* private; Default-equivalent initial state */ }
impl ReceiverBuilder { pub fn new() -> Self; pub fn window(self, v: i64) -> Self; pub fn max_body(self, v: usize) -> Self;
    pub fn dedup_retention(self, v: i64) -> Self; pub fn enforce_server_identity(self, v: bool) -> Self;
    pub fn mcp_server_kid(self, v: Option<String>) -> Self; pub fn mcp_server_public_key(self, v: Option<String>) -> Self;
    pub fn keys(self, v: Vec<WebhookKeyRecord>) -> Self; pub fn key_source(self, v: Option<Arc<dyn KeySource>>) -> Self;
    pub fn require_webhook_key_check(self, v: bool) -> Self; pub fn webhook_key_tool(self, v: Option<Value>) -> Self;
    pub fn jack(self, v: Option<JackConfig>) -> Self; pub fn secrets(self, v: Vec<ReceiverSecret>) -> Self;
    pub fn routed(self, v: Vec<String>) -> Self; pub fn try_build(self) -> Result<Receiver, WebhookError>; }
pub struct JackConfigBuilder { /* private */ }
impl JackConfigBuilder { pub fn new() -> Self; pub fn aud(self, v: impl Into<String>) -> Self;
    pub fn window(self, v: i64) -> Self; pub fn callback_urls(self, v: BTreeMap<String, String>) -> Self;
    pub fn build(self) -> JackConfig; }
```

`SenderBuilder` is initialized with the transport, resolver, clock, and required endpoint-verification gate that current `Sender::new` requires; its `build` returns the configured `Sender`. `ReceiverBuilder::try_build` returns a validated `Receiver`, not the config record. `JackConfigBuilder::build` returns the public nested `JackConfig` value. `Verifier::new` uses the actual source config item, `server::verify::Config`, whose source name within that module is `Config`; `VerifierConfig` is not a source type. Other `build` results in the sketch are the configured SDK type (`JackLayer`, `StreamLayer`, `StreamPipe`, `StreamVerifier`, or `Client`) rather than a private configuration record. Sketch signatures are proposals and must be reconciled with the source entry points and dependencies before implementation.


`ReceiverConfig` defaults and Jack defaults above must remain unchanged. `max_body_bytes`/`max_response_bytes` zero remains 1 MiB; verifier zero remains default 30 (constructor rejects outside 0..=120); stream verifier <=0/zero defaults retain documented meanings.

## Per-struct call-site counts

Method: narrow, separate per-type/per-directory searches were reviewed against candidate contexts based on returned independent evidence. Counts include only literal value expressions constructing the target struct; declarations, patterns, function return/type signatures, and unrelated `Config` values are excluded. Rust README examples/doctests count when they contain a literal construction. Constructor and builder invocations are not counted. These are manually inspected literal-expression counts, not raw search-match totals.

`rust/src` counts include inline test and doc examples as well as other source-tree code. `rust/tests` contains standalone integration tests. The six requested directories appear in the specified order; totals are computed across those columns.

| Type | rust/src | rust/tests | interop/rust | tools/consumer/rust | tools/mcp-e2e/rust | rust/README.md | Total |
|---|---:|---:|---:|---:|---:|---:|---:|
| `server::verify::Config` | 1 | 15 | 4 | 0 | 0 | 1 | 21 |
| `HandlerConfig` | 2 | 14 | 2 | 1 | 0 | 1 | 20 |
| `RotatingHandlerConfig` | 1 | 1 | 1 | 0 | 0 | 1 | 4 |
| `StreamConfig` | 0 | 1 | 1 | 0 | 0 | 0 | 2 |
| `RotatingStreamConfig` | 0 | 0 | 1 | 0 | 0 | 0 | 1 |
| `StreamPipeConfig` | 2 | 0 | 0 | 0 | 0 | 0 | 2 |
| `StreamVerifierConfig` | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| `client::rpc::Config` | 6 | 4 | 1 | 7 | 0 | 1 | 19 |
| `SenderConfig` | 6 | 0 | 1 | 0 | 0 | 0 | 7 |
| `ReceiverConfig` | 2 | 0 | 0 | 0 | 0 | 0 | 2 |
| `JackConfig` | 0 | 1 | 1 | 0 | 0 | 0 | 2 |

For verification, the `server::verify::Config` source literal is `rust/src/server/verify/tests/mod.rs:86`; integration examples include `rust/tests/durable_restart.rs:173,415,640`, `conformance/verify.rs:127`, `conformance/admin.rs:258`, `durable_nonce_vectors/main.rs:660`, `streams/smoke.rs:77`, `server/webhook_key_tool.rs:213`, `modern/server/wire_forward.rs:146`, `native_result.rs:127`, `mirror_refusal.rs:133`, `modern/vectors/wire_request.rs:279`, `server/http_layer/identity.rs:205`, `server/http_layer/mod.rs:181`, and `rotation/server/signing/mod.rs:358`. Interop examples are `interop/rust/src/bin/interop_server.rs:542`, `modern/server.rs:213`, `rotation_server.rs:270`, and `stream/server.rs:526`; README example is `rust/README.md:21`.

Other candidate/context checks included `HandlerConfig` source in `rust/src/server/http/stream_layer.rs` and the code example in `rust/src/server/http/mod.rs`; `RotatingHandlerConfig` construction in `stream_layer.rs` (the declaration in `http/mod.rs` is excluded); source `StreamConfig`/`RotatingStreamConfig` declarations only (no constructions); `StreamPipeConfig` constructions in `server/http/stream.rs` and `server/stream/tests/pipe.rs` (declaration in `server/stream/pipe.rs` excluded); and the `StreamVerifierConfig` literal in `stream/verifier.rs` (candidates in `client/stream/tests/mod.rs` and `stream/tests/verifier.rs` are declaration/return-type contexts). For `SenderConfig`, source literals are in `webhook/http/tests/verification.rs` (2), `rebinding.rs` (3), and `deadline.rs` (1), excluding the `sender.rs` declaration. For `ReceiverConfig`, source literals are in `receiver/tests/mod.rs` and `receiver/tests/dispatch.rs`; `rust/tests/webhook_vectors/receiver_family/receiver.rs` is a return type and excluded. `rust/tests/webhook_vectors/receiver_family/receiver.rs` and `interop/rust/src/bin/webhook/receiver.rs` contain the two `JackConfig` literals. The remaining per-directory literal counts are shown in the authoritative table above.

**Test migration impact:** `rust/tests` integration literal sites by input type are: `server::verify::Config` 15, `HandlerConfig` 14, `RotatingHandlerConfig` 1, `StreamConfig` 1, `RotatingStreamConfig` 0, `StreamPipeConfig` 0, `StreamVerifierConfig` 0, `client::rpc::Config` 4, `SenderConfig` 0, `ReceiverConfig` 0, and `JackConfig` 1. In addition, `rust/src` has literal sites in test/doc contexts; all literal construction sites in these contexts and in the integration tests must migrate to builders. These counts do not imply one distinct test file per construction.

Limitations: searches covered only the named source-tree paths, not macro-generated constructions or external consumers. Counts observe literal syntax only; constructor/builder use is intentionally outside scope. They are reviewed literal-expression counts, not raw match counts, and are approximate: for example a raw search for `HandlerConfig {` in `rust/tests` returns 17 matches against the 14 reviewed literal sites above (the difference is not itemised here). The implementation task recounts per struct before it starts; the numbers here only size the work (tens of call sites per main struct, a few dozen files).

### Per-item `#[non_exhaustive]` decisions

The decisions apply to downstream-facing types if their declarations are included in the supported public/export surface; export/feature completeness is not inferred from visibility alone. “Now” means before first release. For inputs, the selected private-field builder recommendation already blocks struct literals; annotation is still chosen explicitly as an API evolution signal where applicable.

| Item | Class | Source declaration | Decision | Rationale |
|---|---|---|---|---|
| `server::verify::Config` | input | `rust/src/server/verify/mod.rs:144` | Now | Evolution room; accompany with builder/constructor. |
| `HandlerConfig` | input | `rust/src/server/http/mod.rs:108` | Now | Can gain fields; replace literals with builder. |
| `RotatingHandlerConfig` | input | `rust/src/server/http/mod.rs:132` | Now | Same evolution need; keep rotating construction distinct. |
| `StreamConfig` | input | `rust/src/server/http/stream_layer.rs:31` | Now | Stream-layer configuration can grow; builder preserves defaults/profile. |
| `RotatingStreamConfig` | input | `rust/src/server/http/stream_layer.rs:41` | Now | Same, without merging static and rotating profiles. |
| `StreamPipeConfig` | input | `rust/src/server/stream/pipe.rs:37` | Now | Coordinated low-level fields; builder enables evolution. |
| `StreamVerifierConfig` | input | `rust/src/stream/verifier.rs:42` | Now | Settings/defaults may evolve; builder exposes options. |
| `client::rpc::Config` | input | `rust/src/client/rpc.rs:15` | Now | Transport, clock and nonce configuration can evolve; builder replaces literals. |
| `SenderConfig` | input | `rust/src/webhook/http/sender.rs:123` | Now | Limits/policies can evolve; builder replaces literals. |
| `ReceiverConfig` | input | `rust/src/webhook/receiver/config.rs:98` | Now | Large defaulted configuration may evolve; preserve `Default` through builder. |
| `JackConfig` | input | `rust/src/webhook/receiver/config.rs:42` | Now | Webhook-auth settings can evolve; preserve `Default` through builder. |
| `NativeCall` | input passed to implementor | `rust/src/server/verify/mod.rs:104` | Now | Downstream-provided call data may need fields; literals should not freeze shape. |
| `NativeResult` | implementor-produced result | `rust/src/server/verify/mod.rs:131` | Now | Result may gain metadata; avoid freezing downstream literal construction. |
| `NativeOptions` | input/config struct | `rust/src/server/native/mod.rs:31` | Now | Public configuration-shaped value; provide construction API if downstream-constructible. |
| `DurableStoreOptions` | input/config struct | `rust/src/server/durable/durable_store.rs:45` | Now | Public configuration-shaped value; provide construction API if downstream-constructible. |
| `StreamOptions` | input/options | `rust/src/server/stream/options.rs:16` | Now | Public stream options may grow; annotation requires non-exhaustive construction policy. |
| `StreamLimits` | input/options | `rust/src/server/stream/options.rs:40` | Now | Public limits may grow; annotation requires non-exhaustive construction policy. |
| `VerifyResult` | SDK output | `rust/src/server/verify/mod.rs:681` | Now | Avoid exhaustive field destructuring; expose accessors. |
| `PendingRequest` | SDK output | `rust/src/server/verify/pending.rs:40` | Now | Issued value may gain state; use methods/accessors. |
| `VerifiedIdentity` | SDK output | `rust/src/server/identity.rs:22` | Now | Returned identity may gain claims; avoid exhaustive destructuring. |
| `HttpResponse` | SDK output | `rust/src/client/transport.rs:70` | Now | Transport result may gain metadata; retain accessors. |
| `ToolCatalog` | SDK output | `rust/src/client/modern/projection.rs:222` | Now | Projection output may gain state; avoid exhaustive destructuring. |
| `DurableReceipt` | SDK output | `rust/src/server/durable/durable_format.rs:76` | Now | Lifecycle receipt may gain fields; protect exhaustive patterns. |
| `Authentication` | matched enum | `rust/src/server/verify/pending.rs:17` | Now | New variants should require wildcard handling. |
| `Profile` | matched enum | `rust/src/server/modern/mod.rs:15` | Now | Variants may evolve; require wildcard matches. |
| `RefusalReason` | matched enum | `rust/src/server/modern/mod.rs:76` | Now | Refusal taxonomy can grow; require wildcard matches. |
| `ModernOutcome` | matched enum | `rust/src/server/modern/mod.rs:211` | Now | Outcome variants can evolve; require wildcard matches. |
| `PipeStop` | matched enum | `rust/src/server/stream/pipe.rs:20` | Now | Stop causes can grow; require wildcard matches. |
| `ClientError` | matched enum | `rust/src/client/error.rs:197` | Now | Failure taxonomy can grow; require wildcard matches. |
| `StreamCode` | matched enum | `rust/src/stream/mod.rs:60` | Now | Result codes can grow; require wildcard matches. |
| `NativeTools` | implementor trait | `rust/src/server/verify/mod.rs:139` | Not applicable / do not add | Trait annotation does not solve method compatibility; add semantically sound defaults or a companion trait. |
| `StateStore` | implementor trait | `rust/src/server/registry/state.rs:174` | Not applicable / do not add | Preserve implementations; use sound default/companion methods. |
| `Transport` | implementor trait | `rust/src/client/transport.rs:203` | Not applicable / do not add | Preserve downstream transports; use defaults/companion methods. |
| `Signer` | implementor trait | `rust/src/client/request_signing/signer.rs:18` | Not applicable / do not add | Preserve signer implementations; avoid new required methods. |
| `ResponseKeys` | implementor trait | `rust/src/server/response_keys.rs:86` | Not applicable / do not add | Preserve custom providers; extend via defaults/companion trait. |
| `AuditSink` | implementor trait | `rust/src/server/audit.rs:41` | Not applicable / do not add | Preserve sinks; use default/companion extension. |
| `HostResolver` | implementor trait | `rust/src/webhook/http/transport.rs:57` | Not applicable / do not add | Implementor contract; use defaults/companion methods. |
| `WebhookTransport` | implementor trait | `rust/src/webhook/http/transport.rs:185` | Not applicable / do not add | Implementor contract; use defaults/companion methods. |
| `EndpointVerifier` | implementor trait | `rust/src/webhook/verification/gate.rs:163` | Not applicable / do not add | Implementor contract; use defaults/companion methods. |
| `DocumentFetcher` | implementor trait | `rust/src/webhook/verification/document.rs:193` | Not applicable / do not add | Implementor contract; use defaults/companion methods. |
| `StreamSigner` | implementor trait | `rust/src/stream/signer.rs:18` | Not applicable / do not add | Implementor contract; use defaults/companion methods. |
| `StreamBody` | implementor trait | `rust/src/client/stream/source.rs:24` | Not applicable / do not add | Implementor contract; use defaults/companion methods. |
| `StreamSource` | implementor trait | `rust/src/client/stream/source.rs:32` | Not applicable / do not add | Implementor contract; use defaults/companion methods. |

External input/config structs other than the 11-item builder scope identified in this pass include `NativeCall`, `NativeResult`, `StreamOptions`, `StreamLimits`, `NativeOptions`, and `DurableStoreOptions` (itemized above). `NativeOptions` and `DurableStoreOptions` are configuration-shaped declarations; downstream construction/export reachability is **UNVERIFIED**, so the Now recommendation is conditional on their inclusion in the supported surface. Traits are not annotated `#[non_exhaustive]`; adding compatible default methods or a companion trait is the extension mechanism, while new required methods break implementors. This relevant-item inventory is not an exhaustive export/use-site audit; completeness remains **UNVERIFIED**.


## Nonce admission design

Volatile `NonceStore` uses a mutex for atomic `(kid, nonce)` check/insert; pair is live through equality (`now <= retain_until`), purge removes only `< now`, replay does not extend retention (`rust/src/server/registry/nonce.rs:36-73`). Verifier checks signature before recording (`rust/src/server/verify/mod.rs:365-394,431-453`). The Linux durable store has explicit lifetime ownership, reserve before dispatch, lease/close/fence, and recovery semantics—not a boolean callback (`rust/src/server/durable/durable_store.rs:695-697,835-905`; `docs/design/restart-replay.md:24-48`; `docs/operations.md:215-225`).

Propose a `nonces` option on `VerifierBuilder` replacing the current `Arc<NonceStore>` field in `server::verify::Config` with `Arc<dyn NonceAdmission>` (new breaking API), plus `fn check_and_record(&self, kid: &str, nonce: &str, now: i64, retain_until: i64) -> Result<NonceDecision, NonceAdmissionError>`, where `NonceDecision::{Recorded, Replay}`. This operation must be atomic check-and-insert. Errors distinguish confirmed no-commit/refusal from unknown commit outcome; only a confirmed `Recorded` authorizes dispatch, replay rejects, and any uncertain outcome fails closed and must not dispatch/retry. Preserve inclusive retention, purge semantics, and no replay extension. Proposed error type is typed and non-exhaustive; exact variants/payload and public names require review. **UNVERIFIED:** precise mapping from volatile/durable failures to verifier wire refusal codes.

Options:

1. **Trait only, memory default (recommend):** adapt `NonceStore`; keep durable profile as the existing explicit Linux implementation with its stronger leases and recovery; cost is an adapter/trait and a clear boundary between semantics. Risk: a simple trait cannot represent all durable transaction/recovery lifecycle; never claim it does.
2. **Trait plus rotation/lease store abstraction:** expose reservation receipts, finish/lease, close and recovery through a richer API. Cost and surface grow substantially; risk of misrepresenting current backend-specific recovery rules. Choose only if application-provided durable backends are explicitly required.
3. **Async trait:** permit async I/O stores; requires async verifier/authentication propagation and runtime-facing changes. Cost touches request pipeline; risk of changing scheduling/dispatch contracts. No async requirement found; prefer synchronous initially.

Current verifier/registry/durable calls are synchronous (`rust/src/server/verify/mod.rs:431-453`; durable reservation `rust/src/server/durable/durable_store.rs:888-905`). A synchronous database adapter can block a request executor/thread and needs bounded latency/appropriate integration; async is not free. Linux durable implementation stays opt-in and retains owner exclusion, commit acknowledgment, leases and recovery; it must not be flattened to `NonceAdmission`'s simple boolean-like decision. Default remains in-memory. Footguns: don't record before signature; don't dispatch after failure/unknown outcome; don't renew expiry on replay; don't evict live entries; don't silently recover corrupt/missing/unsafe state as empty; don't imply cluster safety from a mutex.

Go already has an admission abstraction and durable reserve seam (`server/verify.go:90-101`; `server/internal/verify/admission.go:34-77`); TS has synchronous `checkAndRecord` (`ts/src/server/registry/nonce.ts:18`) and a distinct durable admission (`ts/src/server/durable/admission.ts:124`). Recommend semantic parity (atomic admission, retention, fail-closed) but **not** force Rust to mirror Go/TS signatures or storage formats; Rust's richer durable receipt/lease lifecycle needs its own seam. Whether cross-SDK abstraction parity is desired: owner decision.

## Typed verifier error

Current `Verifier::new` returns `Result<Self, String>` and validates empty/control-character audience and window outside 0..=120, then maps zero to default (`rust/src/server/verify/mod.rs:197-215`). Proposed replacement in the breaking pre-release API:

```rust
#[non_exhaustive]
#[derive(Debug)]
pub enum VerifierConfigError {
    EmptyAudience,
    AudienceControlCharacter,
    InvalidWindow,
}
impl std::fmt::Display for VerifierConfigError { /* hand-written stable messages */ }
impl std::error::Error for VerifierConfigError {}
impl Verifier { pub fn new(config: Config) -> Result<Self, VerifierConfigError>; }
```

This replaces, rather than preserves, the `String` result. Hand-writing `Display`/`Error` adds no dependency. `rust/Cargo.toml:21-29` has no `thiserror`; adding it requires owner approval. The source search for public `Result<_, String>` and public borrowed-string errors found only `Verifier::new`; other `Result<String, Error>` / `Result<&str, Error>` use typed errors (e.g. `rust/src/user_key/transfer.rs:395`). Private `Receiver::verify -> Result<Verified, &'static str>` is not public API (`rust/src/webhook/receiver/state.rs:534`). Search was textual, not compiler-derived; additional macro-generated results **UNVERIFIED**.

## Invariants

No wire-byte or signature-byte change: builder migration only changes Rust construction, not protocol input or serialization. Preserve exact defaults and zero conventions listed above, including `max_body_bytes`/response limit zero => 1 MiB and verifier zero window => default. Keep cross-language fixture bytes and values unchanged; fixture source is outside this documentation change. Preserve verification ordering: signature before nonce admission, replay before dispatch (`rust/src/server/verify/mod.rs:365-394,431-453`; `spec/01-authentication.md:66-90`). These are design requirements; this task did not execute runtime or fixture validation.

## Recommendation and ordered review plan

**Five-line recommendation**
1. Make all 11 input structs private-field builder APIs before first publication.
2. Mark each selected input/output/enum non-exhaustive now, with constructor/accessor/wildcard rationale.
3. Replace verifier string error with non-exhaustive typed error; keep default nonce storage in memory.
4. Add a separate synchronous nonce-admission trait; retain Linux durable leases/recovery as explicit opt-in.
5. Preserve every wire byte, signature byte, default, zero rule and shared fixture.

| Order/task | Files to review/change if approved | Recommendation / owner question |
|---|---|---|
| 1. Confirm API/export and counts | `rust/src/**`, `rust/tests/**`, `interop/rust/**`, `tools/consumer/rust/**`, `tools/mcp-e2e/rust/**`, `rust/README.md` | Independently spot-check counts and export coverage; external consumers are unknown. |
| 2. Builder shape (#283 after #286) | The 11 declaration files named in input inventory and their constructor/call sites | **Recommendation / owner question:** use private fields plus builders (B; recommend) or public fields plus `#[non_exhaustive]`, required constructor and setters (A)? Approve names and validation. `ServerSigningKey` is intended from parallel work; compilation/signature details pending. |
| 3. Non-exhaustive policy | Public enum/output declarations cited above and each of 11 inputs | **Recommendation / owner question:** apply `#[non_exhaustive]` to each listed input, output (`VerifyResult`, `PendingRequest`, `VerifiedIdentity`, `HttpResponse`, `ToolCatalog`, `DurableReceipt`) and matched enum (`Authentication`, `Profile`, `RefusalReason`, `ModernOutcome`, `PipeStop`, `ClientError`, `StreamCode`) as itemized above, or select a narrower set? The table says `Now` individually for each named input/output/enum. |
| 4. Nonce abstraction (#286 first) | `rust/src/server/verify/mod.rs`, `rust/src/server/registry/nonce.rs`, `rust/src/server/durable/**` | **Recommendation / owner question:** implement atomic admission trait only, leaving rotation/lease stores and durable lifecycle separate (recommend), or include rotation stores/leases in the new abstraction? |
| 5. Execution model/parity | Same Rust nonce files; compare `server/internal/verify/admission.go`, `ts/src/server/**` | **Recommendation / owner question:** synchronous (recommend for the current pipeline) or async? Separately, mirror Go/TS APIs/signatures or match semantics only (recommend)? |
| 6. Error contract | `rust/src/server/verify/mod.rs`, `rust/Cargo.toml` only if dependency proposed | Approve typed variants and hand-written `Display`/`Error`; `thiserror` requires owner approval. |
| 7. Acceptance after implementation | Rust tests, interop/consumer suites, cross-language fixtures, release CI | #286 precedes #283 per task direction; RC re-runs each applicable suite and approved layout lint. Exact RC matrix **UNVERIFIED**. |

## Unverified items

- Export coverage, exact builder names, constructor validation beyond observed verifier behavior, and public error payload details require approval.
- Durable trait-to-wire refusal mapping, async demand, owner preference for Go/TS API/signature parity, and choice of which enums receive `#[non_exhaustive]` are **UNVERIFIED**.
- #286/#283 ordering and overlap are task-provided, not independently checked; exact RC matrix is **UNVERIFIED**.
- Representative output/enum annotation choices and implementor-trait non-annotation decisions are tabulated per item above; export coverage and owner approval remain open.
