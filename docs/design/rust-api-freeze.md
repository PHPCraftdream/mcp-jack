# Rust API: target shape before the first release

## Premise and scope

`mcp-jack` is unpublished (`rust/Cargo.toml:1-5`); there are no external users or semver promise to preserve yet (task premise). Make breaking public-API changes within unpublished 0.1.0 to reduce avoidable breaks after first release. This is an API-shape document only: no wire-format, signature-byte, fixture, or protocol changes. Task #300 concerns server-side input/config builders only; #301/#302 remain non-goals here. The six selected server-side records are `server::verify::Config`, `HandlerConfig`, `RotatingHandlerConfig`, `StreamConfig`, `RotatingStreamConfig`, and `StreamPipeConfig`. Other input, output, enum, and implementor-trait recommendations below are separate recommendations, not work claimed by #300.

## Compatibility classes and inventory

A declaration's visibility does not alone prove default-feature/root-export reachability. The following declaration audit summarizes relevant public consumers and implementors observed in Rust source; feature/export completeness is **UNVERIFIED**. Input means callers construct/configure it; SDK output means SDK returns it; enums are matched; traits are implemented by downstream code.

| Class | Examples and source locations | Compatibility rule to target |
|---|---|---|
| Input/config struct | The six selected server-side structs in the next table. Other examples: `NativeCall`/`NativeResult` (`rust/src/server/verify/mod.rs`), `StreamVerifierConfig` (`rust/src/stream/verifier.rs`), `SenderConfig` (`rust/src/webhook/http/sender.rs`). | `#[non_exhaustive]` prevents downstream struct literals (and requires a constructor/builder); pair it with a usable `new`/builder. Other input recommendations remain recommendations, not work claimed for task #300. |
| SDK output struct | `VerifyResult` (`rust/src/server/verify/mod.rs:668`), `PendingRequest` (`rust/src/server/verify/pending.rs:40`), `VerifiedIdentity` (`rust/src/server/identity.rs:22`), `HttpResponse` (`rust/src/client/transport.rs:70`), `ToolCatalog` (`rust/src/client/modern/projection.rs:222`), `DurableReceipt` (`rust/src/server/durable/durable_format.rs:76`). | Non-exhaustive output prevents downstream exhaustive destructuring; expose accessors, not an assumption all output values are non-constructible. Per-item annotations still require confirming actual consumption/export. |
| Matched enum | `Authentication`, `Profile`, `RefusalReason`, `ModernOutcome` (`rust/src/server/verify/pending.rs:17`; `rust/src/server/modern/mod.rs:15,76,211`); `PipeStop` (`rust/src/server/stream/pipe.rs:20`); `ClientError` (`rust/src/client/error.rs:197`); `StreamCode` (`rust/src/stream/mod.rs:60`). | A downstream exhaustive match can break on a new variant. `#[non_exhaustive]` requires wildcard matches and must be chosen per enum now; it does not prevent constructing existing variants. |
| Implementor trait | `NativeTools` (`rust/src/server/verify/mod.rs:139-141`), `StateStore` (`rust/src/server/registry/state.rs:166-189`), `Transport` (`rust/src/client/transport.rs:203-220`), `Signer` (`rust/src/client/request_signing/signer.rs:18-27`), `ResponseKeys` (`rust/src/server/response_keys.rs:86`), `AuditSink` (`rust/src/server/audit.rs:41`). | Adding a required method breaks implementors. Use a semantically sound default method or companion trait; sealing forecloses downstream implementations and is a deliberate policy choice, not a blanket fix. Preserve object safety where trait objects are used. |

This is a relevant-item audit, not a claim that every public type is exhaustive. Task #300 implements Option B only for the six selected server-side input/config structs; it does not implement the recommendations for client, stream-verifier, or webhook configurations, output structs, enums, or implementor traits. Draft's broad inventory includes many public values but no use-site proof for each; complete generated/exported/feature-gated inventory remains **UNVERIFIED**.

| Input type | Declaration / scope | Option B construction |
|---|---|---|
| `server::verify::Config` | `rust/src/server/verify/mod.rs`; six selected server-side types | `VerifierBuilder::new(aud, state) ... try_build()`; config is internal |
| `HandlerConfig` | `rust/src/server/http/mod.rs`; static signing profile | `HandlerBuilder::new(verifier, server_key)...build() -> JackLayer` |
| `RotatingHandlerConfig` | `rust/src/server/http/mod.rs`; rotating signing profile remains distinct | `RotatingHandlerBuilder::new(verifier, response_keys)...build() -> JackLayer` |
| `StreamConfig` | `rust/src/server/http/stream_layer.rs`; static signing profile | `StreamLayerBuilder::new(...).build() -> StreamLayer` |
| `RotatingStreamConfig` | `rust/src/server/http/stream_layer.rs`; rotating signing profile remains distinct | `StreamLayerBuilder::rotating(...).build() -> StreamLayer` |
| `StreamPipeConfig` | `rust/src/server/stream/pipe.rs`; low-level pipe settings | `StreamPipeBuilder::new(required fields)...build() -> StreamPipe` |

The six selected configuration records are internal construction details, not public literal APIs. Their former public-field/config-record constructors are replaced because the crate is unpublished; any equivalent records retained internally are private implementation details. In particular, `StreamPipeConfig` is a private `pub(crate)` record used internally; callers construct `StreamPipe` with `StreamPipeBuilder`. #301/#302 remain non-goals.

### Implemented builder surface

These are the observed public construction entry points (omitted fields/methods are not implied). Defaults and static/rotating distinctions remain as implemented.

```rust
VerifierBuilder::new(aud, state)
    .nonces(...).audit(...).native_tools(...).window_seconds(...).now(...)
    .with_server_keys(...).with_webhook_keys(...)
    // Linux only:
    .with_durable_nonces(...)
    .try_build() -> Result<Verifier, VerifierConfigError>

HandlerBuilder::new(verifier, server_key)
    .max_body_bytes(...).max_response_bytes(...).with_profile(...).build() -> JackLayer
RotatingHandlerBuilder::new(verifier, response_keys)
    .max_body_bytes(...).max_response_bytes(...).with_profile(...).build() -> JackLayer

StreamLayerBuilder::new(verifier, server_key)       // static
StreamLayerBuilder::rotating(verifier, response_keys) // rotating
    .max_body_bytes(...).max_response_bytes(...).streams(...).with_profile(...)
    .build() -> StreamLayer

StreamPipeBuilder::new(sid, open_sig, open_ts, limits, method, started_ms, signer)
    .request_id(...).cutoff(...).build() -> StreamPipe
```

`StreamLayerBuilder` has `profile` as an alias for `with_profile`; handler builders expose `with_profile`. The records produced/consumed internally are not public construction surfaces. The old `Verifier::new(config)` and layer/config-record construction APIs were replaced in the unpublished crate.

## Per-struct construction-site counts

The required acceptance metric is the count of original legacy struct-literal expressions at baseline HEAD, grouped by exact requested directories. Counts include every actual selected record literal, including internal `StreamLayer` implementation temporaries and the internal HTTP `StreamPipeConfig` literal; they are not limited to downstream construction sites.

| Original legacy struct literal (baseline HEAD) | `rust/src` | `rust/tests` | `interop/rust` | `tools/consumer/rust` | `tools/mcp-e2e/rust` | `rust/README.md` | Total |
|---|---:|---:|---:|---:|---:|---:|---:|
| `server::verify::Config` (including aliases `VerifierConfig`) | 2 | 15 | 4 | 1 | 0 | 1 | 23 |
| `HandlerConfig` | 1 | 14 | 2 | 1 | 0 | 1 | 19 |
| `RotatingHandlerConfig` | 1 | 1 | 1 | 0 | 0 | 1 | 4 |
| `StreamConfig` | 0 | 1 | 1 | 0 | 0 | 0 | 2 |
| `RotatingStreamConfig` | 0 | 0 | 1 | 0 | 0 | 0 | 1 |
| `StreamPipeConfig` | 2 | 0 | 0 | 0 | 0 | 0 | 2 |

Count literal expressions only: include aliases, assigned literals, and nested literals wherever they occur in the listed directories, including tests, interop, and documentation; exclude declarations, patterns, type/return positions, imports, comments, and unrelated `Config` types. The counts were manually inspected against baseline HEAD candidates after narrow searches. Current builder-call counts are listed separately for context; they are not a 1:1 migration measure because builder calls also occur in helpers and documentation, and builder methods differ from legacy struct literals.

| Current builder call | `rust/src` | `rust/tests` | `interop/rust` | `tools/consumer/rust` | `tools/mcp-e2e/rust` | `rust/README.md` | Total |
|---|---:|---:|---:|---:|---:|---:|---:|
| `VerifierBuilder::new` | 8 | 18 | 6 | 1 | 0 | 1 | 34 |
| `HandlerBuilder::new` | 1 | 15 | 2 | 1 | 0 | 2 | 21 |
| `RotatingHandlerBuilder::new` | 1 | 1 | 1 | 0 | 0 | 0 | 3 |
| `StreamLayerBuilder::new` (static) | 0 | 1 | 1 | 0 | 0 | 0 | 2 |
| `StreamLayerBuilder::rotating` | 0 | 0 | 1 | 0 | 0 | 0 | 1 |
| `StreamPipeBuilder::new` | 2 | 0 | 0 | 0 | 0 | 0 | 2 |

The separate searches used were `VerifierBuilder::new`, `HandlerBuilder::new`, `RotatingHandlerBuilder::new`, `StreamLayerBuilder::new`, `StreamLayerBuilder::rotating`, and `StreamPipeBuilder::new` in each listed directory. No Cargo command, test, build, lint, or other check was run for this documentation edit.

### Linux-gated candidate inventory

Inventory procedure: search `target_os = "linux"` in `rust/tests`, `rust/src`, and `interop/rust`, then inspect Linux-gated files for the selected server builders/configs, constructor or `with_*` use, and verifier references. The following are the exact affected files; paths are repository-relative. Details distinguish actual selected API construction/configuration from other verifier mentions:

- `rust/tests/rotation/server/signing/mod.rs` — builds `VerifierBuilder` with server-key configuration, then constructs both `HandlerBuilder` and `RotatingHandlerBuilder`; the profile-specific harness branches select static versus rotating signing.
- `rust/tests/durable_restart.rs` — constructs verifiers with `VerifierBuilder::new` in durable restart scenarios; no handler/stream builder construction.
- `rust/tests/durable_nonce_vectors/main.rs` — constructs a verifier with `VerifierBuilder::new` and `.with_durable_nonces(...)`.
- `rust/src/server/verify/tests/mod.rs` — defines the shared verifier helper using `VerifierBuilder::new`; its Linux-gated additions create a durable test store, not another selected builder/config API.
- `rust/src/server/verify/tests/constructor_and_time.rs` — Linux-gated test constructs `VerifierBuilder`, sets `.window_seconds(...)`, `.with_durable_nonces(...)`, and calls `.try_build()` to check durable-option window validation.
- `rust/src/server/verify/mod.rs` — declares the verifier builder API and Linux-only durable nonce method; the gated references are API implementation/configuration, not downstream construction sites.
- `rust/src/server/verify/pending.rs` — Linux-gated durable-admission cleanup in `PendingRequest::drop`; verifier context only, no selected builder/config construction.
- `interop/rust/src/bin/interop_server.rs` — Linux-gated verifier configuration includes `.with_durable_nonces(...)`; also builds the verifier and static `HandlerBuilder` layer.
- `interop/rust/src/bin/stream/server.rs` — builds verifiers and uses `StreamLayerBuilder::new` (static) and `StreamLayerBuilder::rotating` (rotating); no selected config-record literals.
- `interop/rust/src/bin/stream/mod.rs` — Linux-gated `durable` submodule declaration and `StreamVerifierConfig`/`StreamVerifier` use; the latter is the separate stream verifier configuration, not a selected server builder/config.
- `interop/rust/src/bin/interop/mod.rs` — Linux-gated `rotation_server` module declaration; no selected server builder/config or verifier use in this file itself.
- `interop/rust/src/bin/interop/rotation_server.rs` — included by the Linux-gated module above; constructs/configures a `VerifierBuilder` and a `RotatingHandlerBuilder` for rotating response signing.

Other Linux-gated files in these trees were not included: their inspected gated content did not reference the selected server APIs, a relevant constructor/`with_*` call, or a verifier. In particular, `rust/tests/server/key_tool.rs` exercises `NativeTools` directly (no verifier construction), and the Linux-only rotation-state/property test code concerns rotation stores rather than these server builder/config APIs. No successful build or test check is claimed.

### Historical `#[non_exhaustive]` recommendations (not task #300 scope)

The decisions below are prior recommendations for downstream-facing types. Task #300 changes only the six server-side input/config construction APIs above. It does not implement output, enum, client, stream-verifier, webhook, or implementor-trait recommendations. Export/feature completeness remains unverified.

The following table is historical recommendation inventory, not implementation evidence for task #300.

| Item | Class | Source declaration | Historical decision | Rationale |
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

- **Historical recommendation only:** external input/config structs outside the six-item builder scope and the output/enum/trait recommendations below are unchanged by #300. `NativeOptions` and `DurableStoreOptions` downstream construction/export reachability remains **UNVERIFIED**. This relevant-item inventory is not an exhaustive export/use-site audit; completeness remains **UNVERIFIED**.


## Nonce admission design

Volatile `NonceStore` uses a mutex for atomic `(kid, nonce)` check/insert; pair is live through equality (`now <= retain_until`), purge removes only `< now`, replay does not extend retention (`rust/src/server/registry/nonce.rs:36-73`). Verifier checks signature before recording (`rust/src/server/verify/mod.rs:365-394,431-453`). The Linux durable store has explicit lifetime ownership, reserve before dispatch, lease/close/fence, and recovery semantics—not a boolean callback (`rust/src/server/durable/durable_store.rs:695-697,835-905`; `docs/design/restart-replay.md:24-48`; `docs/operations.md:215-225`).

Propose a `nonces` option on `VerifierBuilder` replacing the current `Arc<NonceStore>` field in `server::verify::Config` with `Arc<dyn NonceAdmission>` (new breaking API), plus `fn check_and_record(&self, kid: &str, nonce: &str, now: i64, retain_until: i64) -> Result<NonceDecision, NonceAdmissionError>`, where `NonceDecision::{Recorded, Replay}`. This operation must be atomic check-and-insert. Errors distinguish confirmed no-commit/refusal from unknown commit outcome; only a confirmed `Recorded` authorizes dispatch, replay rejects, and any uncertain outcome fails closed and must not dispatch/retry. Preserve inclusive retention, purge semantics, and no replay extension. Proposed error type is typed and non-exhaustive; exact variants/payload and public names require review. **UNVERIFIED:** precise mapping from volatile/durable failures to verifier wire refusal codes.

Options:

1. **Trait only, memory default (recommend):** adapt `NonceStore`; keep durable profile as the existing explicit Linux implementation with its stronger leases and recovery; cost is an adapter/trait and a clear boundary between semantics. Risk: a simple trait cannot represent all durable transaction/recovery lifecycle; never claim it does.
2. **Trait plus rotation/lease store abstraction:** expose reservation receipts, finish/lease, close and recovery through a richer API. Cost and surface grow substantially; risk of misrepresenting current backend-specific recovery rules. Choose only if application-provided durable backends are explicitly required.
3. **Async trait:** permit async I/O stores; requires async verifier/authentication propagation and runtime-facing changes. Cost touches request pipeline; risk of changing scheduling/dispatch contracts. No async requirement found; prefer synchronous initially.

Current verifier/registry/durable calls are synchronous (`rust/src/server/verify/mod.rs:431-453`; durable reservation `rust/src/server/durable/durable_store.rs:888-905`). A synchronous database adapter can block a request executor/thread and needs bounded latency/appropriate integration; async is not free. Linux durable implementation stays opt-in and retains owner exclusion, commit acknowledgment, leases and recovery; it must not be flattened to `NonceAdmission`'s simple boolean-like decision. Default remains in-memory. Footguns: don't record before signature; don't dispatch after failure/unknown outcome; don't renew expiry on replay; don't evict live entries; don't silently recover corrupt/missing/unsafe state as empty; don't imply cluster safety from a mutex.

Go already has an admission abstraction and durable reserve seam (`server/verify.go:90-101`; `server/internal/verify/admission.go:34-77`); TS has synchronous `checkAndRecord` (`ts/src/server/registry/nonce.ts:18`) and a distinct durable admission (`ts/src/server/durable/admission.ts:124`). Recommend semantic parity (atomic admission, retention, fail-closed) but **not** force Rust to mirror Go/TS signatures or storage formats; Rust's richer durable receipt/lease lifecycle needs its own seam. Whether cross-SDK abstraction parity is desired: owner decision.

## Historical verifier error discussion

The source-defined verifier error is unchanged by task #300; this section records prior review context only.

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

This section's verifier API examples are historical and superseded by task #300's builder constructor. Error-contract recommendations here are not additional task #300 changes.

## Invariants

This change documents builder-based Rust server construction only. It does not change wire bytes or protocol behavior. Preserve the existing defaults and zero conventions, including body/response limit zero => 1 MiB and verifier window zero => default. No runtime or fixture checks are claimed here.

## Historical recommendation and review-plan context

The active construction recommendation for task #300 is complete: builders are used for the six selected server-side input/config types. Other historical recommendation items listed here are not part of task #300.

| Order/task | Files to review/change if approved | Context (historical unless task #300 noted) |
|---|---|---|
| 1. Confirm API/export and counts | `rust/src/**`, `rust/tests/**`, `interop/rust/**`, `tools/consumer/rust/**`, `tools/mcp-e2e/rust/**`, `rust/README.md` | Independently spot-check counts and export coverage; external consumers are unknown. |
| 2. Builder shape (#283 after #286) | The six selected server-side declarations and their call sites | Task #300 implements Option B for `server::verify::Config`, `HandlerConfig`, `RotatingHandlerConfig`, `StreamConfig`, `RotatingStreamConfig`, and `StreamPipeConfig`. The former public configuration-record construction APIs are replaced in this unpublished crate; any equivalent internal records are private. Static and rotating forms remain distinct. |
| 3. Non-exhaustive policy | Public enum/output declarations and selected inputs | Historical recommendations apply per item in the table; task #300 does not change output or enum policy. |
| 4. Nonce abstraction (#286 first) | `rust/src/server/verify/mod.rs`, `rust/src/server/registry/nonce.rs`, `rust/src/server/durable/**` | **Historical recommendations / owner questions:** implement atomic admission trait only, leaving rotation/lease stores and durable lifecycle separate (recommend), or include rotation stores/leases in the new abstraction? |
| 5. Execution model/parity | Same Rust nonce files; compare `server/internal/verify/admission.go`, `ts/src/server/**` | **Historical recommendations / owner questions:** synchronous (recommend for the current pipeline) or async? Separately, mirror Go/TS APIs/signatures or match semantics only (recommend)? |
| 6. Error contract | `rust/src/server/verify/mod.rs`, `rust/Cargo.toml` only if dependency proposed | Historical proposal to approve typed variants and hand-written `Display`/`Error`; `thiserror` requires owner approval. |
| 7. Acceptance after implementation | Rust tests, interop/consumer suites, cross-language fixtures, release CI | #286 precedes #283 per task direction; RC re-runs each applicable suite and approved layout lint. Exact RC matrix **UNVERIFIED**. |

## Unverified items

- Export coverage, exact builder names, constructor validation beyond observed verifier behavior, and public error payload details require approval.
- Durable trait-to-wire refusal mapping, async demand, owner preference for Go/TS API/signature parity, and choice of which enums receive `#[non_exhaustive]` are **UNVERIFIED**.
- #286/#283 ordering and overlap are task-provided, not independently checked; exact RC matrix is **UNVERIFIED**.
- Representative output/enum annotation choices and implementor-trait non-annotation decisions are tabulated per item above; export coverage and owner approval remain open.
