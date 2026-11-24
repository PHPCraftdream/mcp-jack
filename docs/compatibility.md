# MCP compatibility

This document describes the checked-in profile rules and the bounded scope documented by the SDK and CLI materials. It is not a claim that conformance matrices passed. The `mcp-jack/v1` request and JSON-response bytes remain unchanged; modern streams and webhook delivery use additional identifiers (specs [04](../spec/04-modern-profile.md), [05](../spec/05-signed-streams.md), [06](../spec/06-webhooks.md)).

## Supported MCP revisions

| MCP revision | Profile | Status and behavior |
|---|---|---|
| `2025-06-18` | Legacy | Supported. `initialize`-era behavior; legacy requests do not run modern header/session rules. |
| `2025-11-25` | Legacy | Supported. Legacy `initialize`-era behavior. |
| `2026-07-28` | Modern | Supported. Per-request metadata and mirror rules; optional signed streams and Events delivery. |
| `2025-03-26` | — | Not supported by default: batch arrays conflict with the frozen one-JSON-RPC-object v1 body rule. |
| `2024-11-05` | — | Not supported by default: HTTP+SSE requires a separate GET stream endpoint and is deprecated by MCP. |

The last two are the default currently applied to open owner decision 7 in `design/mcp-2026-07-28.md` §9; the owner decision remains open. They must not be represented as approved compatibility.

Servers select `legacy`, `modern`, or `both`. `legacy` always uses the legacy era; `modern` always uses the modern era; `both` determines the era per request after authentication. In `both`, either a modern protocol-version header or modern version in signed `_meta` selects the modern era, then mirrors must agree. This prevents stripping the unsigned version header from downgrading a modern body. Legacy-era requests remain untouched by modern rules (spec 04 §§1,3,5).

Clients negotiate/fallback based on verified replies, not unsigned status/body content: verified success or recognized modern JSON-RPC errors indicate modern; selected legacy responses such as 405 lead to legacy `initialize`; unverified/malformed replies or network failures do not establish an era (spec 04 C9). A verified `-32022` can prompt one retry only with mutually supported versions, otherwise negotiation fails (spec 04 C9).

## CLI profiles

| CLI component | Era/profile selection | Behavior |
|---|---|---|
| `jack gateway` | `profile` config or `--profile legacy\|modern\|both`; default `legacy` | Legacy remains the default; `modern` enables modern rules and `both` selects per authenticated request. Signed streams require a modern-capable profile and `Jack-Accept: s1`. |
| `jack bridge` | Client config `era`: `legacy` (default), `modern`, `auto` | Legacy behavior remains unchanged by default; modern relays verified replies and signed-stream frames. `auto` probes using verified era negotiation. The bridge does not listen on a socket. |
| `jack events receive` | No protocol-era setting | Separate webhook callback receiver; receipt state is persisted and restored after restart. |

Raw CR or LF in a verified signed-stream message aborts only that bridge stream and emits a diagnostic to stderr. Closing stdin cancels active calls; matching `notifications/cancelled` cancels the request.

## 2026-07-28 changes and Jack handling

The design's classification in `design/mcp-2026-07-28.md` §2 distinguishes transparent v1-carried changes (**T**), modern header/dispatch rules (**H**), signed streams (**S**) and webhooks (**W**). The normative details are in specs 04-06, not the earlier historical design wording.

| MCP/Events feature | Class | Jack handling documented in current specs |
|---|---:|---|
| Request `_meta`, `server/discover`, Tasks, MRTR, Events poll/subscribe/unsubscribe/list, error-code changes | T | Body remains authenticated by v1; Jack forwards ordinary requests to the wrapped handler. Events principal is the authenticated Jack identity. |
| `CacheableResult` (`ttlMs`, `cacheScope`) | T + doc | Clients may cache verified results privately by exact request, bounded by `ttlMs`; never use a shared cache or any HTTP cache, regardless of `cacheScope`. |
| `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*` mirrors | H | Validate applicable mirrors against signed body and refuse disagreement; project/forward annotated parameter headers under spec rules. |
| GET/DELETE removal, session and last-event headers | H | Modern era requires POST; strips `Mcp-Session-Id` and `Last-Event-ID`. Legacy handling remains unchanged. |
| `subscriptions/listen` | S | Optional `s1` signed streams deliver notifications only when opted into by the subscription/listen request. |
| `notifications/events/list_changed` | S | Delivered through opted-in `subscriptions/listen` streams. |
| Events webhook delivery and endpoint verification | W | Separate server-to-client HTTPS channel; Standard Webhooks signatures plus optional Jack `w1`, hardened destination policy, verification and receiver handling. |
| Server Card webhook signing-key discovery | W | Dedicated webhook keys are discovered from same-origin Server Card material; optionally cross-check against `jack.server.webhook_key`. |
| `jack.server.webhook_key` | W | Dedicated key publication/cross-check source; it cannot widen the key set accepted from same-origin Server Card discovery. |
| Deprecated Roots, Sampling, Logging and HTTP+SSE | T/no added support | Jack adds no special handling; HTTP+SSE is not supported by default. |

Classification follows design §2; current exact behavior is spec 04 §§3-6, spec 05 §§1-7 and spec 06 §§1-8. The wrapped MCP server owns Events/task semantics; Jack authenticates and transports them, not event production or task execution semantics.

## Events, streams and webhooks

The Events extension's poll, push and webhook modes are in scope. Poll requests use the ordinary signed request/response channel. Push uses `s1`; webhook delivery is separate from `Jack-Auth`. See [operations](operations.md) for stream limits, retry/receiver procedures and SSRF configuration, and [threat model](threat-model.md) for security properties and known gaps.

The only documented public SDK concept names in the checked API docs are:

| Language | Modern API concepts evidenced in SDK docs |
|---|---|
| Go | `client/modern` package: `BuildRequestMirrors`, `ValidateAnnotations`, `FilterDefinitions`, `ProjectArguments`, `DetectEra`, `ResultCache`; server profile types `server.ProfileLegacy`, `server.ProfileModern`, `server.ProfileBoth` (`client/modern/modern.go`, `server/middleware.go`). |
| Rust | `Client::with_era`, `ClientEra`, `client::modern::{build_mirrors, add_client_info}`, `detect_era`, `ToolCatalog`, `EventCatalog`, `project_arguments`, `Resync`, `PrivateResultCache`; server `JackLayer::with_profile` and `Profile::{Legacy, Modern, Both}` (`rust/README.md` §§4-5). |
| TypeScript | `jackFetchHandler` profile option, `Client` era, `client.ModernClient`, `detectEra`, `buildRequestMirrors`, and mirror/annotation helper exports (`ts/README.md` §Modern profile). |

These are conceptual/API names as documented, not a claim that each language has identical helper shapes. Webhook receiver APIs have language-specific names: Go exports `webhook.Receiver` (`webhook/receiver.go`), Rust defines `Receiver` (`rust/src/webhook/receiver/state.rs`), and TypeScript defines `WebhookReceiver` (`ts/src/webhook/receiver/core.ts`). This table does not assert live Server Card fetching in interop.

## Stream and webhook SDK building blocks

Concepts are shared across languages, while exported names and feature gates differ. This API mapping documents available building blocks; it is not a claim that all profiles or interop cases pass.

| Concept | Go | Rust | TypeScript |
|---|---|---|---|
| Stream signer/server | `server.StreamOptions`, `server.StreamFromContext` (`server/middleware.go`) | `server::http::StreamLayer`, `StreamConfig`, `RotatingStreamConfig`, `server::stream::StreamOptions` | `jackStream`, `StreamServerOptions` |
| Verified stream/client | Go `client/stream.Verifier`, `client/stream.Stream` | `client::stream::VerifiedStream` | `client.openSignedStream`, `client.SignedStreamSession` |
| Webhook sender | `webhook.Sender` | `webhook::http::Sender` (requires `http`; concrete HTTPS dialer via `client-http`) | `WebhookSender` |
| Webhook receiver | `webhook.Receiver` | `webhook::receiver::Receiver` | `WebhookReceiver` |
| Webhook key discovery | `webhook.CardSource`, `webhook.KeySource` | `webhook::card` | `fetchDecision`, `CardFetchInput` |

For Rust, `webhook::http` is gated by feature `http`; its `https` concrete transport additionally requires `client-http`. Exact client APIs and constructor/config shapes remain language-specific; see the public SDK source and READMEs. Webhook sender/receiver APIs are building blocks only: applications own subscription persistence and lifecycle (Go `webhook/doc.go`, Rust `rust/src/webhook/mod.rs`, TypeScript `ts/src/webhook/index.ts`).


The checked-in interop README defines matrices for request/response (sections 1-10), credential transfer (section 11), rotation (section 12), durable nonce restart (section 13), modern requests (section 14), and webhooks (section 15), plus the official MCP SDK end-to-end matrix (section 6 and CI job contract). These are descriptions of matrix scope, not result receipts; no results are claimed here. The webhook contract notes a skipped TypeScript DNS-rebinding scenario and implementation/harness gaps (Go TLS-root configuration option absent; Rust webhook-id injection seam absent; Go challenge POST visibility absent; no live Server Card fetch; TypeScript hardened transport has no rebinding recheck seam).

`spec/tests/modern/CASES.md` is generated conformance inventory, not a run receipt. Its fixture files and exact case counts are:

| Fixture file | Cases |
|---|---:|
| `modern-request-vectors.json` | 98 |
| `header-encoding-vectors.json` | 51 |
| `x-mcp-header-vectors.json` | 84 |
| `era-detection-vectors.json` | 38 |
| `stream-vectors.json` | 80 |
| `stream-build-vectors.json` | 8 |
| `webhook-signature-vectors.json` | 45 |
| `webhook-w1-vectors.json` | 25 |
| `webhook-receiver-vectors.json` | 107 |
| `webhook-endpoint-verification-vectors.json` | 93 |
| `ssrf-vectors.json` | 120 |
| `webhook-subscription-vectors.json` | 49 |
| `server-card-keys-vectors.json` | 43 |

These counts describe fixture scope only; they are not test results and make no pass claim. The modern profile spec says C7/C8/C10/C12 are SDK-test exemptions (spec 04 §8); stream server concurrency/duration/heartbeat/cancellation and some transport mapping rules likewise have SDK-level exemptions (spec 05 Exemptions).

The compatibility statements above are based on the cited checked-in specifications, SDK README/API source, and matrix contracts. No tests, builds or scripts were run for this documentation update.
