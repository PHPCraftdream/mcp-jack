# Design: Rust and TypeScript server SDKs

Status: draft, not implemented. Scope: server side only, matching the Go `jack` + `spec` + `server` packages. Client SDKs for Rust and TypeScript are a later step.

## 1. Goal and acceptance

A service written in Rust or TypeScript can put an unmodified MCP endpoint behind mcp-jack exactly as the Go `server` package does.

Acceptance, per language:

1. Every fixture file in `spec/fixtures/` is consumed by a conformance test, with the same runner contract as `spec/tests/README.md`:
   - `request-vectors.json`: every case, including `jack.*` tools (native tools are part of the SDK);
   - `admin-vectors.json`: every sequence;
   - `key-vectors.json`, `pattern-vectors.json`, `response-vectors.json`;
   - `load-vectors.json`: both `policies` and `registries`.
2. The HTTP adapter passes an end-to-end test: a request signed with the test keys reaches a trivial wrapped MCP handler, the signed response verifies, a rejection carries the spec error body and `WWW-Authenticate: Jack-Auth` on 401, a streaming response is refused with 501 `streaming_unsupported`.
3. Behavioral parity tests that the vectors cannot express, ported from the Go tests: atomic state updates, concurrent last-admin protection, invite code never stored, nonce retention and purge, strict state-file loading, bootstrap.
4. CI runs all of it on Linux and Windows. Fixtures are read from `spec/fixtures/` in place, never copied, so a fixture change breaks all three SDKs at once.

Non-goals for this step: client SDKs, stdio bridge, gateway binary, streaming signatures (spec README Q1), publishing to crates.io or npm, a CLI.

## 2. Repository layout

```
/                 Go module (unchanged)
/rust/            Cargo package `mcp-jack` (one crate)
/ts/              npm package `mcp-jack`
/spec/fixtures/   shared normative vectors, read by all three
```

One crate and one npm package, not workspaces: the server SDK is small and a split into `core` and `server` can happen when the client SDKs arrive.

## 3. Module map (parity with Go)

| Go | Rust (`mcp_jack::…`) | TypeScript (`mcp-jack/…`) |
|---|---|---|
| `base64.go` | `encoding` | `encoding.ts` |
| `signing.go` | `signing` | `signing.ts` |
| `authheader.go` | `auth_header` | `auth-header.ts` |
| `ed25519.go` | `ed25519` | `ed25519.ts` |
| `syntax.go` | `syntax` | `syntax.ts` |
| `errors.go` | `error` (`JackError`, `codes`) | `errors.ts` (`JackError`, `Code`) |
| `server/state.go`, `statefile.go` | `server::state`, `server::state_file` | `server/state.ts`, `server/state-file.ts` |
| `server/nonce.go` | `server::nonce` | `server/nonce.ts` |
| `server/audit.go` | `server::audit` | `server/audit.ts` |
| `server/policy.go` | `server::policy` | `server/policy.ts` |
| `server/verify.go` | `server::verify` | `server/verify.ts` |
| `server/native.go` | `server::native` | `server/native.ts` |
| `server/middleware.go` | `server::http` (feature `http`) | `server/fetch.ts`, `server/node.ts` |
| `spec/spec.go` | `tests/common/fixtures.rs` (test-only) | `test/fixtures.ts` (test-only) |

Names follow each language's conventions (`Verifier::verify` / `verifier.verify`), but types, fields, error codes and check order are the Go ones. Where Go and the spec disagree, the spec wins and the Go code gets a fix.

## 4. Shared semantics that are easy to get wrong across languages

These are the places where three independent implementations drift. Each gets a dedicated unit test in both new SDKs; any gap found in the vectors is fixed in `gen-fixtures.mjs` first, so all three SDKs inherit the case.

- **Exact bytes.** The body hash and signature cover the raw body bytes. Never re-serialize JSON before hashing; never decode the body to a string before the UTF-8 check.
- **UTF-8 before JSON.** Invalid UTF-8 is `invalid_request` before any parse. Rust: `std::str::from_utf8`; TypeScript: `new TextDecoder("utf-8", { fatal: true })`. `JSON.parse` on a lossily decoded string must never happen.
- **Strict base64url.** Unpadded, alphabet `A-Z a-z 0-9 - _`, non-zero trailing bits rejected, exact decoded length for fixed-size fields. Rust: `base64` crate engine with `DecodePaddingMode::RequireNone` and `decode_allow_trailing_bits(false)`, plus an explicit alphabet check. TypeScript: hand-written decoder (Node's `Buffer.from(s, "base64url")` is lenient and must not be used for verification).
- **Strict Ed25519.** S < L and canonical, prime-order-subgroup, non-identity public keys (spec 01, strict verification section).
  - Rust: `ed25519-dalek` `verify_strict` for the signature; public-key validation through `curve25519-dalek` (decompress, re-compress and compare bytes for canonicity, `is_torsion_free`, not identity).
  - TypeScript: `node:crypto` `verify(null, …)` for the signature plus an explicit S < L check on the signature bytes; public-key validation by porting the BigInt point arithmetic of `spec/tools/reference-verifier.mjs` (no third-party crypto).
  - `key-vectors.json` decides; a library that accepts a vector the spec rejects is wrapped, not trusted.
- **Missing vs null.** Policy `scope` absent and `scope: null` differ. Rust: deserialize rules into `serde_json::Map` and inspect keys; TypeScript: `Object.hasOwn`. No `Option<T>` shortcut in Rust that merges the two.
- **Unknown fields.** Strict loaders reject unknown fields (`#[serde(deny_unknown_fields)]` in Rust; an explicit key whitelist in TypeScript).
- **Integers.** Native tool arguments such as `ttl_seconds` follow Go's `intFrom`: the JSON number must be an integer in range. `1.0`, `1e3` and `-0` are a cross-language hazard; the TypeScript side cannot tell `1` from `1.0` after `JSON.parse`. A shared fixture task first checks which of these Go accepts, then adds fixture cases so all three agree (a `JSON.parse` reviver with source text is not available on Node 20, so TypeScript inspects the raw argument text).
- **Duplicate JSON object keys.** Go, `serde_json::Map` and `JSON.parse` all keep the last value. This matches today, but is unspecified; recorded as a spec question rather than solved here.
- **Clocks and randomness.** Injected clock (Unix seconds) and injected random source for invite codes, as in Go; no wall-clock reads in logic.
- **Atomic state.** `StateStore.update` takes a closure over a deep-copied edit and swaps it in only on success; the closure may run against a snapshot taken under the store lock. The last-admin rule depends on this.

## 5. Rust design

- Package `mcp-jack`, library name `mcp_jack`, edition 2021, MSRV 1.75 (recorded in `rust-version`).
- Dependencies (runtime): `ed25519-dalek` (features `std`), `curve25519-dalek`, `sha2`, `base64`, `serde` (derive), `serde_json`, `getrandom`. Feature `http` adds `http` 1.x, `bytes`, `http-body-util` and `tower-service`/`tower-layer` for the adapter. Dev: `tokio` (rt, macros), `tower` (util) for adapter tests. No `axum` dependency; a `tower::Layer` works under axum, hyper and tonic alike.
  - Tradeoff: `tower` is the de-facto Rust middleware abstraction; avoiding it would mean an adapter per framework. It stays behind a feature so the core has no async dependency.
- Core is synchronous: `Verifier::verify(&self, &Request) -> VerifyResult`. Types are `Send + Sync`; the stores use `std::sync::Mutex`.
- Traits mirror Go interfaces: `StateStore { view, lookup, update }`, `AuditSink { record }`, `NativeTools { call(&self, &mut NativeCall) -> Result<NativeResult, JackError> }`.
- `JackLayer` / `JackService<S>`: buffers the request body up to `max_body_bytes` (default 1 MiB), runs the verifier, answers native tools itself, forwards accepted requests to the inner service with the body restored, buffers and signs the response, refuses `text/event-stream` with 501.
- Fixtures: integration tests in `rust/tests/` load `../spec/fixtures/*.json` through `env!("CARGO_MANIFEST_DIR")`. Not embedded in the library, so `cargo package` stays valid.
- Lints: `#![forbid(unsafe_code)]`, `cargo clippy -- -D warnings`, `cargo fmt --check`.

## 6. TypeScript design

- Package `mcp-jack`, ESM only, `"type": "module"`, Node >= 20, TypeScript `strict` plus `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`.
- Zero runtime dependencies (only `node:crypto`, `node:fs`, `node:http`). Dev dependencies: `typescript`, `@types/node`. Tests use `node:test` and `node:assert`; no test framework dependency.
- Core is synchronous where Go is (`Verifier.verify`); stores expose a synchronous `update(fn)` so the atomic-update rule is easy to keep (a JavaScript closure cannot be preempted).
- HTTP, two thin layers over one core:
  - `jackFetchHandler(config, next)`: `next` is a Fetch-standard `(Request) => Promise<Response>`; the returned handler has the same shape. This fits Hono, Deno, Bun and the Web-standard transport of the MCP TypeScript SDK.
  - `serveNode(handler)`: adapts a Fetch handler to `node:http` (`(IncomingMessage, ServerResponse)`), with the same body limit.
  - Gateway use (an MCP server in another process) is `next = (req) => fetch(upstreamUrl, …)`, documented as an example, not a separate API.
- Fixtures: tests read `../spec/fixtures/*.json` with `node:fs` relative to the test file. Not shipped in the package.
- Build: `tsc -p .` to `dist/`; tests run against compiled output (`node --test dist-test/`), so no loader or `tsx` dependency.

## 7. CI

Add to `.github/workflows/ci.yml`:

- `rust` (ubuntu, windows): `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, plus `cargo test --no-default-features` on ubuntu.
- `ts` (ubuntu, windows; Node 20 and 22): `npm ci`, `npx tsc -p . --noEmit`, `npm test`.
- Path filters are not added: the fixtures are shared, so every SDK must run on every change.

Local checks follow the project rule: builds and tests run in CI. Locally only `cargo fmt`, `cargo check` and `cargo clippy` for Rust; for TypeScript nothing beyond formatting unless the user allows `tsc --noEmit`.

## 8. Risks

- No local test runs: as with Go, the first CI run will surface compile and test failures. Mitigation: Rust is checked locally with `cargo check` and `cargo clippy`, which the rules allow.
- Crypto library strictness differs from the spec; the key and request vectors are the arbiter (section 4).
- The Go SDK itself has never run; a divergence found by Rust or TypeScript may be a Go bug. Decision rule: the spec text and the JavaScript reference verifier decide, then the vectors.

## 9. Open questions

1. Allow `tsc --noEmit` locally for TypeScript (type check only, no build output)?
2. Package names on crates.io and npm are free (checked on 2026-11-05); reserve them now or at the first release?
3. Duplicate JSON object keys in request bodies: reject in all SDKs (needs a custom parser in Go and TypeScript) or keep last-wins and state it in the spec?
