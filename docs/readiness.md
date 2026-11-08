# SDK coverage readiness review

Status: documentation review of the tree at commit `2530b70` ("Read the full request before the
timeout socket fixture responds"), worktree `sdk-coverage-readiness-1108`, plus the uncommitted
coverage/fuzz/readiness delivery in this worktree: new fuzz targets in the root, `server`,
`client` and `userkey` packages, the `.github/workflows/coverage.yml` and
`.github/workflows/fuzz.yml` workflows, the summarizer and campaign scripts
(`tools/coverage/go-summary.mjs`, `tools/coverage/lcov-summary.mjs`,
`ts/scripts/coverage-summary.mjs`, `tools/fuzz/go-campaign.sh`) and this document. It reviews the Go,
Rust and TypeScript SDKs, the specification and fixtures, the test suites and the CI workflow
definitions, and it consolidates the readiness evidence for the SDKs as delivered, including the new coverage and fuzz CI. Every factual claim carries a `path:line` citation verified by
reading the tree. CI execution itself is observed separately by the operator; this document
makes no claim that any workflow has run or passed.

## 1. Scope and method

Reviewed by read-only inspection: the specification (`spec/README.md`, `spec/fixtures/`), the
design records (`docs/design/interop.md`, `docs/design/user-keys.md`,
`docs/design/rust-ts-server-sdks.md`), the three SDKs (Go module at the root, `rust/`, `ts/`),
the interop and credential-transfer harnesses (`interop/`), the consumer packaging checks
(`tools/consumer/`) and the workflow definitions present at this commit
(`.github/workflows/ci.yml`, `.github/workflows/license.yml`). No build, test or harness was
executed; all numbers (scenario counts, fixture case counts, transfer-matrix counts) were
counted directly in the files that declare them. The coverage and fuzz workflows
(`.github/workflows/coverage.yml`, `.github/workflows/fuzz.yml`), the bounded-campaign script
(`tools/fuzz/go-campaign.sh`) and the three summarizer scripts (`tools/coverage/go-summary.mjs`,
`tools/coverage/lcov-summary.mjs`, `ts/scripts/coverage-summary.mjs`) are reviewed below as
in-tree files of this delivery.

## 2. Product surface by language and role

### Go (module at repository root)

- Client: `client.Transport` (signing/verifying `http.RoundTripper`), `NewHTTPClient` with a
never-follow redirect policy (`client/transport.go:62-99`); `Signer` interface and
`InMemorySigner` (`client/signer.go:11-41`); `Config`/`NewClient` (`client/rpc.go:19-85`);
profile loading (`client/profile.go`); typed native-tool calls (`client/tools.go`,
`client/doc.go`).
- Server: `NewHandler` middleware (`server/middleware.go:85`), `Verifier`
(`server/verify.go:115-195`), policy engine (`server/policy.go`), native tools and
`BootstrapAdmin` (`server/native.go:31,706`), nonce store (`server/nonce.go:16`), audit sinks
(`server/audit.go:29-82`), `FileState` with strict load and atomic writes
(`server/statefile.go:48-228`).
- User keys/transfer: `userkey.GenerateClientKey`/`ImportClientKey` (client role) and
`ImportServerKey` (server role, no private export) (`userkey/key.go:88,231`), the portable
transfer surface `ExportPublicEnvelope`, `ImportClientPublicEnvelope`,
`ImportClientPrivateEnvelope`, `ImportServerPublicEnvelope`, `ImportCredential`,
`ValidateCredential`, `IssueUserKey` (`userkey/transfer.go:133-263`); role contract documented
in `userkey/doc.go:1-60`.
- Shared primitives in the root package `jack`: auth-header parsing, signing strings, strict
Ed25519, base64url, syntax, errors (`authheader.go`, `signing.go`, `ed25519.go`, `base64.go`,
`syntax.go`, `errors.go`).

### Rust (`rust/`, crate `mcp_jack`, MSRV 1.85)

- Public modules: `auth_header, client, ed25519, encoding, error, server, signing, syntax,
user_key` (`rust/src/lib.rs:8-16`).
- Client: `Transport` trait, `SigningTransport`, `HttpRequest`/`HttpResponse`
(`rust/src/client/transport.rs:40-244`), `Config`/`Client` (`rust/src/client/rpc.rs:13-289`),
typed tools (`rust/src/client/tools.rs:196-326`), profile (`rust/src/client/profile.rs`), URL
policy (`rust/src/client/url.rs`), optional blocking HTTP/HTTPS transport behind the
`client-http` feature (`rust/src/client/http_transport.rs:1-32`).
- Server: `HandlerConfig`, `JackLayer`, `JackService<S>` tower adapter
(`rust/src/server/http.rs:55-148`), verifier, policy, native tools, nonce, audit, state and
state-file modules (`rust/src/server/mod.rs:3-12`).
- User keys: `ClientSigningKey`, `IssuedClientKey`, `ServerPublicKey`, `UserKeyPublic`,
`ExpectedIdentity`, `ConnectionData` and the import pipeline in `rust/src/user_key.rs:134-660`.

### TypeScript (`ts/`, package `mcp-jack`, ESM, Node >= 20, `private: true`, zero runtime
dependencies)

- Root exports re-export errors, auth-header, ed25519, encoding, signing, syntax, user-key,
user-key-transfer and all server modules, plus a namespaced `client` entry
(`ts/src/index.ts:2-20`).
- Client: signing fetch and transport (`ts/src/client/transport.ts:38,317-345`), URL policy
(`ts/src/client/url-policy.ts`), signer, profile, rpc, tools (`ts/src/client/index.ts`).
- Server: `jackFetchHandler` Fetch adapter (`ts/src/server/fetch.ts:87`), `serveNode` node:http
adapter (`ts/src/server/node.ts:24`), verifier, policy, native, nonce, audit, state, state-file
modules.
- User keys: `ClientUserKey`, `ServerUserKey`, `UserKeyHandoff`, `issueUserKey`
(`ts/src/user-key.ts:29-143`); transfer imports/exports and `issueUserKeyCredential`
(`ts/src/user-key-transfer.ts:522-614`).

## 3. Protocol capabilities

The normative oracle is the shared fixture set `spec/fixtures/` (request, response, key,
pattern, load, admin vectors; `spec/README.md` "Conventions": generated vectors are normative;
`client-url-policy.json` and `user-key-transfer.json` are hand-maintained SDK test tables
outside `gen-fixtures.mjs --check`, `spec/fixtures/README.md:1-8`). Each language loads the same
files in place:

- Go: `spec/fixtures_test.go` (119 lines) and `spec/statefile_loader_test.go`; fixture freshness
is enforced in CI by the `fixtures are up to date` job (`.github/workflows/ci.yml:46-53`).
- Rust: `rust/tests/fixtures_load.rs`, plus per-vector conformance tests (`keys_conformance.rs`,
`verify_conformance.rs`, `patterns_conformance.rs`, `policy_conformance.rs`,
`responses_conformance.rs`, `admin_conformance.rs`, `state_file.rs`) in `rust/tests/` (18
files).
- TypeScript: `ts/test/fixtures-load.test.ts` and per-vector tests (`request-vectors.test.ts`,
`response-vectors.test.ts`, `verify-vectors.test.ts`, `key`/`pattern` via
`admin-vectors.test.ts`, `load-vectors.test.ts`, `state-file.test.ts`) — 30 `*.test.ts` files in
`ts/test/`.

Capabilities implemented in all three: auth-header parse/format and freshness window (Go
`authheader.go`, `client/auth.go:14,80-81` with `DefaultWindow = 30s`; Rust
`rust/src/auth_header.rs`, `rust/src/signing.rs:89-91`; TS `ts/src/client/auth.ts:17,66` with
`DEFAULT_WINDOW_SECONDS = 30`); strict Ed25519 signing/verification and public-key validation
per spec decision D12 (`spec/README.md` D12; Go `ed25519.go`, Rust `rust/src/ed25519.rs`, TS
`ts/src/ed25519.ts`, pinned by `key-vectors.json`); server policy matching with deny-by-default
(`server/policy.go`, `rust/src/server/policy.rs`, `ts/src/server/policy.ts`, pinned by
`pattern-vectors.json`, `load-vectors.json`); audit (`server/audit.go:29-82`,
`rust/src/server/audit.rs`, `ts/src/server/audit.ts`); replay protection via a nonce store keyed
`kid+nonce` with `retainUntil = ts + window` (`server/nonce.go:26-52`,
`rust/src/server/nonce.rs`, `ts/src/server/nonce.ts`); strict state-file loading and atomic
tmp-file/fsync/rename persistence (`server/statefile.go:65,240-260`,
`rust/src/server/state_file.rs`, `ts/src/server/state-file.ts`).

## 4. Transport: HTTP, TLS, limits, timeouts, redirects

### Client side

Go: response bodies are buffered through `io.LimitReader` with a 1 MiB cap (`maxBodyBytes`,
`client/transport.go:120-122,215-222`); redirect statuses 301/302/303/307/308 are refused before
verification and `Location` is never surfaced (`client/transport.go:199-206`,
`client/urlpolicy.go:22-51`); streaming `text/event-stream` answers are refused
(`client/transport.go:208-213`); the raw destination string is policy-checked before signing —
https for any plain host, http only for literal canonical `127.x.y.z` or `[::1]`, no userinfo,
no `%` in the authority, no backslash or non-ASCII bytes (`client/urlpolicy.go:53-119`). TLS,
connect/request timeouts and proxy behavior are entirely delegated to the caller:
`NewHTTPClient` sets only `Transport` and `CheckRedirect` (`client/transport.go:97-99`), and
`client/doc.go` states that a caller-supplied `http.Client`/`Config.HTTP` base round tripper is
outside SDK control. There is no SDK-enforced timeout in Go.

Rust: the `client-http` feature provides a blocking Hyper/rustls transport with TLS via
`tokio_rustls`/ring and `webpki_roots::TLS_SERVER_ROOTS`, DNS via hickory-resolver with the
hosts snapshotted at construction and supplied to each resolver (per-request system-file reads disabled), an absolute round-trip timeout defaulting to 15 s
(`DEFAULT_TIMEOUT_SECONDS`, `rust/src/client/http_transport.rs:1,29,57,89-95,224,388`), and an
explicit "No redirects, proxy, insecure TLS, or retries" contract
(`rust/src/client/http_transport.rs:32`). The signing transport refuses the same five redirect
statuses (`rust/src/client/transport.rs:20,291-297`) and caps response bodies at
`MAX_BODY_BYTES` before verification (`rust/src/client/transport.rs:310`; enforced in
`rust/src/client/http_transport.rs:544-554`). The transport-abstract path (`Transport` trait)
delegates TLS/timeout policy to whatever implementation the caller injects
(`rust/src/client/transport.rs:47-189`).

TypeScript: `createSigningFetch` buffers and signs exact bytes, forces `redirect: "error"` on
the outbound init (`ts/src/client/transport.ts:317-325`), and additionally refuses any response
that is, or was produced by following, a redirect — status 301/302/303/307/308, `type ===
"opaqueredirect"` or `redirected === true` — so an injected `fetchImpl` that follows redirects
is still caught (`ts/src/client/transport.ts:242-266,336-337`); the 1 MiB response cap is
`MAX_BODY_BYTES` (`ts/src/client/transport.ts:38`); streaming answers are refused
(`ts/src/client/transport.ts:344`). TLS and timeouts come from the platform `fetch` or the
injected `fetchImpl`; the only cancellation channel is the forwarded `AbortSignal`
(`ts/src/client/transport.ts:67`), i.e. no SDK-enforced timeout.

### Server side

All three adapters buffer request bodies up to a default 1 MiB (`MaxBodyBytes`,
`server/middleware.go:18-31`) and buffer responses up to a default 1 MiB
(`defaultMaxResponseBytes`, `server/middleware.go:20`; TS `DEFAULT_MAX_RESPONSE_BYTES`,
`ts/src/server/fetch.ts:49`; Rust `JackLayer` per `docs/design/rust-ts-server-sdks.md` section
5). Oversized upstream responses answer a signed 502 `response_too_large`; `text/event-stream`
is refused with signed 501 `streaming_unsupported`, and the 501 check precedes the size cap
(`server/middleware.go:62-81`). All adapters document explicitly that the byte caps bound bytes,
not time: a deadline covering body consumption must wrap the whole handler and is the caller's
responsibility (Rust/TS adapters per `docs/design/rust-ts-server-sdks.md` sections 5-6; Go notes
it cannot forcibly stop a handler goroutine, `server/middleware.go:81`). No server adapter
implements its own timeout.

## 5. User keys and credential transfer

The portable model is the versioned transfer envelope (`user-key/public`, `user-key/private`)
and the server-issued client credential (`user-key/credential/client`), canonical-byte templates
per `docs/design/user-keys.md` sections 3-4, imported through one strict ordered pipeline with a
shared closed error-class set (`docs/design/user-keys.md` sections 5-6). The trust tuple is
`{url, aud, server_public_key, server_kid}` supplied independently out of band; trust checks run
only after document validation; there is no TOFU, no silent pin overwrite, no automatic rotation
(`docs/design/user-keys.md` section 8; `userkey/doc.go` "Scope boundary"; `ts/README.md`
user-key section). Redaction guarantees: client role has no private-export API, server role
imports public material only, issuance results redact in Debug/String/JSON forms
(`docs/design/user-keys.md` sections 1, 9-10; `userkey/doc.go:6-28`). Input cap: 4096 bytes,
`oversized_envelope` beyond it (`docs/design/user-keys.md` section 5 step 1).

The shared fixture table `spec/fixtures/user-key-transfer.json` contains 66 cases: 14 positives,
51 negatives and 1 context case. This was counted directly in the fixture (array lengths of
`positives`, `negatives`, `context_cases`) and is pinned by the shape test
`ts/test/user-key-transfer.test.ts:447-452`. Per-language exercise: Go
`userkey/transfer_test.go` (1623 lines), Rust `rust/tests/user_key_transfer.rs` (2619 lines,
loading the fixture from `../spec/fixtures` per `rust/tests/common/fixtures.rs`), TypeScript
`ts/test/user-key-transfer.test.ts` (1373 lines, including the 14-row acceptance table of
`docs/design/user-keys.md` section 12.3).

## 6. Interop and consumers

Interop matrix: `interop/run.mjs` runs 22 normative scenarios (`interop/scenarios.json`, counted
and declared at `interop/README.md:3`) across every (client, server) language pair — 9 pairs
including the diagonal — built from six executables in CI (`.github/workflows/ci.yml:117-145`).
It also runs the byte-exactness phase against 8 sign cases (`interop/sign-cases.json`,
`interop/README.md:3-4,25`) and cross-verifies every (signing, verifying) pair via
`--verify-only`, including one tampered-body control per pair (`docs/design/interop.md` section
5).

Credential-transfer matrix: `interop/transfer.mjs` runs per-language transfer executables across
the 3x3 matrix and asserts the exact counts 9 credential pairs, 63 credential handoffs, 594 case
visits, 9 trust pairs, 9 public pairs, 225 public exports (`interop/transfer.mjs:52-53`); a
self-test using real SDK probes plus synthetic lifecycle/error controls runs first (`.github/workflows/ci.yml:175-177`). The 66-case fixture
table of section 5 is the input oracle.

Consumers: `tools/consumer/package-ts.mjs`/`verify-ts.mjs`, `package-rust.mjs`/`verify-rust.mjs`
and `package-go.mjs`/`verify-go.mjs` produce a private npm tarball, a `publish = false` crate
and a staged Go module snapshot, then install each into a fresh standalone consumer and
smoke-test it; each is restricted to GitHub Actions (`tools/consumer/verify-go.mjs:6-8` —
"CI-only") and uploads artifacts. Licence checking lives in `.github/workflows/license.yml`:
go-licenses with allowlist and fixture refusal controls (job at line 28), cargo-deny with
expression and refusal controls (line 47), npm allowlist checks including dev dependencies and
tooling (line 79), and dual-licence manifest checks with a negative fixture control (line 116).
These consumer and licence jobs run in CI only and cannot be exercised locally without the
CI-produced artifacts.

## 7. Test and CI inventory

| Capability | Go tests | Rust tests | TS tests | CI jobs |
|---|---|---|---|---|
| Auth header / signing / verification | `authheader` via `header_test.go`, `signing.go` via `client/signer_test.go`, `ed25519_test.go`, `spec/fixtures_test.go` | `rust/tests/verify_conformance.rs`, `keys_conformance.rs`, `client_sign*.rs` | `auth-header.test.ts`, `signing.test.ts`, `verify.test.ts`, `ed25519.test.ts` | `go` (Linux+Windows, `.github/workflows/ci.yml:13`), `go race` (36), `rust` (57) + no-default-features/http isolation (78-81), `rust 1.85 check` (86), `ts` (97, Node 20/22 Linux+Windows), `fixtures are up to date` (46) |
| Policy / patterns | `server/policy_test.go`, `pattern_test.go` | `policy_conformance.rs`, `patterns_conformance.rs` | `policy.test.ts`, `syntax.test.ts` | same per-language jobs |
| Server middleware / nonce / audit / state | `server/middleware_test.go`, `nonce_test.go`, `audit_test.go`, `state_test.go`, `statefile_test.go` | `rust/tests/state_file.rs`, `http_layer.rs` | `native.test.ts`, `nonce.test.ts`, `audit.test.ts`, `state.test.ts`, `state-file.test.ts`, `fetch.test.ts`, `node-http.test.ts` | same per-language jobs |
| Client transport / URL policy | `client/transport_test.go`, `urlpolicy_test.go`, `rotate_freshness_test.go` | `client_transport.rs`, `client_http_transport.rs`, `client_url_policy.rs` | `client-transport.test.ts`, `client-url-policy.test.ts` | same per-language jobs |
| User keys / transfer | `userkey/key_test.go`, `userkey/transfer_test.go` | `rust/tests/user_key.rs`, `user_key_transfer.rs` | `user-key.test.ts`, `user-key-transfer.test.ts` | `credential transfer matrix (3x3)` (`.github/workflows/ci.yml:149-177`) |
| Cross-language behavior | — | — | — | `interop matrix (3x3)` (`.github/workflows/ci.yml:117-145`) |
| Packaging / licences | — | — | — | `consumer ts` (181), `consumer rust 1.85` (211), `consumer go 1.22` (235), `license.yml` jobs (28, 47, 79, 116) |
| Coverage | `coverage.yml` jobs `go coverage` / `rust coverage` / `ts coverage`, artifacts `coverage-go` / `coverage-rust` / `coverage-ts`; `ts coverage` runs its summarizer regression controls via a `node --test` step | as declared | as declared | `.github/workflows/coverage.yml` (in-tree) |
| Fuzzing | `fuzz.yml` job `go fuzz (bounded campaign)`; 8 targets, 30 s fuzz + 10 s minimize per target; per-target execution and failing-input collection (Go's fuzz cache + package-relative testdata corpus, safe artifact naming) in `tools/fuzz/run-target.sh`; campaign loop in `tools/fuzz/go-campaign.sh`; collection/error-source controls in `tools/fuzz/campaign-selftest.sh`; failing inputs as artifacts | none | none | `fuzz_test.go`, `server/fuzz_test.go`, `client/fuzz_test.go`, `userkey/fuzz_test.go` |

As implemented in this delivery: `coverage.yml` with jobs `go coverage`, `rust coverage`,
`ts coverage` producing artifacts `coverage-go`, `coverage-rust`, `coverage-ts`; the Go job
summarizes with `go tool cover -func`/`-html` plus `tools/coverage/go-summary.mjs`
(`parseProfile` statement + line-span metrics) and runs its summarizer regression
controls via `node --test tools/coverage/go-summary.test.mjs tools/coverage/lcov-summary.test.mjs`,
the Rust job with
`tools/coverage/lcov-summary.mjs` (strict DA parsing), and the TS job with
`ts/scripts/coverage-summary.mjs` (`aggregateExecutions` + source inventory, fail-closed);
the `ts coverage` job runs its summarizer regression controls via `node --test scripts/coverage-summary.test.mjs`.
`fuzz.yml` job `go fuzz (bounded campaign)`: a 25-minute-timeout, 8-target bounded campaign
via `tools/fuzz/go-campaign.sh` with 30 s fuzzing plus 10 s minimization per target —
`FuzzParseRequestAuth`, `FuzzParseResponseAuth`, `FuzzMatchPattern` (`fuzz_test.go`),
`FuzzClassifyBody`, `FuzzParsePolicy` (`server/fuzz_test.go`), `FuzzLoadProfile`
(`client/fuzz_test.go`), `FuzzImportEnvelopes`, `FuzzValidateCredential`
(`userkey/fuzz_test.go`) — each run by `tools/fuzz/run-target.sh` (bounded go test run;
failing-input collection from Go's fuzz cache and the package-relative testdata corpus;
safe artifact naming), with collection/error-source controls in
`tools/fuzz/campaign-selftest.sh` and logs plus failing inputs uploaded as artifacts.

## 8. Known limitations and gaps

1. **Fuzzing is Go-only by design.** Neither `rust/` nor `ts/` has any fuzz or property-fuzz
harness (no `cargo-fuzz` targets under `rust/`, no fuzz test in `ts/test/`). Parsers that face
hostile input in those languages — the TS hand-written base64url decoder and surrogate precheck
(`ts/src/user-key-transfer.ts`, decoder per `docs/design/rust-ts-server-sdks.md` section 4), the
Rust import pipeline (`rust/src/user_key.rs`) — are covered
only by curated fixture cases, not by randomized input. Fix (narrow): cargo-fuzz targets for the
Rust import/auth-header parsers and a property-based (`fast-check`-style) random-input harness
for the TS decoder, run bounded like the Go campaign.
2. **Go statement coverage does not measure branches.** `go test -cover` counts
statements/blocks; condition-level coverage (e.g. the many `if b <= 0x20 || b == 0x7f` style
branches in `client/urlpolicy.go:67-71`) is invisible. Fix: none within the toolchain; report
the limitation and rely on the fixture-driven negative tables (`client-url-policy.json` rows)
for branch confidence.
3. **Rust branch coverage requires a nightly compiler.** `-C instrument-coverage` based branch
coverage (LLVM `branch` region mapping) is nightly-only; CI's stable toolchain
(`dtolnay/rust-toolchain@stable`, `.github/workflows/ci.yml:69`) yields region/line coverage
only. Fix: either accept line coverage on stable or add a separate nightly job if branch data is
required.
4. **TypeScript coverage is measured on `tsc`-emitted JS, not TS source lines.** The test script
compiles first (`tsc -p tsconfig.test.json && node scripts/run-tests.mjs`, `ts/package.json`
"scripts"), so any instrumentation applies to `dist-test/` output; line numbers do not map 1:1
to `src/`. Fix: source-map remapping in the coverage report step, or an accept-and-document note
in `coverage.yml`.
5. **State-file loaders have no fuzz coverage.** The Go campaign covers the body classifier (`FuzzClassifyBody`) and the policy compiler
(`FuzzParsePolicy`) in `server/fuzz_test.go`; `server/statefile.go`'s
strict loader (`server/statefile.go:65-132`) and the equivalent Rust/TS loaders take
operator-controlled documents and have no fuzz target. Fix: add a `FuzzLoadStateFile`-style Go
target and randomized-load tests elsewhere.
6. **Transport timeouts are delegated in Go and TypeScript.** Go's `NewHTTPClient` sets no
`Timeout` (`client/transport.go:97-99`) and `Config.HTTP` is caller-owned
(`client/doc.go:40-46`); TS forwards only an `AbortSignal`
(`ts/src/client/transport.ts:67`) and the server adapters explicitly leave whole-call deadlines
to the caller (`ts/README.md` server section; `server/middleware.go:81`). Only the Rust
`client-http` transport enforces a timeout (15 s default,
`rust/src/client/http_transport.rs:29`). This is documented behavior, not a bug; the gap is
documentation-only: readiness reviewers must not read "coverage" as implying timeout behavior is
SDK-guaranteed everywhere.
7. **Byte caps bound bytes, not time, on all server adapters** (`server/middleware.go:62-81`;
`docs/design/rust-ts-server-sdks.md` section 5): a never-yielding upstream body is not stopped
by the cap. Same documentation-only caveat as gap 6.
8. **Streaming signatures are unspec'd** (spec README open question Q1, `spec/README.md`): all
clients refuse `text/event-stream` (`client/transport.go:208-213`,
`rust/src/client/transport.rs:114,305`, `ts/src/client/transport.ts:344`) and all servers answer
501. Coverage of the refusal paths exists, but the streaming protocol itself is out of scope for
this readiness cycle.

Not gaps (verified, so not listed above as deficiencies): Go response size cap, redirect
refusal, URL policy, freshness window, nonce retention, atomic state writes and the 66-case
transfer table are all implemented and tested as documented (citations in sections 3-5).

## 9. Not covered by this review

Runtime CI observation (green/red status of any workflow), release and publishing decisions
(crate/npm/Go module remain unpacked-locally, `private: true` retained, `ts/package.json`),
live-network behavior including real TLS peers, DNS behavior under resolver variation, proxy
environments, and performance or soak characteristics. The coverage and fuzz workflows are
reviewed as in-tree files of this delivery; runtime execution of any workflow is observed
separately by the operator and is not claimed here.
