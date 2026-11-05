# Checkpoint — 2026-11-05 18:52 [mcp-jack-rust-ts-interop-handoff]

## Session summary

mcp-jack is a secure transport protocol that wraps plain MCP (Ed25519 signature on every request and response, server-owned policy, user management as `jack.*` tools). The Go SDK, the specification (`spec/01-04`) and the shared fixtures existed before this stretch of the session (see `mcp-jack-go-sdk-handoff.md`).

In this stretch the user asked for server SDKs with tests for Rust and TypeScript, then for client SDKs and cross-language tests ("клиентские и серверные SDK корректно работают с противоположными SDK других языков"). Designs are in `docs/design/rust-ts-server-sdks.md` and `docs/design/interop.md`. Everything is committed locally on `main` as one commit per task; nothing is pushed (there is no remote).

Delivered and merged: shared-fixture edge cases (integers judged on JSON text, invalid UTF-8, strict base64url; one Go fix in `server/native.go` `intFrom`); Rust crate in `rust/` (primitives, stores, policy, verifier, native tools, tower adapter `JackLayer`, client SDK); TypeScript package in `ts/` (primitives, stores, policy, verifier, native tools, Fetch and `node:http` adapters, client SDK); CI jobs for Rust and TypeScript; the interop harness in `interop/` (`run.mjs`, contract in `interop/README.md`, `scenarios.json` with 22 scenarios, `sign-cases.json`, self-test with fakes); Go interop executables in `interop/go/`; TypeScript interop executables in `ts/src/interop/`.

In flight: task #33, the Rust interop executables, is being written by a `rush` sub-agent in the worktree `worktrees/sdk-interop-rust` on branch `sdk-interop-rust` (session id `sdk-interop-rust`, prompt and output in `.rush/stdin/sdk-interop-rust.*`). The worktree is based on `296c34c`. A babysit cron (every 15 minutes, session-only) is armed.

**Nothing in this stretch has been compiled or run, except by `cargo fmt/check/clippy` for Rust.** The user's rule is that builds and tests run in CI only, and there is no GitHub remote, so no test of Go, Rust or TypeScript has ever executed. Rust code passes `cargo fmt --check`, `cargo clippy -D warnings` and `cargo check` (also for the Linux target and with `--no-default-features`); TypeScript and Go were only read and reviewed (Go also `gofmt`). Every module went through a zero-trust review by rush's reviewer role; the reviewer's FAIL verdicts were mostly real defects (compile errors, failing test oracles, spec divergences) that were fixed in follow-up rounds, and a few were wrong and were rejected after checking.

## Active goal

none

## TaskList

### in_progress
- #33 Interop: Rust server and client executables  (blockedBy: none open)

### pending
- #35 Interop: CI job running the 3x3 matrix  (blockedBy: #33)
- #28 Cross-SDK review and README update  (blockedBy: #35)

### recently completed
- #14 shared-fixture edge cases; #15-#20 Rust scaffold, primitives, stores, verifier, native tools, tower adapter; #21-#26 TypeScript scaffold, primitives, stores, verifier, native tools, adapters; #27 CI jobs; #29 Rust client; #30 TypeScript client; #31 interop harness and contract; #32 Go interop executables; #34 TypeScript interop executables

## Decisions

- Same polarity everywhere for the nonce store: `check_and_record` / `checkAndRecord` returns true on a live replay (Go reference), false when recorded fresh.
- Omitted or null `kind` in a stored registry entry means `human`; for tool arguments an explicit `kind: null` is `invalid_params` (spec 03 section 3, reference verifier and Go agree).
- Integer arguments are judged on their JSON text (no fraction, no exponent, `-0` is 0); Rust and TypeScript implement it lexically, Go via decoding into `int64`.
- Authentication failures are not signed; authenticated rejections (403, 409, 501, 400) must be signed and the clients verify them; the clients report only the status for an unsigned 401.
- Streaming (`text/event-stream`) is refused with a signed 501 by all three servers; the check happens on the header before the body is read.
- `effect: null` in a policy is rejected (spec wins over Go and the reference verifier); a BOM at the start of a request body is rejected by the TypeScript verifier.
- Rust MSRV is 1.85; `Cargo.lock` is committed (format 4); no TypeScript lockfile exists yet, so CI uses `npm install`.
- Rejected after checking: a reviewer claim that `interop/scenarios.json` was invalid JSON, and a claim that JavaScript `$` matches before a trailing newline.

## Open questions

- Create a private GitHub repository (suggested `PHPCraftdream/mcp-jack`) and push so CI can run the tests? The user has not answered; nothing runs anywhere until then.
- Allow local `cargo test`, `tsc --noEmit`, `go build` (and one-off Node checks of pure logic)? Each review round caught defects that a compiler would have shown in seconds.
- Licence is undecided. Spec open questions Q1-Q11 are open (Q11: duplicate JSON keys are last-wins everywhere, unspecified).
- Go gaps to fix in #28, all listed in the description of task #28: the Go client keeps HTTP 401 on client-side response errors; the Go state loader rejects an omitted `kind` and its spec test never feeds the registry load vectors through the loader; `profile_test.go` references an undefined `NewClientFromProfile`; `TestAdminListDecodesWrappers` queues one nonce for two calls; the Go client parses the body of an unsigned 401 and detects streaming through `mime.ParseMediaType`.

## Repo state

```
(main is clean; the worktree worktrees/sdk-interop-rust holds uncommitted work of task #33)
```

```
5e10e6a Interop: TypeScript server and client executables
296c34c Rust SDK: tower HTTP adapter
e76c955 TypeScript SDK: Fetch and node:http adapters
51c49e6 Rust SDK: protocol-native tools and bootstrap
413112e TypeScript SDK: protocol-native tools and bootstrap
```
