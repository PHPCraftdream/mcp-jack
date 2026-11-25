# Official MCP SDK end-to-end compatibility fixtures (tools/mcp-e2e)

Bounded profile from `docs/design/mcp-compatibility.md`: legacy Streamable HTTP
`2025-11-25` entered by stdio, one JSON-RPC object per POST, no-session upstream
in JSON-response mode, exercised as the full chain official stdio client →
`jack bridge` → signed `jack gateway` → official Streamable HTTP server; 3
clients × 3 servers = 9 cells (Go go-sdk v1.8.0, TS client+server 2.4.0 with
@modelcontextprotocol/node 2.1.2, Rust rmcp 3.9.0), plus one response-tamper
cell per client × server pair and per-cell GET recording (G4). That document is
the source for every expectation below.

## Layout

| Path | Contents |
| --- | --- |
| `go/` | Nested Go module (own `go.mod`, toolchain 1.25.0; NEVER touched by root `go` commands): `cmd/client` and `cmd/server` on go-sdk v1.8.0. |
| `ts/` | Exact-pinned `package.json`; `client.mjs` (official SDK client over `StdioClientTransport` spawning `jack bridge`); `server.mjs` (`createMcpHandler(factory, {responseMode:'json'})` served via `toNodeHandler` on a Unix socket). |
| `rust/` | Standalone Cargo package (NOT part of the root `rust/` crate): `mcp-e2e-rust-server` (StreamableHttpService in JSON-response mode on a Unix socket) and `mcp-e2e-rust-client` (spawns `jack bridge`; lifecycle + `tools/list` + `tools/call`). |
| `run.mjs` | Dependency-free Node >= 22 driver: locked/frozen builds (env overrides below), per-cell key/state provisioning via the real CLI flow, capture proxy, per-hop assertions. |

## Pins

Taken from `docs/design/mcp-compatibility.md`; CI confirms them by installing
and building from exactly these declarations.

| Component | Pin | File |
| --- | --- | --- |
| Go SDK | `github.com/modelcontextprotocol/go-sdk` v1.8.0 (toolchain Go 1.25.0) | `tools/mcp-e2e/go/go.mod` |
| TS client / server | `@modelcontextprotocol/client` 2.4.0, `@modelcontextprotocol/server` 2.4.0 | `tools/mcp-e2e/ts/package.json` |
| TS node adapter | `@modelcontextprotocol/node` 2.1.2 | `tools/mcp-e2e/ts/package.json` |
| Rust SDK | `rmcp` `=3.9.0` (features `client`, `transport-child-process`, `transport-streamable-http-server`) | `tools/mcp-e2e/rust/Cargo.toml` |

## Lockfiles

`go/go.sum`, `ts/package-lock.json`, and `rust/Cargo.lock` are committed, and CI
builds from exactly these lockfiles using frozen installs: `go mod download`,
`npm ci`, and `cargo build --locked --release`. CI fails if any lockfile is
missing. Lockfiles are regenerated in CI only, never on a developer machine, with
`go mod tidy` inside `tools/mcp-e2e/go`, `npm install --package-lock-only` inside
`tools/mcp-e2e/ts`, and `cargo generate-lock` inside `tools/mcp-e2e/rust`; the
owner commits the results afterwards. Never hand-edit lockfiles.

## How CI runs it

The `mcp-compat-e2e` job in `.github/workflows/ci.yml` runs on `ubuntu-latest`
only (jack's private-file storage is Unix-only; `docs/design/cli.md` says Windows fails closed). Steps:

- Install Go 1.25.0 (the fixture toolchain; the root module floor is 1.25.0), Node 22, and stable Rust, with `Swatinem/rust-cache` scoped to `tools/mcp-e2e/rust`.
- Fail clearly if any fixture lockfile (`go/go.sum`, `ts/package-lock.json`, `rust/Cargo.lock`) is missing.
- Frozen installs: `go mod download` in `go/`, `npm ci` in `ts/`; then `cargo build --locked --release` in `rust/`.
- Build the shipping CLI (`CGO_ENABLED=0`, `go build -trimpath -o "$RUNNER_TEMP/jack" ./cmd/jack`, mirroring `go-cli-process`).
- Run `node tools/mcp-e2e/run.mjs` with `JACK_BIN` pointing at it.

Local runs need the three fixture toolchains provisioned, then
`node tools/mcp-e2e/run.mjs` (`--clients`, `--servers`, `--list`, `--keep`,
`--allow-skip-ts-server`); override builds per artifact with
`JACK_BIN`, `GO_CLIENT_BIN`, `GO_SERVER_BIN`, `RUST_CLIENT_BIN`, `RUST_SERVER_BIN`.

## Exit codes and skips

- `2` — usage error or artifact-resolution failure (missing committed lockfile,
  failed fixture/CLI build, or a `*_BIN` override pointing at a missing file).
- `1` — any cell FAILED.
- `0` — only when every required cell ran.

A TS-server cell that cannot run (the known TS server 2.4.0
initialize→SSE→gateway 501 `streaming_unsupported` limitation) FAILS the run by
default; exiting 0 with SKIPs is no longer possible. Passing
`--allow-skip-ts-server` permits skipping exactly those cells: every skipped
cell is listed by name (`SKIP <client>-client x ts-server`) in the summary.
Nothing else may be skipped — artifact unavailability or any failure on a
non-TS-server cell FAILS with or without the flag.

## What is asserted per cell

- Hop captures between bridge and gateway (capture proxy): method, status, media type, body.
- Exactly the sequence `initialize` → `initialized` → `tools/list` → `tools/call`, with the `tools/call` echo result matching.
- The notification POST is answered 202 with an empty body.
- Protocol version `2025-11-25` is preserved in both directions.
- `Accept` always contains both `application/json` and `text/event-stream`; `Jack-Auth` is present.
- Bridge stdout purity: driver-side framing probe over raw stdio sees exactly the expected JSON-RPC frames, empty stderr, exit 0.
- Tamper cells (one per client × server pair): one flipped response byte at the proxy — upstream still answers 200, but the bridge exits 1 with zero stdout bytes and stderr exactly `jack: remote call failed; no retry performed`. TS-server tamper cells hit the same known SSE limitation and follow the fail-by-default / `--allow-skip-ts-server` rule.
- GET probes recorded per cell (see G4 below); exit 0 only when every required cell ran — skipped TS-server cells only via `--allow-skip-ts-server`, each listed by name.

## G4: recorded vs asserted vs source-derived

Within this stdio chain the bridge issues POST only — no official client GET ever traverses the chain; recorded GET evidence per cell:

- Upstream GET probe driven directly against the official server's Unix socket: expected source-derived 405 for the Go and Rust servers (stateless JSON-response mode); the TS server's GET status is recorded, not asserted.
- Unauthenticated GET against the gateway: asserted 401 (unsigned pre-auth rejection per `server/middleware.go`). The signed 405 an authenticated GETter would receive cannot be produced by this driver — only the bridge can produce `Jack-Auth`, and the bridge never GETs.

The per-client GET tolerance table stays source-derived from
`docs/design/mcp-compatibility.md`: Go — 405 benign, non-SSE 501 warn/close not fatal, SSE 501
fatal; TS — 405 benign, either-content-type 501 fatal `ClientHttpFailedToOpenStream`; Rust — 405 →
`ServerDoesNotSupportSse` benign, either-content-type 501 an HTTP status error. The G4 runtime question
(gateway answering GET with 501 vs 405) cannot arise inside this profile; the job records the raw
inputs and keeps the conclusion explicit rather than claiming a runtime pass.

## Limits and known gaps

- Bounded profile only: no SSE, no sessions, no cancellation, no batches, no modern `2026-07-28`.
- Official clients never exercise their own HTTP transports against the gateway (that is the separate proposed `mcp-http-client-transports` job).
- TS server GET status recorded, not asserted; Rust server-side capture logs only the initialize request parts (go/ts log more); bridge stderr capture through the SDK clients is best-effort; each tamper cell flips exactly one response byte at the proxy.

## Product bugs

Failures caused by bridge/gateway defects are reported in the job output and surfaced to the
parent; this fixture tree never patches `go/` or `internal/` product code.
