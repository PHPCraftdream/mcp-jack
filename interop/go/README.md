# Go interop executables

Builds the `interop-server` and `interop-client` of `../README.md` sections
4–5 (module `github.com/PHPCraftdream/mcp-jack`, Go >= 1.22, no external
dependencies).

## Build

The harness expects the binaries at `interop/bin/go-server` and
`interop/bin/go-client` (see `../targets.json`; on Windows add `.exe`):

```
mkdir -p interop/bin
go build -o interop/bin/go-server ./interop/go/server
go build -o interop/bin/go-client ./interop/go/client
```

## Usage

```
interop-server --aud <aud> --policy <file> --state <file> --server-seed-hex <64 hex>
               [--bootstrap-ttl <seconds>] [--verify-only]
```

All four required flags must be present; any startup failure (missing flags,
bad hex, unreadable or invalid state/policy file) prints to stderr and exits 1
without ever writing to stdout.

Serve mode binds `127.0.0.1:0`, prints exactly one stdout line

```
{"ready":true,"port":<n>,"server_public_key":"<b64u>","server_kid":"<kid>"}
```

and serves through `server.NewHandler` in front of the fixed trivial MCP
handler. `--bootstrap-ttl` mints one admin invite via
`server.BootstrapAdmin` and prints `{"bootstrap_invite":"<code>"}` to stderr.
The server exits 0 on SIGTERM, Ctrl-C or stdin EOF.

`--verify-only` reads one JSON object from stdin
(`{"method","target","jack_auth","body_b64u"}`), performs request-auth steps
1–4 and 7 of spec 01 section 4 (steps 5/6/8 skipped — the sign cases use fixed
`ts` 0 and 999999999999), prints one line
`{"verify":"accept","kid":"<kid>"}` or `{"verify":"reject","code":"<code>"}`
and exits 0 either way.

## Files

- `server/main.go` — the interop-server: flag parsing, startup, verify-only
  mode, HTTP wiring and the MCP handler.
- `client/main.go` + `client/scenarios.go` — the interop-client: CLI parsing
  and the raw/typed step machinery in `main.go`, the per-scenario
  implementations in `scenarios.go`.

Notes:

- The verifier uses the spec default 30 s timestamp window and the wall clock
  (Config `Window`/`Now` left zero/nil).
- `logs.tail` and `config.set` have handlers even though the harness policy
  denies them before they are reached; they exist per the contract table.
