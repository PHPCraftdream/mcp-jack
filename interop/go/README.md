# Go interop executables

The Go integration source lives under `interop/go/`: `server/main.go` implements `interop-server`; `client/main.go` and `client/scenarios.go` implement `interop-client`; `transfer/main.go` is the independent credential-transfer probe. These are harness programs, not part of the Go SDK API. The SDK itself is the module's `client/`, `server/`, and `userkey/` packages plus root protocol primitives.

The migrated SDK contract has ordinary MCP requests forwarded unchanged and hands the handler immutable verified identity. Application authorization is the handler's responsibility; the protocol's `admin` flag gates reserved `jack.admin.*` tools only. Legacy user/state `kind` and `scopes` fields are rejected without migration or rewrite.

## Current server interface

`interop-server --aud <aud> --state <file> --server-seed-hex <64 hex>` accepts optional `--bootstrap-ttl <seconds>` and `--verify-only`; it takes no policy-file input. Serve mode uses the Go `server` SDK, listens on loopback, prints a JSON ready line to stdout and reports diagnostics on stderr. The current MCP handler demonstrates application-owned authorization using `server.IdentityFromContext`.

In `--verify-only` mode the process reads one JSON object from stdin (`method`, `target`, `jack_auth`, `body_b64u`) and checks its signature against the configured audience and state. Fixed signing cases skip key validity, time-window and nonce checks. It emits one accept/reject JSON verdict and exits successfully for either verdict.

## Client and status

`interop-client` accepts `--url`, `--seed-hex`, `--server-public-key`, `--aud`, and `--scenario`; optional inputs are `--seeds`, `--ts`, `--nonce`, and repeatable `--arg k=v`. `sign-only` uses fixed values and does not contact a server. The Go interop sources implement identity forwarding for POST/GET and dot-segment targets, plus malformed required-boolean admin-input controls; `scenarios.json` is the shared expected-outcome source. Parent CI passed on `444c69b`; these are implemented harness cases, not design-only work.

Signing parity, freshness/replay, trusted server responses, signed authenticated errors and last-active-admin behavior remain coverage requirements. For transfer-envelope behavior see [the independent user-key contract](../../docs/design/user-keys.md); it is separate from request interop.
