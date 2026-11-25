# Modern official-SDK E2E fixture contract

This contract implements `docs/design/mcp-e2e-modern.md` scenarios 1–8 for Go and TypeScript official SDK fixtures. The legacy suite under `tools/mcp-e2e/` is independent and must not be modified, imported, or used as a fixture. SDK packages are Go `github.com/modelcontextprotocol/go-sdk` and TS `@modelcontextprotocol/client`, `@modelcontextprotocol/server`, `@modelcontextprotocol/node`. Resolve exact versions only from `tools/mcp-e2e-modern/pins/`; never hardcode a version here or in fixture behavior.

## Layout and manifest

| Path | Contents |
| --- | --- |
| `tools/mcp-e2e-modern/fixtures.json` | Driver-read manifest of prebuilt fixture artifacts. The driver never builds fixtures. |
| `tools/mcp-e2e-modern/go/cmd/server/` | Go official-SDK HTTP server fixture. |
| `tools/mcp-e2e-modern/go/cmd/client/` | Go official-SDK client fixture. |
| `tools/mcp-e2e-modern/ts/server.mjs` | TypeScript official-SDK HTTP server fixture. |
| `tools/mcp-e2e-modern/ts/client.mjs` | TypeScript official-SDK client fixture. |
| `tools/mcp-e2e-modern/pins/` | Exact SDK pins and lock data, maintained by the pin owner. |
| `tools/mcp-e2e-modern/lib/config.mjs` | Driver single source of timeout defaults and timeout flag names. |

`fixtures.json` is UTF-8 JSON with this exact shape; all keys are required, with no additional driver-interpreted fields:

```json
{
  "fixtures": {
    "go-server": {"build_kind":"go-binary","artifact":"go/bin/server","env":"GO_SERVER_BIN"},
    "go-client": {"build_kind":"go-binary","artifact":"go/bin/client","env":"GO_CLIENT_BIN"},
    "ts-server": {"build_kind":"node-script","artifact":"ts/server.mjs","env":"TS_SERVER_BIN"},
    "ts-client": {"build_kind":"node-script","artifact":"ts/client.mjs","env":"TS_CLIENT_BIN"}
  }
}
```

`build_kind` is exactly `go-binary` or `node-script`; `artifact` is a path relative to `tools/mcp-e2e-modern/`; `env` is the corresponding optional `*_BIN` override. For a Go artifact the override names an executable; for a Node script it names the script path (run using `node`). Missing artifacts/invalid manifest/invalid override are harness errors (exit 2), not SKIPs. Fixtures are built elsewhere from committed pins/locks; the driver performs no build/install. SDK name/version values are reported by fixtures and must match the pin data, not a duplicated constant.

## Process and JSON-line conventions

All fixture arguments use the exact long option names below; options with values use the next argv item. No shell is involved. Fixture subprocesses inherit the driver-provided environment plus manifest `env`; secrets are never placed in argv. Server and client stdout each contain exactly one UTF-8 machine-readable JSON object line per process (newline terminated), with no other output. Server stdout is its ready line; client stdout is its result line. Go/Node diagnostics, SDK logs, and child `jack bridge` stderr go only to stderr. Every control request/response, ready/result record, and manifest is one JSON object per line/document as applicable. Driver rejects extra stdout lines, malformed JSON, or non-object records.

Server common argv: `--listen 127.0.0.1:0`; `--control-listen 127.0.0.1:0`; optional `--legacy-only`. Bind both sockets before emitting the ready line. The actual address and control address are returned there. `--legacy-only` is a deterministic legacy negative-control mode and is not official-SDK coverage; it must reject modern requests without initializing or silently serving modern protocol.

Client common argv: `--scenario <1..8>`, `--server <go|ts>` (SDK identity label), and exactly one mode: direct mode uses `--direct --url <address>` (the URL is the address to connect to and exactly one `--url` flag appears); Jack mode uses `--bridge-bin <path> --bridge-config <path> --era <modern|auto>`. `--url` never appears in Jack mode; `--bridge-*` never appears in direct mode. Key material is delivered through the driver-written bridge config, not client argv. `--scenario` is always required. For scenario 5 direct mode additionally accepts `--config <path>` carrying the same JSON credentials as the bridge config minus `era`, for the SDK Jack auth hook.

### Bridge spawn contract (Jack mode)

The fixture spawns exactly `jack bridge --config <path>` using the config file written by the driver, inherits driver environment, passes through the child's stdio, collects bridge stderr separately, and terminates/reaps the child. The bridge endpoint is the driver's capture-proxy URL. Config JSON has exactly these fields: `{"version":1,"endpoint":"<capture-proxy-url>","aud":"<audience>","server_public_key":"<key>","server_kid":"<kid>","key_file":"<user-secret-file>","key_format":"raw-seed","call_timeout_ms":<integer>,"era":"modern|auto|"}`. Scenario 5's optional probe may reuse this mechanism.

## Server fixture

Implement with the official SDK server and modern Streamable HTTP transport, listening on the ephemeral loopback address specified above. Ready stdout schema (exact keys, all required):

```json
{
  "address":"http://127.0.0.1:<port>",
  "control_address":"http://127.0.0.1:<port>",
  "sdk":{"name":"<package/module>","version":"<exact pinned version>"},
  "capabilities":[{"id":"<capability id>","status":"supported|unsupported|unknown","evidence":"<API evidence>"}]
}
```

`address`, `control_address`, `sdk.name`, `sdk.version`, and every capability object's `id`, `status`, `evidence` are required strings; `capabilities` is an array containing every manifest ID defined below exactly once. `evidence` identifies the actual SDK API or says why unsupported/unknown; do not claim runtime support based only on a fake handler.

Register:

* `echo`: deterministic, returns the supplied `value` unchanged, and has NO registered parameter mirror. The bridge never sends `Mcp-Param-*` (nil annotations); the gateway may forward such headers only if the client produced them. Preserve applicable modern per-request `_meta`.
* `progress`: accepts `count` and optional `hold`/`call_id`; emits exactly `count` progress notifications with monotonically increasing progress values `1..count`, then terminal deterministic result. When held, keep the call live after notifications until released by control endpoint or cancelled. The client result reports observed notifications in delivery order.
* `listen`/subscription: expose the official SDK `subscriptions/listen` tool/method and lifecycle only if the SDK actually provides it. Do not emulate unsupported SDK capability. If implemented, deliver a deterministic notification and clean end.

Control channel is loopback-only and excluded from MCP traffic. Exact endpoints:

* `POST /v1/release`, JSON body `{"call_id":"<string>"}`; release the matching held `progress` call. Respond `200` with `{"released":true,"call_id":"<string>"}` or `404` with `{"released":false,"call_id":"<string>"}` if no held call matches.
* `GET /v1/cancelled?call_id=<URL-encoded string>`; respond `200` with `{"call_id":"<string>","cancelled":true|false}`. `true` only after the SDK request/stream cancellation has reached the fixture; this endpoint must not itself cancel anything.

Control JSON responses are one object; control logs go stderr. Track cancellation from actual request/stream closure, not a synthetic cancellation POST. Ready line is emitted only after both listeners and SDK server are ready. A server ready line whose capability `evidence` is empty or whitespace is INVALID (harness error).

## Client fixture

Use the corresponding official SDK client. In direct mode connect to the server's `address` with modern HTTP. In Jack mode connect via the spawned `jack bridge` stdio transport; `--bridge-config` is written by the driver and its `endpoint` is the driver's capture-proxy URL. The fixture must not decide that an SDK capability is supported merely because a scenario could be scripted.

Exactly one result object on stdout, with these required keys and types:

```json
{
  "scenario":1,
  "sdk":{"name":"<package/module>","version":"<exact pinned version>"},
  "outcome":"ok|fail|unsupported",
  "tool_result":null,
  "sdk_error":null,
  "request_meta":null,
  "bridge":{"spawned":true,"exit_code":null,"stdout_bytes":0,"stderr_tail":""},
  "progress":[{"progress":1,"total":3}],
  "capability_evidence":null,
  "timings":{"started_ms":0,"first_event_ms":null,"completed_ms":1,"cancelled_ms":null}
}
```

`request_meta` is the `_meta` object the client sent with its `tools/call`; it MUST be non-null for scenario 3 and null otherwise. `bridge` is required. In direct mode `spawned` is false and other fields are null/0 (stderr tail empty); in Jack mode, `exit_code` is the bridge exit code (null if killed/timed out), `stdout_bytes` counts bridge stdout bytes, and `stderr_tail` is a bounded tail of at most 2000 characters. Scenarios 2 and 8 assert these bridge fields, not the fixture's own exit. `scenario` is integer 1–8. `tool_result` is the SDK-decoded tool result or null; `sdk_error` is the SDK-surfaced error or null (at most one of these is non-null for a terminal call). `progress` is an ordered array of observed notifications, each with required numeric `progress` and optional numeric `total`; preserve arrival order. `capability_evidence` is null except when `outcome` is `unsupported`, then it is a nonempty string naming the missing SDK API/capability and evidence. Timings are elapsed integer milliseconds from fixture start: `started_ms` is 0; `first_event_ms` and `cancelled_ms` are null until applicable; `completed_ms` is terminal completion elapsed time or null if not completed. `outcome:"unsupported"` may only be used for capability-based omission of scenarios 4–7, never as a pass. Required scenario failures use `fail`.

Scenario calls: 1 invokes `echo` via auto-era bridge and observes modern discovery/traffic at driver proxy; client itself must not initialize. 2 attempts `echo` through explicit modern bridge to legacy-only/scripted control and surfaces the SDK error, with no retry; `bridge.exit_code` must be nonzero, `bridge.stdout_bytes` zero, `sdkErrorPresent` true, `refusedCount >= 1`, and `fallbackCount === 0`. 3 invokes `echo` with deterministic value and applicable `_meta`. 4 invokes held `progress`, records ordered progress then terminal result. 5 is the separate authenticated direct HTTP no-opt-in refusal oracle where SDK transport can set required Jack auth; require verified gateway 501 `streaming_unsupported`, otherwise report capability evidence, not fabricated success. 6 invokes held `progress`, uses the SDK's own cancellation API if exposed, then reports cancellation timing; never simulates SDK cancellation. 7 invokes official `subscriptions/listen` only if both SDK endpoints expose it. 8 invokes `echo` through buffered tamper proxy; require nonzero numeric `bridge.exit_code`, zero `bridge.stdout_bytes`, and `fabricated_result !== true`. See scenario observations below.

## Capability and scenario matrix

Capability manifest IDs are exactly: `stdio_client`, `streamable_http_server`, `stateless`, `progress`, `cancellation`, `subscriptions_listen`, `server_discover`, `protocol_2026_07_28`. Each manifest value has exactly `{id,status,evidence}`, with `status` one of `supported`, `unsupported`, `unknown`. Evidence is API-specific. A server capability `unknown` is a FAIL; the harness cannot skip on unknown. `unsupported` is SKIP with evidence, and SKIP is permitted only for scenarios 4–7.

| Scenario | Required? | Path and assertion |
| --- | --- | --- |
| 1 auto detection, no initialize | Required | `bridge-auto-both`: separately record bridge-generated signed `server/discover` and subsequent SDK traffic; verify signature and modern response before selection; assert modern POST sequence and no `initialize`/`initialized`; expected echo result. |
| 2 no silent downgrade | Required | Explicit `bridge-modern` to legacy-only or scripted legacy control; require `bridge.exit_code` to be a nonzero number, `bridge.stdout_bytes === 0`, `sdkErrorPresent`, `refusedCount >= 1`, and `fallbackCount === 0`; no initialize or legacy retry/fallback requests. Runtime error shape is not fixed. Scripted control is labeled non-SDK. |
| 3 tool call + metadata | Required | Direct controls and `bridge-modern`; deterministic echo; assert exactly the mirrors the bridge really builds — protocol version, method (`Mcp-Method`), tool name (`Mcp-Name`) — and that modern `_meta` has the SAME values on all observable hops: client→bridge (as reported by the fixture), bridge→gateway (capture proxy request), gateway→server (relay-decoded request body); verify signed response at bridge. |
| 4 progress stream | Capability-skippable | Direct control and bridge path only with verified stream capability. Jack-specific `Jack-Accept: s1`, signed status-200 event stream and frame-signature checks (including terminal `end`) apply only to Jack-path cells. Direct cells assert SDK-observed progress ordering and proxy-observed SSE frames only. First progress is visible before terminal; client observes ordered progress then result. |
| 5 missing-opt-in refusal | Capability-skippable | Separate authenticated direct SDK HTTP control to modern/both gateway without `Jack-Accept: s1` (or isolated signing-boundary harness). Oracle: signature-verified 501/code `streaming_unsupported`. Do not claim bridge stream-success covers missing opt-in. Bridge's resulting generic protocol error is not the oracle; record known gap. Never use modern request against legacy gateway. |
| 6 live cancellation | Capability-skippable | Driver incrementally captures stream, sees progress, then invokes SDK abort/context-cancel API. Client fixture may accept one stdin command line `cancel\n` for scenario 6 only; stdin remains open until then, and receiving it aborts the in-flight call through the SDK's own abort API, never a `notifications/cancelled` POST. The client fixture owns its `jack bridge` child's stdin; the DRIVER only ever writes the `cancel` command to the client fixture's own stdin and never claims or asserts a bridge-stdin cleanup. HTTP cancellation is stream/request closure. Assert proxy aborts upstream and no late frame; gateway must not send `notifications/cancelled` upstream. |
| 7 `subscriptions/listen` | Capability-skippable | Only if both official endpoints expose method and stream lifecycle; assert delivered notification, clean end, opt-in, signed stream and client-visible order. No fake handler substitute. |
| 8 tamper | Required | Separate buffered tamper-only proxy flips a captured signed response; upstream response remains successful; assert `bridge.exit_code` is a nonzero number, `bridge.stdout_bytes === 0`, and `fabricated_result !== true`. Never use buffering for stream/cancellation. |

Direct SDK-to-SDK controls are required for every no-Jack cell kind, using official client/server where capability exists. Direct cells have no Jack signature oracle. Jack paths are `bridge-modern` (bridge era modern, modern gateway) and `bridge-auto-both` (era auto, gateway profile both). Scenario 5's isolated/authenticated refusal control and scenario 2's scripted legacy control are explicitly separate path kinds, not official-SDK cells. Record every eligible cell and every capability-based omission; unavailable artifacts are failures, not capability skips.

## Driver ledger, attribution, and redaction

Each ledger entry is one JSON object with these required fields (nullable values remain present); `failure_fingerprint` is optional and `client_visible` is REQUIRED:

```json
{
  "cell_id":"scenario-3-go-client-ts-server-bridge-modern",
  "path":"direct|bridge-modern|bridge-auto-both|scripted-control",
  "client":"go|ts|scripted",
  "server":"go|ts|scripted",
  "sdk_versions":{"client":{"name":"<name>","version":"<version>"},"server":{"name":"<name>","version":"<version>"}},
  "scenario":3,
  "outcome":"PASS|FAIL|SKIP",
  "attribution":"sdk|fixture|jack",
  "reason":"<concise explanation>",
  "captures":[{"hop":"<identity>","direction":"request|response|event","method":"<method or null>","status":200,"media_type":"<type or null>","body":"<redacted bounded text>"}],
  "signature_oracle":{"applicable":true,"result":"verified|invalid|not-applicable|not-run"},
  "timings":{"readiness_ms":0,"tool_ms":0,"first_event_ms":null,"stream_completion_ms":null,"cancellation_ms":null,"shutdown_ms":0},
  "failure_fingerprint":"<stable short token>",
  "client_visible":{"tool_result":null,"sdk_error":null}
}
```

`failure_fingerprint` when present must be a string or null; `client_visible` must be an object with nullable JSON `tool_result`/`sdk_error` values or null. The signature oracle is filled from real observations for every signed topology; direct controls remain `not-applicable`. Attribution is `sdk` only when the direct control cell for the same client/server/scenario has the same outcome and the same `failure_fingerprint` (both fingerprints present); otherwise use the existing fixture/jack rule. `cell_id`, `path`, `client`, `server`, `outcome`, `attribution`, `reason` are strings; `scenario` is integer 1–8; `sdk_versions` holds client/server name+version strings or null for a non-SDK endpoint; `captures` is a bounded ordered array. Capture fields are required, nullable where shown; `status` is integer or null. `signature_oracle.applicable` is boolean and `.result` one of the listed strings. Timing values are elapsed integer milliseconds or null. Captures retain request/response/event ordering and per-hop identity, but are bounded in both count and bytes; record truncation explicitly in `body` as `[truncated]`.

Attribution follows the design: attribute to `sdk` if the same request through the direct no-Jack path fails the same way; `fixture` if fixture readiness or its own echo check fails before any Jack hop; otherwise `jack`. A cell outside a declared SDK capability is `SKIP` with API evidence, never PASS; SKIP applies only to scenarios 4–7. Required scenario failure is FAIL. Direct controls intentionally record `not-applicable` signature oracle. Scenario 1 records bridge discovery signature verification separately from SDK requests. Before any capture/log/ledger write, the driver registers all provisioned secret file contents and paths (server/user keys and invite) in the secret set. Redaction strips the whole credential value after `Authorization:`/`Jack-Auth:`/`Bearer`/`Basic` up to line end or the next separator from free text as well as keyed fields. The failure fingerprint is computed from already-redacted text. Never store credentials, private/public key material, auth headers, or signing secrets. Before any capture reaches ledger, logs, or artifacts, redact secret/key material and auth values; redaction is mandatory for request, response, event, SDK, fixture, and bridge logs. Redaction must occur before persistence, not only display.

Exit codes: `2` harness/manifest/artifact/usage error; `1` any failed required cell (or any failed cell); `0` only when all required cells ran. A capability SKIP for 4–7 does not count as PASS and must include API evidence. No other skip is permitted.

Provisioning order is `keygen server --secret --public`; `keygen user --secret --public`; `bootstrap --state --invite-file`; start server; start gateway; `enroll --config <client.json> --invite-file --name`. Gateway command is `jack gateway --config <file> --profile legacy|modern|both`; its config uses `upstream_socket` (private 0600 Unix socket) and `upstream_url` of the form `http://upstream/<path>` (host literally `upstream`, HTTP only). Jack topology: client fixture -> `jack bridge` (stdio) -> incremental capture proxy (TCP; bridge config endpoint) -> `jack gateway` -> Unix-socket relay (driver-owned) -> official server fixture (TCP). The relay is driver infrastructure, not a fixture.

`tools/mcp-e2e-modern/lib/config.mjs` is the single source of timeout defaults. Flags override each default in milliseconds; flag names are exact:

| Phase | Default | Override flag |
| --- | ---: | --- |
| readiness | 10000 | `--readiness-timeout-ms` |
| direct ordinary tool | 30000 | `--direct-tool-timeout-ms` |
| bridge + gateway tool | 45000 | `--bridge-tool-timeout-ms` |
| first stream event | 10000 | `--first-stream-event-timeout-ms` |
| stream completion | 30000 | `--stream-completion-timeout-ms` |
| cancellation completion | 10000 | `--cancellation-timeout-ms` |
| shutdown | 5000 | `--shutdown-timeout-ms` |

Timeout records identify the cell and phase; no fixture owns a competing default. These are scenario deadlines, not a global job timeout.
