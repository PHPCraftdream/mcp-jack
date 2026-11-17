# Operating mcp-jack

This guide is the operator runbook for the v0.1.0 Go CLI (`jack`) that runs the mcp-jack gateway and stdio bridge with durable nonce admission and server-key rotation. The release is unreleased and Linux-first. For the project overview see [../README.md](../README.md); for the historical design reference see [design/cli.md](design/cli.md), which this guide must agree with and does not replace as a design record.

## Deployment shape

The production chain is:

```
MCP client (stdio)
  -> jack bridge        (local stdio entry; pipes / FIFOs / UNIX-domain sockets only)
  -> [TLS-terminating reverse proxy in front, if the gateway is reached remotely]
  -> jack gateway       (authenticated loopback HTTP listener)
  -> fixed Unix-socket hop (mode 0600, owner-controlled 0700 directory)
  -> upstream MCP application
```

- The reverse proxy, when present, is an external trusted component. It must preserve the signed origin-form request target and the exact request body bytes; any rewrite of the target or body breaks signature verification.
- The gateway validates the upstream socket type, owner, parent directory and permissions at startup and on every dial. The upstream application must listen ONLY on that Unix socket and must not bind any TCP port or other ingress. Absence of another listener is an operator prerequisite — permissions do not prove it.
- One owner per state: state files are created with `O_CREATE|O_EXCL` and carry an owner marker. Exactly one gateway may serve a given state file. There is no clustering, no HA mode, no lock bypass, and no automatic stale-owner recovery.
- Known persistence caveat (owner-accepted limitation): filesystem operations — state writes and socket checks — are synchronous and not hard-bounded in time. Deploy on a healthy local filesystem.
- The gateway rebuilds outbound headers from scratch (only `Accept`, `Content-Type` and the protocol version are copied) and sets `X-Jack-Kid`, `X-Jack-Name` and `X-Jack-Admin` from the verified identity. `Jack-Auth` and caller headers never cross the hop.
- The bridge answers `tools/call` for `jack.*` tools locally with a JSON-RPC error (`-32602`) and never signs or forwards them. Enrollment and administration use the dedicated `jack` commands, never the bridge.
- Only `jack.enroll` is permitted natively by default. `native_admin: true` additionally enables the user/invite admin tools. `jack.whoami`, user-key rotation, server-key rotation and unknown `jack.*` tools are never forwarded upstream.

## Files and permissions

Every path argument and every path inside configuration must be an absolute, clean native path. Directories are never created implicitly.

| Rule | Detail |
| --- | --- |
| File mode | Secret, config and state files must be regular owner-owned files with mode exactly `0600` |
| Directory mode | Containing directory must be owner-owned with mode exactly `0700` |
| Symlinks | Symlink files and symlink ancestors are rejected |
| Ancestors | Must be root- or current-user-owned and not group/world-writable (a root-owned sticky directory is acceptable) |
| Creation | `O_CREATE|O_EXCL` mode `0600`; never overwrites an existing file, pin, symlink or stale owner marker |
| Scope | Permission checks assume a trusted local operator account; they do not protect against root or another process with the same account |

Configuration is strict JSON: version 1, unknown and duplicate fields rejected, maximum 16 KiB. Secrets appear only as file paths, never inline.

Key and document formats:

- Server / user secret: exactly 32 raw seed bytes (`jack keygen server` / `jack keygen user`).
- Server public file: JSON `{"server_public_key": "<b64u>", "server_kid": "<kid>"}`.
- Invite code: exactly 43 canonical base64url characters.
- State: SDK version-1 registry/invite document containing public identities and hashed invite IDs only.

## Platform support

| Capability | Linux | macOS | Windows |
| --- | --- | --- | --- |
| CLI binary (`jack`) | Qualified | Qualified (darwin/arm64: help, keygen, bootstrap, enroll, static gateway, bridge) | Fails closed on private-file operations (help works) |
| Static gateway + bridge | Yes | Yes | No (private-file operations fail closed) |
| Durable nonce store (optional, Linux-only, in all three SDKs) | Qualified | Not qualified | Not qualified |
| Rotation store (private-file backend) | Qualified (Linux-only) | Not qualified | Not qualified |
| Go/Rust/TypeScript SDKs | Tested | Tested | Tested (CI) |

Bridge stdio requires pipes, FIFOs or UNIX-domain sockets; regular files and terminals are rejected, and non-Unix stdio is unsupported.

## First deployment

```console
jack keygen server --secret /etc/jack/server.seed --public /etc/jack/server.public.json
jack keygen user --secret /etc/jack/client.seed --public /etc/jack/client.public.json
jack bootstrap --state /var/lib/jack/state.json --invite-file /var/lib/jack/invite.first
jack gateway --config /etc/jack/gateway.json
jack enroll --config /etc/jack/client.json --invite-file /var/lib/jack/invite.first --name ops-client
```

The operator provisions `/etc/jack`, `/var/lib/jack` (mode 0700) and the client config first; the CLI never creates directories. `jack enroll` signs a `jack.enroll` call against the endpoint in the client config — that endpoint is the running gateway, so the gateway must already be up before enroll runs.

Gateway config (`/etc/jack/gateway.json`, minimal):

```json
{
  "version": 1,
  "aud": "mcp-jack",
  "server_seed_file": "/etc/jack/server.seed",
  "state_file": "/var/lib/jack/state.json",
  "listen": "127.0.0.1:8080",
  "upstream_socket": "/var/lib/jack/upstream.sock",
  "upstream_url": "http://upstream/mcp",
  "call_timeout_ms": 10000,
  "max_concurrent": 8
}
```

`listen` must be a literal loopback address with a nonzero port. `durable_nonces` and `native_admin` are optional: omitting `durable_nonces` selects the volatile in-memory store; `native_admin` defaults to `false`. `durable_nonces` is an object with `path` (absolute path of the initialized nonce store), `deployment_id` and `window`; the gateway accepts a `window` of 1 to 30 seconds (30 is the default of the protocol), because a larger window would let unauthenticated enrollment attempts fill the nonce capacity at the gateway's admission rate. `call_timeout_ms` must be in 100..30000; `max_concurrent` in 1..64, or 1..32 when `durable_nonces` is selected.

Client config (`/etc/jack/client.json`, written by the operator; `jack enroll` only reads it). `server_public_key` and `server_kid` are provisioned out of band from `/etc/jack/server.public.json`:

```json
{
  "version": 1,
  "endpoint": "http://127.0.0.1:8080/mcp",
  "aud": "mcp-jack",
  "server_public_key": "<placeholder-b64u>",
  "server_kid": "<placeholder-kid>",
  "key_file": "/etc/jack/client.seed",
  "key_format": "raw-seed",
  "call_timeout_ms": 10000
}
```

Invite handling: `jack invite-create` reserves a private output file first; the invite code is written only after a verified reply. A failed or unknown operation leaves the reservation file in place; it is not reset or retried automatically.

`jack bootstrap` accepts only a completely absent state destination and there is no reset path. To start over, provision fresh state files (see Crash recovery).

## Admin operations

Admin commands use a client config (`--config FILE`).

| Command | Description |
| --- | --- |
| `jack user-create` | Create a user identity in the registry |
| `jack user-list` | List registered users |
| `jack user-get` | Show one user record |
| `jack user-set-admin` | Grant or revoke the admin flag on a user |
| `jack user-revoke` | Revoke a user identity |
| `jack invite-create` | Create an enrollment invite, writing the code to a reserved private file |
| `jack invite-list` | List outstanding invites |
| `jack invite-revoke` | Revoke an outstanding invite |

Admin tools are reachable only when the gateway runs with `"native_admin": true`; by default exactly `jack.enroll` is permitted natively. The response-signing identity is excluded as a native caller.

## Server-key rotation runbook

### Profile

For rotation, the gateway config uses `server_rotation_file` in place of `server_seed_file` (exactly one signing profile). Rotation mode requires an initialized durable-nonces profile with the same immutable window, so the rotation `window` is also limited to 1 to 30 seconds and `jack server-key-init-unused` refuses a larger value (the ring window cannot be changed later); the ring and nonce stores must be distinct files and the ring file must differ from the registry state; the profile audience must equal the gateway audience.

The rotation profile may include a `signers` array; entries are `{reference, kid, seed_file}`, where `seed_file` holds 32 raw seed bytes from `jack keygen server`. Distinct key IDs may share an opaque reference.

```json
{
  "version": 1,
  "store_file": "/var/lib/jack/rotation.store",
  "endpoint": "https://service.example/mcp",
  "aud": "mcp-jack",
  "window": 30,
  "anchor_kid": "<placeholder-kid>",
  "anchor_public_key": "<placeholder-b64u>",
  "anchor_reference": "anchor-0",
  "signers": [
    {
      "reference": "key-2027-01",
      "kid": "<placeholder-kid>",
      "seed_file": "/etc/jack/next.seed"
    }
  ]
}
```

`endpoint` is the exact public endpoint URL bound at init time — the independently configured external binding, not the loopback listener address or a value inferred from requests.

### Provisioning

`jack server-key-init-unused --config FILE --confirm-unused-endpoint URL --confirm-unused-aud AUD` provisions a rotation binding offline from an independently provisioned anchor (the ordinal-zero public key, never discovered from a remote payload). Both confirm flags must equal the configured binding exactly. It is an operator assertion, not recovery or reset; creation is exclusive and never replaces an existing file. Success prints nothing to stdout.

### Announce

`jack server-key-announce --config FILE --reference HANDLE --kid KID` selects one already configured next key and publishes exactly one record.

Stop and drain the gateway first: announce runs offline under the same lifetime-exclusive store owner as the serving gateway, and a concurrently serving owner blocks it. There is no lock bypass, no automatic retry, and no reset.

| Symbol | Meaning |
| --- | --- |
| P (published_at) | Publication time, fixed once at the authorized publication point, immutable thereafter |
| A (activates_at) | `P + 172800` seconds (48 h) |
| Overlap | From P to A both the old and the new key verify |
| Cutoff | At A the successor takes over; the old key's interval ends. Strict cutoff: an old-key response at or after A is rejected even if signed earlier |

Only confirmed publication emits JSON, containing `ordinal`, `hash`, `published_at`, `activates_at`, `state_revision` and the public record. If a stdout error occurs after commit, the publication is NOT rolled back — never repeat automatically. Inspect `jack server-key-status` and keep the emitted JSON as evidence. Repeating the same retained key is refused.

Retired seeds may be removed from the inventory once no longer required; retained public references and the anchor profile are never rewritten.

### Status and client refresh

`jack server-key-status --config FILE` is offline inspection under the same exclusive owner (a concurrently serving owner blocks it). It prints public store, owner, clock, state, head and count/flag metadata only; it never clears dirty/unsafe flags and does not authorize a restart.

Clients refresh explicitly: an SDK rotation client requests one `jack.server.key` page (single page, at most 16 records) and commits it. Ordinary traffic never triggers a refresh. There is no auto-refresh, no hidden retry, no fallback, and no TOFU.

## Durable nonce store across SDKs

All three server SDKs ship an optional, Linux-only durable nonce store; without it every SDK keeps nonces in memory and a restart loses replay history. The store is explicit opt-in per deployment and is never selected by default.

| SDK | Enable | Store format | Recovery |
| --- | --- | --- | --- |
| Go (library) | `durable/` package, bbolt-backed private file | bbolt store | library `durable.InitializeUnused`, `durable.InspectRecovery`, `durable.ReconcileUnknown`; CLI `jack nonce-init-unused`, `jack nonce-inspect`, `jack nonce-reconcile-terminal` |
| TypeScript | set `VerifierConfig.durable` to a `DurableNonceAdmission` wrapping a `DurableNonceStore` | one canonical JSON sealed document, atomically rewritten at the configured path; owner marker `<path>.owner` | static `DurableNonceStore.inspectRecovery(path, options)` and `reconcileUnknown(path, options, expectedHash, receipt)`; library only |
| Rust (Linux only) | open with `SharedDurableNonceStore::open(path, &options, clock)` (or `initialize_unused` with the same arguments), where `clock` is a `BoxedDurableClock` (`Box<dyn FnMut() -> i64 + Send>` returning Unix seconds), then `Verifier::with_durable_nonces(Arc<SharedDurableNonceStore>)` | canonical binary exact-byte format; owner marker `<path>.owner` | library `inspect_recovery(path, &options)` and `reconcile_unknown(path, &options, expected_hash, &receipt)` in `rust/src/server/durable_recovery.rs`; library only |

All three stores are optional, explicit opt-in and Linux-only, including Go. Serving-open rejects dirty or unsafe state, unresolved intents, and the 64-tombstone recovery cap; recovery inspection is a separate read-only path, not serving-open. Go uses bbolt and a process-held exclusive lock. Rust and TS use bounded private files plus persistent owner markers; TS uses no-follow, mode/owner/link-count and bounded-read checks even during recovery inspection. Rust's binary format and TS's JSON format require a byte-exact canonical encoding. Recovery operations bind the supplied deployment and window; reconcile also requires the exact inspected snapshot hash and receipt.

Operator recovery for Rust and TypeScript is a library call, not a command: only the Go CLI (`jack nonce-inspect`, `jack nonce-reconcile-terminal`) exposes operator commands.

A committed admission lease spans response handling: Go releases it when middleware finishes the response path; Rust releases it when the response object is produced; TypeScript releases it after response construction, with the Node adapter also attempting an idempotent release after writing. These are response-lifecycle release points, not permission to overlap close with active request handling. Close behavior differs:

| SDK | Close behavior |
| --- | --- |
| Go | Sets `closing` under the mutex, then waits for leases outside it. A verifier overlapping the drain can receive a closing refusal that fences the store; fenced close reports `ErrRecoveryRequired`, closes bbolt, and leaves the persisted dirty state fail-closed. |
| Rust | Sets `closing` under the mutex, drains leases outside it with synchronous 1 ms sleeps, then clears dirty only if not fenced. Fenced close reports `RecoveryRequired` and releases the owner marker unless I/O fails. A closing refusal is treated as definite, unlike Go's overlapping-verifier case. |
| TypeScript | If leases remain, `close()` immediately throws 503 `durability_unavailable` before setting `closing`; admission remains open and the marker stays held. Stop ingress, release/drain outstanding reservations, then retry: a non-fenced leased close can succeed. A fenced close reports recovery-required (503 `durability_unavailable`, message `durable: recovery required`) and releases the owner marker, as in Go and Rust; the persisted dirty epoch keeps the store fail-closed, and recovery inspection can run at once. |

What fenced and dirty mean:

- An admission failure with unknown write outcome, `durability_unavailable` or `clock_unsafe` fences the store; definite admission refusals (`401`, `state_changed`, `capacity_exhausted`) do NOT fence in any SDK. Do not generalize admission behavior to `close()`: a TypeScript leased-close `durability_unavailable` occurs before `closing` or fencing, leaves admission open, and can succeed after the caller stops ingress, drains leases and retries. A fenced close in any SDK reports recovery-required and releases the owner.
- A dirty store (for example after a crash between writes) refuses serving-open in every SDK. Recovery inspection is a read-only snapshot, not permission to serve. Reconcile moves only the exact receipt and expected snapshot hash to a terminal no-redelivery tombstone; it refuses on a hash mismatch, and a missing record is not proof of abort. Reconcile never clears dirty/unsafe state or authorizes restart; unresolved intents or tombstones at cap 64 also make serving-open refuse. A repaired forensic record remains fail-closed; use fresh deployment state when the runbook requires serving again.
- Clock samples below the persisted high-water mark `H`, or outside the supported timestamp domain, latch the store unsafe permanently; a forward clock jump alone does not latch it. If a later sample falls below the raised `H`, the store latches unsafe. No command in any SDK clears that latch; the remedy is fresh state as in the crash recovery runbook below.

## Crash recovery runbook

v0.1.0 ships NO operator command for serving release, tombstone disposition beyond the narrow reconcile below or ring recovery. A supported in-product recovery path is deferred to a later release. The `nonce-reconcile-terminal` caveat is unchanged: reconcile refuses on an expected-hash mismatch, a missing record keeps the fence, and success is not permission to restart. Operator nonce-recovery commands exist only in this Go CLI.

What failure looks like:

- After a crash, kill or power loss, the ring and nonce stores stay dirty or unknown, and every SDK entry point refuses to serve (fail closed).
- `jack nonce-inspect --config FILE` reads and reports the store state but does not clear dirty/unsafe flags and does not allow startup.

What NOT to do:

- Never copy, edit, or unmark the old store files, and never restore them from a backup. A self-consistent backup rollback is undetectable and a copied clock is not authority.
- Do not delete an owner marker without first proving no owner survives. The marker may survive a crash; there is no automatic stale-marker removal.
- Never repeat a publish or reconcile automatically after an error.

Procedure:

1. Establish out of band that the previous process is gone. Go's bbolt lock is released on process exit; Rust and TypeScript leave persistent `.owner` markers after a crash. Only after proving no owner process survives may an operator remove a stale `STATE.owner` marker so recovery inspection can acquire exclusive ownership.
2. Keep the old store files untouched for investigation.
3. Provision clean state: fresh store files and a fresh deployment/binding. `nonce-init-unused` and `server-key-init-unused` are only for never-used deployments/bindings; use them on the fresh state only.
4. Handle client consequences (below).

Tombstone reconcile: `jack nonce-reconcile-terminal --config FILE --expected-hash HASH --receipt-file FILE --confirm-no-redelivery INTENT_ID` is the one offline evidence action. Run it over an already closed dirty nonce store; it converts one exact receipt (a `NonceReceipt` from `nonce-inspect` evidence) into a terminal no-redelivery tombstone. `HASH` must be the exact current logical graph hash reported by `nonce-inspect`. Limits: it never loads signer material, sends HTTP, redelivers, clears dirty/unsafe, releases serving, or resets storage; success does not undo prior handler effects and is not permission to restart.

Consequences for clients: a new ring needs a checkpoint clients already trust or a new out-of-band server-key pin. Rotation records cannot bridge a discarded ring. Static clients keep their old pin and will fail closed until the operator re-pins them out of band.

## Operational limits to plan for

- **Time source.** The nonce store, the server key ring and every client trust store keep a high-water mark of the clock. A sample below the persisted high-water mark or outside the supported time domain latches the store unsafe; a forward step followed by a return below the raised mark therefore latches, while the forward step alone does not. No 0.1.0 command clears the latch, so use fresh state as in the crash recovery runbook, and re-pin clients as required. Use a trusted, stable time source; never step the clock by hand, and watch for VM pauses and migrations.
- **Unauthenticated load.** The Go CLI gateway admits at most 64 calls per Unix second and 4096 nonce entries; Rust and TypeScript SDKs do not provide this 64/s rate limit. Every deployment must bound request rate and cache occupancy so `rate × (2 × window + 1) < cache capacity` (spec 01 §4); put a rate-limited front or firewall before SDK servers. A self-signed `jack.enroll` from an unknown key reserves a nonce only with a live invite. Keep the Go gateway's durable `window` at 30 seconds or less.
- **Rotation ring.** Each signed response re-verifies the key ring, so keep it short. There is no spacing rule between announcements: up to 128 keys can be pending and every retired key counts towards the limit of 1024 retired keys, after which the gateway refuses to sign and clients refuse the ring; compaction is not implemented. To keep a ring from becoming unservable, an announcement is refused once the ring already holds more than 1024 keys, so a ring is good for at most 1024 rotations. Announce rarely, and treat the 48 hours as the overlap of one announcement, not as a limit on how often you may announce.
- **Invites.** The gateway stores at most 1024 invites. Expired invites are removed in the same atomic state edit that creates, enrolls with or revokes an invite (and in first-admin bootstrap), so only live invites count towards the limit; an expired invite is reported as unknown. Unused invites that have not yet expired still count, so do not create invites in bulk.
- **Rust and TypeScript servers.** All three SDKs offer the optional Linux-only durable nonce store (see "Durable nonce store across SDKs" above). Without it, nonce stores are in-memory and restart loses replay history. The Rust and TypeScript durable stores have no operator CLI; recovery there is a library call.

## Monitoring and audit

- The CLI gateway writes best-effort JSON-lines audit events to process stderr for audited native calls that reach the tool; pre-tool refusals emit no event. `Record`/write errors are ignored, so these events are not complete or durable proof; capture stderr for retention.
- Plan a second administrator key: if the only administrator key expires there is no in-band recovery, and a crash can leave a stale `<state>.owner` marker that blocks the gateway until it is removed by hand (see the crash recovery runbook).
- Stderr diagnostics are fixed secret-free strings; no command prints a seed, invite code, or supplied path/URL.
- Bridge stdout carries only verified protocol frames.

Observable gateway behaviors for dashboards:

| Status | Class / reason | Meaning |
| --- | --- | --- |
| 401 / 405 | unsigned pre-auth refusals | Unsigned request rejected before identity verification |
| 401 | `replayed_nonce`, `timestamp_out_of_window`, `bad_signature` | Signed request rejected |
| 403 | `admin_required`, `operation_denied` | Signed request denied |
| 501 | `streaming_unsupported` | Upstream answered SSE; unsupported |
| 502 | upstream redirects, response-cap overflow | Upstream misbehavior |
| 503 | `durability_unavailable`, `state_changed`, `clock_unsafe`, `capacity_exhausted` | Durable-profile failures — never dispatch on these |

Note on 501: the official TypeScript MCP server 2.4.0 answers `initialize` with `text/event-stream` even in JSON response mode; such upstreams are unsupported.

Bounded profile: legacy Streamable HTTP 2025-11-25, one JSON-RPC object per POST, no sessions, no GET stream (authenticated GET answered with signed 405). Caps: request/response bodies 1 MiB; headers 16 KiB; concurrency 1..64 (accepted connections capped at twice that); global admission at most 64 calls per Unix second; nonce admission stops at 4096 entries; registry/invite capped at 1024 records / 1 MiB.

## References

- [../README.md](../README.md) — project overview.
- [design/cli.md](design/cli.md) — CLI design reference (historical; exact schemas).
- [../spec/candidate/server-key-rotation.md](../spec/candidate/server-key-rotation.md) — server-key rotation specification.
- [../spec/candidate/durable-nonces.md](../spec/candidate/durable-nonces.md) — durable nonce specification.
- [threat-model.md](threat-model.md) — threat model.
- [../SECURITY.md](../SECURITY.md) — security policy and reporting.
