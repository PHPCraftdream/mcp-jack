# Go CLI bundle: Tasks63/64/65

Status: implementation sources and unrun parent-CI test sources. No acceptance,
conformance, official-MCP interoperability, independent review, or release claim.
This document selects a bounded implementation profile; it does not turn the
recommendations in the compatibility design into owner acceptance.

## Scope and invocation

The entry point is `cmd/jack`; the command layer is `internal/cli.Run(ctx, args,
IO)`. Exit status is zero for success and one for failure. `help` writes usage to
stderr. All diagnostics are fixed, secret-free strings. No command prints a
seed, invite, credential, HTTP error body, supplied path, or supplied URL.
Bridge stdout contains verified protocol frames only. Commands with documented
JSON output emit only their public result or diagnostics; other commands produce
no stdout.

Commands:

- `jack keygen server --secret FILE --public FILE`
- `jack keygen user --secret FILE --public FILE`
- `jack bootstrap --state FILE --invite-file FILE`
- `jack enroll --config FILE --invite-file FILE --name NAME`
- `jack gateway --config FILE`
- `jack bridge --config FILE`
- `jack server-key-init-unused --config FILE --confirm-unused-endpoint URL --confirm-unused-aud AUD`
- `jack server-key-status --config FILE`
- `jack user-create --config FILE --public FILE --name NAME --admin true|false [--not-before TS] [--not-after TS]`
- `jack user-list --config FILE`
- `jack user-get --config FILE --kid KID`
- `jack user-set-admin --config FILE --kid KID --admin true|false`
- `jack user-revoke --config FILE --kid KID`
- `jack invite-create --config FILE --invite-file FILE --admin true|false [--ttl-seconds N] [--key-ttl-seconds N]`
- `jack invite-list --config FILE`
- `jack invite-revoke --config FILE --invite-id ID`

Every path argument and every file path inside configuration must be an absolute,
clean native path. Directory creation is deliberately not implicit: provision an
owner-controlled directory before use. Examples below use symbolic placeholders,
not paths from any developer machine.

The original bootstrap-only scope now also includes the user/invite admin CLI
and an explicit durable nonce profile; omission of that profile still selects
the original volatile store. This does not supply server-key rotation runtime,
sessions, a general policy engine, or automatic recovery.

The gateway permits only `jack.enroll` by default. Optional configuration
`"native_admin": true` enables exactly the existing SDK user list/get/create/
set_admin/revoke and invite create/list/revoke tools. Omission or `false` keeps
the closed default; `null`, strings and numbers are rejected. Older binaries
that do not recognize this field reject the configuration; removing it restores
the closed default rather than preserving admin enablement. Native SDK admin
authorization and transactional last-admin checks still apply. Both registry
keys and stored invite records are capped at 1024 by the atomic update wrapper;
capacity exhaustion refuses the update without partially committing edits.
`jack.whoami`, user-key rotation, server-key rotation and unknown `jack.*` tools
remain disabled and are never forwarded upstream. The server response identity
cannot enroll or act as a native client. Application authorization for ordinary
MCP operations remains upstream-owned.

Admin commands use the independently pinned client configuration and one signed,
response-verified request, without retries. `user-create` reads only a public
user-key envelope; it does not upload private key material. `invite-create`
reserves a new private output file before the request and writes the code only
after verifying the signed reply and code/ID relationship. Standard output
contains only the public invite ID and expiry. A failed or unknown operation
leaves the reservation file in place; it is not reset or retried automatically.
Filesystem output and remote state are not a cross-file transaction.

## Custody and file contract

On Linux, macOS and the listed BSD targets, secret/config/state files must be
regular owner-owned files with mode exactly 0600 in an owner-owned directory with
mode exactly 0700. Symlink files and symlink ancestors are rejected. Ancestors
must be root- or current-user-owned and not group/world writable, except a
root-owned sticky directory (for example, the system temporary directory).
Permission checks assume a trusted local operator account; they do not protect
against root or another process with the same account. ACLs, mount policies,
backups, memory dumps and hostile concurrent same-account path replacement are
outside this mode-bit policy. No guaranteed zeroization is claimed.

Windows and other unimplemented storage platforms fail closed when creating,
loading, or operating on private files. The executable can display help there;
it does not claim Windows ACL security or functional gateway/bridge support.
Go 1.22 is the language floor, not a security endorsement. Deploy binaries built
with an independently verified patched, supported Go toolchain.

Creation reserves every destination using `O_CREATE|O_EXCL` and mode 0600 before
writing any of the group's contents. Existing files, pins, symlinks and stale
owner markers are never overwritten. Failed reservations remove only files
created by that operation. A write/sync/close failure can leave partial new files;
inspect them out of band rather than retrying over them. Group creation is not a
multi-file transaction or power-loss durability promise.

Formats (no trailing newline):

- Server response-signing secret: exactly 32 raw seed bytes, not hex/base64/PEM.
  Its public file is JSON with `server_public_key` (canonical base64url raw
  public key) and `server_kid`.
- User generation: `userkey.IssueLocalPair`, then the explicit `IssuedKey.Secret`
  handoff writes exactly 32 raw seed bytes; `ExportPublicEnvelope(ServerKey)`
  writes the canonical public envelope. No `ClientKey` private extraction exists.
- User loading supports `raw-seed`, `private-envelope` (canonical SDK private
  transfer envelope), or `credential` (canonical SDK client credential).
  No trimming, newline removal, normalization, or repair occurs on any key file.
- Invite: exactly 43 canonical base64url characters, no newline.
- State: existing SDK version-1 registry/invite format, containing public user
  identities and hashed invite IDs only, never user seeds or credentials.

Server response-signing custody is distinct from the user `ServerKey` public
record. Client loading rejects the server pin as its user identity. Gateway
startup rejects a registry already containing its response-signing identity;
enrollment rejects that identity too.

## Configuration and independent trust

Configuration is strict JSON: version 1, unknown or duplicate fields rejected,
maximum 16 KiB. All configurations are treated as private 0600 files in a 0700
owner directory even though the trust tuple is public. Secrets appear only as
file paths, never inline.

Client configuration (all fields required):

```json
{
  "version": 1,
  "endpoint": "https://gateway.example/mcp",
  "aud": "example-service",
  "server_public_key": "<independently trusted base64url public key>",
  "server_kid": "<independently trusted matching key id>",
  "key_file": "<absolute private key file>",
  "key_format": "raw-seed",
  "call_timeout_ms": 10000
}
```

The endpoint is the exact configured client endpoint, including its path/query;
the SDK applies its public HTTPS/literal-loopback URL policy before networking.
The operator must establish all four tuple fields out of band. A credential's
embedded identity never supplies trust. Credential loading always calls
`userkey.ImportCredential(bytes, ExpectedIdentity{...})` with those independently
configured values. Each mismatch fails before network activity. No TOFU,
automatic pin adoption, pin overwrite, or trust-update command exists. TLS
certificate verification remains enabled; no environment HTTP proxy is used.

Calls advertise `Accept: application/json, text/event-stream`, JSON Content-Type,
and `MCP-Protocol-Version: 2025-11-25`. Version/session/routing headers are unsigned
metadata: validated, never described as signature-protected. Session, resumption,
and modern routing metadata are rejected, not silently ignored. The outer gateway
checks duplicate/incompatible protocol-version headers before SDK dispatch,
including Native enrollment; those pre-auth refusals cannot consume an invite.

## Local first-admin bootstrap and enrollment

Bootstrap accepts **only a completely absent state destination**, not even an
existing empty, expired-invite, malformed or admin-free state. Under the same
exclusive `STATE.owner` ownership marker used by the gateway, it calls public
`server.BootstrapAdmin` on a fresh in-memory store with TTL 900 seconds and
serializes the resulting public-only SDK state. `BootstrapAdmin` itself does not
enforce first-bootstrap policy; exclusive destination creation supplies this
stricter CLI policy. It creates one single-use admin invite, not a user key.
The code goes only to the separately reserved invite file. An existing invite
file fails without modifying an existing state or leaving a new state reservation.
There is no reset/recovery overwrite path. A lost code or expired invite requires
explicit operator investigation and out-of-band recovery, not automatic reset.

Enrollment loads a pre-generated user key or credential, the independent tuple,
and the invite file; signs a `jack.enroll` tools/call; and checks the verified
response's user KID/name. The gateway uses SDK Native enrollment/state mutation,
never forwards native operations upstream, and preserves the SDK's nonce and
single-use invite behavior. Enrollment does not delete the source invite file.
Failures after an ambiguous remote effect are not retried automatically.

One gateway owner per state uses `O_EXCL` on `STATE.owner`. Normal shutdown removes
its marker; crashes may leave it. No automatic stale-lock removal is performed.
The operator must establish that no owner survives before removing a stale marker.
The SDK state-store rename writes are authorized state updates, not overwrites of
CLI-generated pins or secret files. Owner locking is not a crash-durability,
power-loss, replay-across-restart, or multi-instance guarantee.

## Fixed Unix-socket gateway

Gateway configuration (shown fields required; `native_admin` is optional and defaults to `false`):

```json
{
  "version": 1,
  "aud": "example-service",
  "server_seed_file": "<absolute server response seed file>",
  "state_file": "<absolute existing SDK state file>",
  "listen": "127.0.0.1:8080",
  "upstream_socket": "<absolute owner-controlled Unix socket>",
  "upstream_url": "http://upstream/mcp",
  "call_timeout_ms": 10000,
  "max_concurrent": 8
}
```

Only literal loopback listen addresses with a nonzero port are accepted. TLS
termination for remote clients is an external, trusted reverse-proxy deployment;
configure it to preserve the signed origin-form target and exact body bytes.
No public plaintext listener or automatic TLS provisioning is supplied.

**Required deployment:** the wrapped application listens ONLY on the configured
Unix socket, in an owner-controlled 0700 directory, with socket mode 0600, under
the same trusted local operator account. It must not additionally bind any TCP
port or other unwrapped ingress. The CLI validates socket type, owner, parent and
socket permissions at startup and every dial, and has no TCP upstream fallback.
It cannot introspect an application's additional listeners: absence of another
network listener is an operator prerequisite, not something socket permissions
prove. Same-account processes can directly use the socket; that is the explicit
local operator trust boundary, not authenticated remote access. Do not deploy
where untrusted processes share that account. Separate-account isolation would
need a separately designed credential/hop mechanism.

The configured HTTP URL must have literal authority `upstream`, no query or
fragment, and a nonempty fixed path. That authority is HTTP metadata only: every
dial goes to the Unix socket. Incoming Host, path and query cannot select routing.
The SDK authenticates the incoming method/target/body before forwarding. Outgoing
headers are rebuilt from scratch: only Accept (including both values),
Content-Type, and protocol version are copied. The three fixed identity headers
`X-Jack-Kid`, `X-Jack-Name`, `X-Jack-Admin` are populated solely from
`server.IdentityFromContext`. Cookies, caller identity duplicates, Authorization,
forwarding headers and Jack-Auth never cross the hop. Upstream response headers
are likewise allowlisted to Content-Type and validated protocol version.

SDK verifier/handler perform request verification and response signing. Ordinary
POST bodies are preserved byte-for-byte. Native tools are intercepted before
upstream. GET is authenticated and answered with signed 405 (no SSE endpoint).
An upstream SSE response is promptly closed, passed to the middleware as an SSE
refusal and becomes signed 501, without reading a stream to EOF. These are distinct
failures. Unsupported HTTP methods retain the SDK's **unsigned pre-auth 405**;
clients must fail verification, not treat that response as authenticated. Header,
body-read, admission and pre-auth failures can also be unsigned. There is no
claim that every error is signed.

Upstream redirects are never followed and become signed 502. Session headers and
cancellation notifications are explicitly refused. Request/response bodies are
capped at 1 MiB; a cap+1 upstream response triggers the SDK signed overflow refusal.
HTTP response/request headers are bounded at 16 KiB (net/http parsing allowances
still apply). Concurrency is configurable 1..64, accepted connections are capped
at twice that value, and overload is rejected without a queue. Global admission
is at most 64 calls per Unix second. Nonce admission stops at 4096 entries before
verification (at most one in-flight concurrency allowance can overshoot); this
also fails closed if clock movement prevents timely expiry. Registry/invite
loading is bounded to 1 MiB/1024 records, with enrollment key count capped at 1024.

Call timeouts are required (100..30000 ms). Inbound read/header/write/idle/connection
deadlines, context deadlines and upstream dial/header/TLS bounds are installed.
These bound network operations, not arbitrary local filesystem operations. Byte
caps alone are not time bounds. Shutdown closes the server and joins accepted
connections before releasing ownership; that join has the persistence limitation
below. No handler or persistence operation is detached to pretend it completed.

**Unresolved persistence/deadline blocker:** SDK `FileState.Update` performs
synchronous local writes, file sync and rename without a context-aware API.
Native enrollment can remain inside those operations after its HTTP context has
expired. A filesystem stall can therefore exceed the advertised call timeout
and block shutdown/owner-lock release indefinitely. Configuration/key/state
reads, socket permission checks, bootstrap creation/sync and lock cleanup are
also synchronous filesystem operations and have no hard stall bound. Network
cancellation does not roll back a possibly committed enrollment, and a timeout
is not proof that its invite was unconsumed. No fully bounded whole-call or
shutdown guarantee applies to these disk operations.

**Owner decision, 2026-11-09:** option 1 below is explicitly accepted as a deployment limitation; no enforced hard disk-stall bound is claimed. Option 2 remains deferred and unauthorized:

1. Accept a supported **healthy, local, bounded-latency filesystem** deployment
   assumption as a product limitation, explicitly accepting that this is not an
   enforced hard disk-stall bound on requests, startup, shutdown or owner release.
2. Separately authorize an owned storage/process-isolation design, including
   mutator lifetime/ownership, committed/failed/unknown outcomes, recovery after
   lost acknowledgements, and stall/commit/recovery tests. This needs independent
   scope and review; no such production change is authorized in this follow-up.

A context-aware SDK transaction API alone is insufficient: checks before commit
cannot interrupt a filesystem syscall already stalled in the kernel. An HTTP
failure/timeout or closed connection is not a commit acknowledgement, rollback
proof or proof an invite remains usable; report an unknown remote effect honestly
and do not automatically retry. Any future hard-bound design must keep ownership
while a mutator can still act and define how an unknown result is reconciled.
This bundle changes neither SDK nor persistence: no detached timeout goroutine,
owner release while a mutator lives, fake success/acknowledgement, weakened state
invariant or new durability claim. Sync/rename/directory-sync semantics remain a
separate contract/recovery question. Acceptance of option 1 changes the supported deployment assumptions, not the implementation's ability to interrupt filesystem calls.

## Bounded stdio bridge profile

This is a deliberately restricted **legacy 2025-11-25, no-session, terminal JSON
response** profile. Configure upstream handlers so no required progress,
server-initiated request, notification, subscription, or SSE output is dropped.
This is neither full legacy transport conformance nor support for modern MCP.
There is no official SDK dependency or official SDK test claim.

- One newline-delimited UTF-8 JSON object per input; no batches, duplicate member
  names, truncated final frames, or silently truncated oversize messages.
- Remove only the delimiter LF before signing. Preserve every other byte,
  including spaces or CR whitespace. Never remarshal requests.
- Relay the caller's sole initialize request, validate its version/capabilities/
  clientInfo, validate the exact correlated initialize result/version/capabilities/
  serverInfo, then require caller `notifications/initialized`. No hidden or second
  handshake, capability rewrite, automatic GET, DELETE, or reinitialization.
- Request IDs must be strings or int64 integer literals; response IDs must match.
  Terminal JSON-RPC error objects are relayed only after shape and ID validation.
- Notifications require **202 empty** and produce no stdout. 204 is not accepted.
  A request receiving 202 empty fails because no reply exists.
- SDK `client.Transport` signs requests and verifies exact response status/body
  bytes before the bridge examines or exposes them. Signed 501/405, non-RPC HTTP
  failures, redirect refusals and unsigned responses terminate with stderr/exit 1,
  never an invented RPC reply or `id:null` frame.
- A verified HTTP JSON body containing a raw LF is rejected before stdout; it
  cannot be remarshal-transformed without losing the exact signed byte contract.
  Escaped `\\n` within JSON strings is fine. A verified single-line body gets only
  a framing LF appended.
- Session/resumption and incompatible version metadata fail closed. Response
  headers are not authenticated by Jack signatures; TLS/hop trust still matters.

One HTTP call/output operation runs at a time. There is at most one pending frame
plus one bounded reader frame. When the pending slot is full, the main loop sets
its ordinary input receive channel to nil: real channel backpressure replaces
pipeline rejection, without growing a queue or dropping/reordering frames. Worker
completion, context cancellation, the unchanged whole-call timer and terminal
input remain serviceable. Only main owns admission; each worker exclusively owns
the protocol state until its completion is received before the next launch.

The reader uses separate unbuffered ordinary and terminal channels and the same
`maxBody+1` bufio capacity. EOF, framing/read errors, malformed JSON objects and
unsupported cancellation are routed to a single terminal event before any normal
send; the reader then exits. Such controls immediately behind the accepted
pending frame remain observable even while stdout is held. This is not arbitrary
look-through: if the reader is blocked holding another ordinary frame, a later
EOF/error/cancellation remains unread until capacity returns (or context/timeout
closes owned IO). Nothing is silently dropped. Context cancellation releases a
blocked channel send; owned IO close interrupts Read/Write, and cleanup joins the
reader and worker.

A complete response that has already finished writing may win a concurrent EOF
race and complete successfully only if there is no accepted pending frame. EOF
with a pending frame always fails, even if the current worker completes with nil;
it cannot silently discard that frame and return success. EOF before a complete
reply fails and cancels the call. Idle EOF succeeds. Input inactivity, slow
framing, blocked stdout and HTTP reads are subject to the configured timeout;
synchronous filesystem setup remains excluded as described above. A bridge
with no input does not wait forever once setup has completed.

The executable and child-test entry use `RunProcess`/`ProcessIO`, which prepare
stdio **only for bridge**. On supported Unix systems, both descriptors must be
pipes/FIFOs: duplicate them, set `O_NONBLOCK` on the duplicates **before**
`os.NewFile`, then require successful `SetReadDeadline`/`SetWriteDeadline`
capability checks. Failure closes owned duplicates and fails closed. Regular
files, terminals, sockets, and non-Unix bridge stdio are intentionally unsupported.
Help/keygen/bootstrap/enroll/gateway do not require pipe stdio.

The Go poller receives nonblocking descriptors rather than reusing the inherited
potentially blocking `os.Stdin`/`os.Stdout` wrappers. No `File.Fd` call is made on
the prepared files, avoiding its blocking-mode transition. A duplicate shares
its open-file description's `O_NONBLOCK` flag with the original: the launcher's
stdio endpoints must be exclusively handed to the bridge, not used concurrently
through another alias. Originals are not closed or reused by the bridge; the
owned pollable copies are closed to interrupt reads/writes. Preparation cannot
promise flag restoration on failure, and no such restoration is attempted.

`Run` takes ownership of bridge In/Out. Their Close must unblock concurrent
Read/Write. On EOF, broken pipe, deadline, cancellation or protocol failure, it
cancels HTTP, closes owned stdio and joins its reader/worker before returning.
Arbitrary injected blocking Go readers/writers whose Close cannot unblock
operations are unsupported. Stderr is a caller-owned diagnostic sink and must
not block indefinitely. The production pipe preparation has focused
blocking-inherited-descriptor/deadline/close regression sources; the current
follow-up edits are unrun. The actual `os.File.Read` deadline control is separate
from the `SyscallConn` close/readiness controls. Those controls first inspect
`O_NONBLOCK` without `File.Fd`, then require a real nonblocking read/write to
return `EAGAIN`/`EWOULDBLOCK` before closing the prepared file. The input peer
stays open without data; output is filled through actual one-byte would-block
and its reader stays open and undrained until the chosen action. RawConn callback
`false` requests poll/readiness retry; callbacks never wait on test channels.

RawConn forwards poll-layer errors directly, without the conversion performed
by `os.File.Read`/`Write`; requiring raw close to match `os.ErrClosed` was the
wrong oracle. Each close case now captures an opaque reference error through
public APIs on a separate independently prepared pipe: obtain its RawConn while
open, successfully `File.Close` it with a bounded join, then call the matching
RawConn Read/Write. The reference must be nonnil and its callback must never run.
It must not contain a `syscall.Errno`, nor match bad-descriptor, would-block,
deadline, invalid-file, EOF or broken-pipe errors in either direction. No internal
sentinel is imported, named in an assertion, or recognized by its error string.
The active operation must match that reference via `errors.Is`, not return a
syscall error, and leave its last syscall at would-block with no progress
(`n == -1` or `n == 0`) and at least one callback. Nil, `EBADF`, `EAGAIN`, deadline,
EOF/broken-peer failure, or a successful final callback cannot satisfy this
combination. Failure diagnostics include error types/values, the reference,
syscall result and callback count. Peer-write/peer-drain positive controls still
must re-enter the callback and complete one byte successfully.

The worker inspected local Go 1.26.0 sources. Parent independently fetched
Go 1.22.12 tagged upstream [rawconn.go](https://github.com/golang/go/blob/go1.22.12/src/os/rawconn.go),
[file.go](https://github.com/golang/go/blob/go1.22.12/src/os/file.go), and
[poll/fd.go](https://github.com/golang/go/blob/go1.22.12/src/internal/poll/fd.go).
RawConn Read/Write return RawRead/RawWrite errors unchanged; the internal
file-closing sentinel is an ordinary errors.New value. File.wrapErr converts
that sentinel to os.ErrClosed and wraps it in a PathError. The test must not
assume this public File conversion also applies to RawConn. Its reference oracle
uses public APIs on the actual CI toolchain rather than importing an internal
sentinel or comparing its error string.

After verified Close and the raw-operation join, a separate actual
`os.File.Read`/`Write` on that same prepared file must return zero bytes and an
error matching `os.ErrClosed`. This checks the public File error conversion
**after** close, not an observed in-flight File operation. The active raw controls
exclude closed-before-call and EOF/broken-peer explanations; they establish an
active RawConn operation that has encountered would-block, not that the runtime
goroutine was already parked when Close happened. They do not prove a distinct
in-flight `os.File.Read`/`Write` hook. Fixture receives and joins remain bounded
failure guards, never evidence of successful interruption.

Each call creates a fresh HTTP/1 transport: no proxy, no connection reuse, no
HTTP/2, no compression, no application retries or redirects. The SDK installs
`GetBody`; the final network wrapper removes it, removes idempotency headers and
sets Close. Fresh connections avoid net/http's reused-connection replay path.
This does not make ambiguous effects recoverable: report failure, investigate
out of band, and never automatically resubmit a side-effecting call.

## Task89 admission correction (unrun)

The new parent-provided coverage evidence,
`.rush/stdin/backpressure-coverage-df23521-failed.log`, lines 13–23, records
`TestOwnedPipeBrokenOutputAndBackpressure/broken` failing in 0.01s: normal Run
code 1, exact protocol stderr, no terminal syscall or File.Write observation,
zero terminal writes, calls `[1 0 0]`, unexpected 0, cleanup joined. The parent
identifies current-main `df2352110ec3e4a183176551db7b5d79b538a4ce` and reports
previously successful 32 checks and five focused repeats. Those prior results do
not override this coverage failure and are not new execution evidence here.
The earlier expensive-large-response hypothesis is superseded for this new
diagnostic: it cannot explain a small-response failure before initialized or
terminal output is reached. The log alone does not identify which admission
branch ran.

Independent inspection of the old main loop identifies two invalid admission
paths. All initialize response bytes can reach the peer before its output Write
returns and the worker publishes completion. A valid peer can then send
initialized followed by tools/list: initialized occupies pending, and the next
ordinary receive returns protocol failure while busy. If that receive instead
consumes completion inline with pending still occupied, the other pending check
also returns protocol failure. The correction disables that ordinary receive
until pending is dispatched; completion is handled only by its own select arm.
It does not serialize the peer beyond valid protocol or change signing, response
bytes, retries, timeout budgets, dependencies or providers.

Regression sources in `internal/cli/bridge_eof_test.go` retain the direct
admission transition checks and the default `Run` signed HTTP lifecycle. A
separate signed HTTP case uses an optional, internal per-invocation observer:
`bridge` delegates to `bridgeWithObserver` with nil, and both execute the same
loop. Main computes `input := admission.input(frames)`, observes that candidate
and admission state immediately before select, and uses that same `input` in the
ordinary receive arm. The observer reports exactly once through a buffered test
event; it does not block main or the worker, alter admission, or add a production
queue, public API field or global hook.

The fixture consumes every initialize response byte while holding its Write
return, then sends initialized and tools/list. Its third raw Read copies the
complete tools frame into bufio's supplied buffer before signaling read-ahead.
This proves bytes have been furnished to the bounded reader buffer, not that
Read has returned or that tools has been parsed or sent. Before releasing the
held Write, the observed-loop case requires both that signal and an actual
pre-select checkpoint with busy true, pending exactly initialized, and evaluated
input nil. Replacing the actual select candidate with unconditional frames makes
that assertion fail independently of scheduling or the old inline-completion
path. This is a static counterfactual, not an executed old/new comparison; the
helper-only assertion is not the production-wiring oracle. No sleep, timed
absence of a receive, or queue growth supplies the discriminator. Bounded receives
and cleanup joins are failure guards only.

Both HTTP cases require the exact three HTTP bodies in
initialize/initialized/tools order, exact two response frames, no extra
output/calls and joined cleanup. The unchanged default `Run` path requires code
0 and empty diagnostics; the observed internal bridge path requires nil error.
The default case alone is not claimed to fail every old scheduling interleaving.

The existing pending-EOF regression still holds the current writer until Close
and requires protocol failure even though that worker returns nil: terminal EOF,
not invalid normal admission, now triggers it. Additional controls cover malformed,
truncated, read-error and unsupported cancellation behind accepted pending while
that writer is held. Separate context-cancellation controls require reader join
with unreceived ordinary read-ahead and bridge join while pending is full and the
writer is held. The causal broken/blocked/peer-drain and accepted raw-close
sources are untouched. All changes in this correction are file-tool edits only;
no commands, tests, formatting or builds were run. Parent integration must apply
only reviewed hunks from this cumulative source checkout (parent source
`42c4256`), preserving current-main integration links and formatting. The separate
persistence blocker and its accepted deployment limitation are unchanged.

## Parent-CI sources and remaining gates

The earlier fixture/documentation correction described below was **unrun here**.
That Task89 follow-up changed the owned-output test in
`internal/cli/limits_test.go` from a 900,000-byte response to a small reply with a
saturated pipe, plus documentation; the admission correction above is a separate
production change.
Historically, parent-provided logs for exact head
`8c769b36bdb862dca9136b73ad331915d395f73b` recorded Linux normal/race/coverage
failures in both raw input-close and output-close cases at the former
`errors.Is(opErr, os.ErrClosed)` assertion. Those logs contained no actual error
value/type, so the raw/public error-layer mismatch was a source-based diagnosis,
not a newly observed runtime result. The logs were found read-only in the parent
`.rush/stdin` directory. No production change was needed for this test-oracle
correction. The parent reports all 32 checks SUCCESS for raw-close head
`9b6778acaa474a162426cc918b9c1708d61acacc`, merged in
`40e90768bb38c66f6566678ee1843afaec549508`. This is historical parent acceptance,
not a new rerun claim or an outstanding raw-close deficiency.

Parent-CI postmerge evidence for Task89 repeats across merge SHAs
`40e90768bb38c66f6566678ee1843afaec549508`,
`d3401c3df805f7daaa5d984370205bda5ab7399c` and
`07aec81cfdb378c9a047ae73e45ab2714a51e5e1`:
`.rush/stdin/cli-postmerge-40e9076-failed.log`, lines 13–22, records the race
failure in `TestOwnedPipeBrokenOutputAndBackpressure/blocked` with
`parent fixture synchronization timed out` and process exit 1. Additional
parent-provided evidence in `.rush/stdin/packaging-postmerge-d3401c3-failed.log`,
lines 13–22, records the same blocked synchronization timeout (3.05s) at
`limits_test.go:106`, exit 1;
`.rush/stdin/design-postmerge-07aec81-failed.log`, lines 13–22, records the broken
case synchronization timeout (3.03s) at `limits_test.go:106`, exit 1. The repeated fixture failure is
not limited to blocked output and does not establish a packaging or design
cause. These excerpts contain neither the bridge Run code nor its stderr.
The former fixture signaled handler entry before constructing its 900,000-byte
response; its size-threshold Write signal was downstream of the real
signing/verification and JSON pipeline. From source, `bridge.go` starts the
unchanged 2000 ms timer before `relayFrame`: HTTP response production, SDK
buffering/body-hash/signature verification, `connection.post` checks,
duplicate-aware `responseObject` parsing and output all share that budget.
Expensive pre-stdout processing exhausting it was a source-based hypothesis,
**not a proven runtime cause**, for those historical synchronization-only logs.
It is superseded for the new diagnostic above; the historical excerpts alone
established no production bug. That earlier correction changed the owned-output
test fixture and documentation only, not production, SDK, manifests or the
separately accepted raw-close controls.
Parent integration should
transfer only reviewed hunks to fresh current main, preserving its existing
formatting and Go 1.22 source-link updates; this source checkout is not an
instruction to replace those paragraphs.

Sources include real Unix listeners and real HTTP signing/verifying middleware,
not solely fake round-trippers; process sources launch the parent-CI test binary
as a child through production `RunProcess` preparation without a nested build.
Setting `JACK_CLI_EXECUTABLE` to an absolute parent-provided executable path runs
that artifact with the same CLI arguments instead. The tests do not build it or
establish its provenance; parent CI must identify the artifact under acceptance.
Child cleanup kills and reaps even after an assertion failure, with a once-only
Wait path. Expected failures require normal exit status 1: a watchdog expiry,
signal kill, helper error or other exit code cannot satisfy a negative control.
Parent request/entry channel receives have explicit timers; stderr verdicts are
examined only after child Wait. Lifecycle stdout frames are read interactively,
with child watchdog failure separately disqualifying the final verdict. Coverage
sources discriminate exclusive overwrites, bootstrap repetition/corruption,
owner locks, each independent tuple mismatch/no network, secret-free diagnostics,
mode/symlink/size refusal, exact bytes, identity duplicate stripping, fixed routing,
redirect refusal, native enrollment interception, signed GET 405/SSE 501 versus
unsigned DELETE 405, distinct response-body/status/signature tampering and
request-body tampering (zero upstream calls), lifecycle/framing, request 202/204,
notification 202 versus 204 and nonempty 202, bridge session-header refusal,
multibyte UTF-8 split within a code point and escaped-newline byte preservation,
cancellation/in-flight EOF, input deadlines, broken pipes, blocked stdout, exact
1 MiB/request cap+1/response cap+1 controls and upstream deadlines. Cancellation
requires exact `errProtocol` stderr; in-flight EOF instead requires `errRemote`,
because EOF cancels and returns the POST result and `connection.post` maps HTTP
errors to `errRemote`. A separate real-process enrollment HTTP-timeout control
stalls a real peer before response headers (outside Native dispatch), requiring
the different `errRemote` diagnostic without the bridge's competing idle timer.
It is a negative control for the cancellation oracle, not an enrollment/signature
verification success control. All three require zero stdout, normal exit 1, an
upstream request-context cancellation observation and exactly one upstream call;
watchdog expiry or fixture abort cannot pass. A silently ignored cancellation
that only fails later on HTTP/idle timeout cannot match the protocol diagnostic.
Refusal tests check exact diagnostics, so request 202 acceptance followed by an
idle timeout
cannot pass; verified 204/405/501 remain distinct from protocol failures. Broken
output must yield a protocol failure; blocked output must reach its deadline.
The Task89 owned-output fixture now uses a small signed terminal `tools/list`
reply (`id:2`, `result:{"tools":[]}`), after the normal initialize/initialized
exchange; independent exact-cap tests are unchanged. For blocked and peer-drain
cases, after consuming initialize it inspects `O_NONBLOCK` through
`SyscallConn.Control` (never `File.Fd`) and fills the owned pollable `os.Pipe`
through an actual one-byte `EAGAIN`/`EWOULDBLOCK`, accounting every filler byte.
No reader drains that pipe before the selected action. The output wrapper
compares the entire terminal reply plus LF, records mismatches, and probes that
exact response with a real nonblocking `syscall.Write` on the same live file.
Only an exact frame with no progress and response-specific would-block can
establish the backpressure stage; an unexpectedly successful probe invalidates
the precondition and its bytes are never delegated again. It then delegates the
actual `File.Write`; no test channel simulates a blocked writer.

The undrained case requires normal Run code 1, exact deadline stderr and a
zero-byte closed File.Write return, with response-specific EAGAIN already
observed; timeout before that stage fails, rather than passing as inactivity.
The distinct broken-peer case closes the reader before the final reply,
requires the exact frame's real syscall EPIPE, a real File.Write EPIPE/closed
return, and code 1 with exact protocol stderr. The peer-drain positive control
first observes the same response EAGAIN, drains exactly the zero filler, receives
the exact final frame and successful File.Write result, then sends stdin EOF
only after the reply is complete. It requires Run code 0, empty stderr and no
extra output before output EOF. Atomic counts require exactly initialize,
initialized and tools/list in order, once each, plus one terminal Write: no retry,
skip or call-timeout increase. These controls establish real OS causes, not that
the File.Write goroutine was already parked in the runtime poller.

Stage waits distinguish events, Run results and bounded failure guards; a cached
Run result avoids a second receive. On failure, cancellation and pipe close are
followed by bounded close/Run/IO joins before reporting stage, syscall and Write
error types/values, frame equality, filler and call counts, and Run code/stderr
when joined. Stderr is captured into an immutable result only after Run returns;
no diagnostic reads a concurrently written bytes.Buffer. A guard expiry or
failed join is always failure, never evidence of interruption. These test sources
remain unrun; they discriminate missing/changed output, wrong OS cause, early
HTTP/protocol failure, idle-only timeout, retries and failure to resume on peer
drain, without claiming to have reproduced the old runtime cause.

Focused follow-up sources additionally cover production preparation of initially
blocking pipe descriptors, regular-file rejection, pending EOF with a successful
final worker write, strict JSON-RPC error codes (null/string/fraction rejected), and invalid or
duplicate Native enrollment versions leaving invite/state bytes unchanged before
a valid enrollment. The process helper now uses the same `RunProcess` preparation
as the executable; the current follow-up edits remain unrun, and the prior
parent-CI failures above are not platform acceptance.

Remaining release gates are real: parent CI must compile, format-check and run
these sources on supported Unix systems and cross-build the fail-closed Windows
path. The artifact-selecting process sources still need execution against the
actual packaged executable; helper-process runs alone do not certify an artifact.
Further discriminating tests are needed for TLS certificate rejection, slow
inbound header/body sockets, overload and clock/nonce saturation, per-platform
filesystem races, root/different-UID socket bypass controls, and signal handling
in the packaged artifact. Added status/signature tamper and exact cap test sources
are unrun, not remaining source omissions or passing acceptance evidence. Permission
checks are not a proof that an upstream has no additional listener; inspect that
deployment separately. Official MCP SDK fixtures, their isolated toolchains,
workflow wiring, and conformance/owner acceptance remain outside this bundle.
Existing sibling threat-model/versioning/compatibility texts were read, not edited.

## Offline candidate server-key initialization and status

These commands use a separate private OOB profile, not client credentials or the
static gateway configuration. The configuration is subject to the existing
16 KiB private-config bound and strict known-field/duplicate checks. Replace the
symbolic values below with independently provisioned values; this is a schema
example, not a ready-to-run key fixture:

```json
{
  "version": 1,
  "store_file": "<absolute-private-store-file>",
  "endpoint": "https://service.example/mcp",
  "aud": "service-audience",
  "window": 30,
  "anchor_kid": "<canonical-base64url-SHA256-of-anchor-public-key>",
  "anchor_public_key": "<canonical-base64url-32-byte-public-key>",
  "anchor_reference": "local-provider/anchor"
}
```

The configuration and store have the CLI's private owner/type/mode requirements;
the parent directory must already exist and be private. This concrete durable
profile is limited to the qualified Linux/filesystem backend. The anchor is the
independently provisioned ordinal-zero public key, not a key discovered in a
remote payload. `window` is explicit and immutable. The exact endpoint/audience
and opaque anchor reference participate in the protected profile; these commands
neither normalize the binding nor load a signer seed or make an HTTP request.

`server-key-init-unused` requires both confirmation values to equal the configured
binding exactly. This is an operator assertion that this rotation binding is
unused, not proof or permission to migrate, replace a missing history, recover a
dirty store, or reset an unsafe clock. Creation is exclusive and never replaces
an existing file; an uncertain creation retains its artifact. Success has no
stdout.

`server-key-status` opens offline inspection under the lifetime-exclusive owner
lock, so a concurrently serving owner prevents it. It does not enter serving,
call the clock, increment owner/revision/H, clear recovery flags, or read signer
material. Its JSON contains public store/owner/clock/state/head/count/flag
metadata only, never protected references, private snapshots, or supplied paths.
A dirty/unsafe report is diagnostic and still requires explicit recovery; the
command does not authorize restart or certify absence of backup rollback.
Malformed or missing stores produce a generic failure without creation or reset.
These commands do not yet select a rotation gateway mode or publish a key.
