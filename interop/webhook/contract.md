# Webhook matrix executable contract

Status: normative for the `webhook_sender` and `webhook_receiver` executables that `interop/webhook.mjs`
launches, and for the self-test fakes, dated 2026-11-23. Sources: [`spec/06-webhooks.md`](../../spec/06-webhooks.md)
(all sections) for the delivery profile, signatures, receiver order, `w1`, endpoint verification, SSRF and Server
Card keys; `spec/fixtures/modern/webhook-*.json` and `ssrf-vectors.json` for shapes; `interop/README.md` section
"Webhook matrix" for the harness; [`interop/webhook-scenarios.json`](../webhook-scenarios.json) for the exact
expected outcomes. The driver treats every statement here as a test oracle, so an executable that disagrees with
this document fails the matrix.

## 1. Roles

For every (sender language, receiver language, scenario) triple the driver runs:

1. one receiver process (`webhook_receiver` target) bound to a loopback TLS port the driver chooses, when the
   scenario needs a receiver;
2. optionally one tamper relay inside the driver process, between sender and receiver; the sender is then given
   the relay's URL instead of the receiver's;
3. one sender process (`webhook_sender` target) that performs the scenario's fixed delivery sequence.

Every hop is `https` (spec 06 R6.1). Nothing here adds SDK API: the executables configure the SDK sender, the
SDK receiver, the SDK endpoint-verification gate, the SDK Server Card key acceptance and the SDK hardened delivery
client; the HTTP listener, the stdout protocol, the clock file and the SSRF seams are the executables' own code.

## 2. Conventions shared by both roles

- **Line discipline.** stdout carries only the lines this document defines, one JSON object per line,
  newline-terminated. Diagnostics and startup failures go to stderr. No other stdout output, ever.
- **Exit codes.** `0` the process completed its role; `1` the process could not start or could not complete
  (invalid flag value, bind failure, unreadable clock file, TLS files unusable) with a one-line stderr diagnostic
  and no result line; `2` reserved for usage errors. A protocol refusal is never an exit code: a receiver that
  answered `401` and a sender whose delivery ended `final` both exit `0`.
- **Fixed clock.** Both roles read one decimal integer from `--clock-file` every time they need "now", and never
  consult the wall clock for it. The driver writes the scenario's values before the run.
  - The receiver reads the file once per delivery and passes that value as the receiver clock (`now`).
  - The sender reads the file as `t0` and for every attempt timestamp. Its retry waits are **virtual**: when the
    SDK asks to wait until an instant (Go `SenderConfig.Sleep`, the Rust `Clock::sleep_until_ms`, the TypeScript
    `sleep` option), the executable writes the absolute target instant (Unix seconds, decimal) into its own clock
    file and returns immediately. The file therefore walks `t0`, `t0 + 30`, `t0 + 270`, `t0 + 870` for a message
    that is retried three times, and every attempt signature carries that attempt's timestamp (spec 06 R1.5).
  - No sleep ever costs wall-clock time, and no timestamp is random.
- **TLS.** The driver generates a throw-away CA and a leaf certificate at run time with the `openssl` CLI in its
  temporary directory. The leaf's only subject alternative name is `DNS:hooks.example.test`; every callback URL in
  this matrix uses that name, so no IP SAN is needed. The receiver serves TLS with `--tls-cert` / `--tls-key`.
  The sender must trust the CA through its SDK's public configuration:
  - TypeScript: `--tls-ca <pem>` (the executable's injected `HardenedDialer` passes `ca` to `node:https`).
  - Rust: `--tls-ca-der <der>` (`webhook::http::HttpsTransport::with_roots`).
  - Go: no public option exists; the driver also sets the environment variable `SSL_CERT_FILE=<ca.pem>` for the
    sender process and the Go executable relies on `crypto/x509` reading it on Unix. See section 10, gap 1.
- **SSRF relaxation for loopback.** The driver always passes `--allowed-range 127.0.0.0/8`, the operator override
  of spec 06 R6.11, to the sender, so a validated answer inside the loopback block is `allowed` with reason
  `allowed_range`. That is the only relaxation; the address tables and the rebinding rule stay in force.
- **Injected resolver.** `--resolver-file <json>` is a JSON object mapping a host name to an array of address
  literals in resolver order, for example `{"hooks.example.test":["127.0.0.1"]}`. The sender resolves every name
  through it and through nothing else; a host that is absent from the object is a resolution failure. Without the
  flag the SDK's own resolver is used.
- **`--rebind-address <ip>`.** The sender must make the address it connects to differ from the address it
  validated, by whichever public seam its SDK offers: its injected resolver answers `--rebind-address` on its
  second lookup (spec 06 R6.8 resolves twice in Rust), or its injected dialer connects to `--rebind-address`
  instead of the validated address (Go, whose delivery client re-checks the connected peer). The expected answer is
  `dns_rebinding` (spec 06 R6.9), category `connection_refused`, final.
- **Framing.** Every delivery POST carries `Content-Length` and never uses chunked transfer coding, so the relay and
  the receiver can reason about the declared length before reading a body.
- **Values supplied by the driver.** The audience `https://svc.example.test`; the fixture seeds read from
  `spec/fixtures/keys.json` (`alice`, `newbie`, `mallory`, `svc`); the throw-away TLS files; the clock files; the
  scenario id. The executables never read `spec/fixtures/` themselves.

## 3. Pinned constants

Both roles and the driver use these exact values; they are the whole configuration space of the matrix.

| constant | value |
|---|---|
| principal | `alice` |
| event name (also the subscription `name`) | `incident.created` |
| subscription `arguments` | `{"severity":"P1"}` |
| callback URL | `https://hooks.example.test:<port>/hooks/alice` |
| audience (`--aud`) | `https://svc.example.test` |
| clock base (`t0`) | `1800000000` |
| delivery secret | the 32 bytes of `SHA-256(utf8(--secret-seed))`, the driver passing `mcp-jack-interop-webhook/secret/1` |
| webhook signing key (`v1a`, `v2a`, `w1`) | fixture `newbie` (seed and `kid` from `spec/fixtures/keys.json`) |
| never-published key (`v1a`, `v2a`) | fixture `mallory` |
| MCP server key (must never verify a webhook) | fixture `svc` |
| Server Card MCP URL (`--card-mcp-url`) | `https://mcp.example.test/mcp` |

The subscription id is `sub_` + the first 16 lowercase hex characters of `SHA-256` over the UTF-8 bytes of the
JCS array `["mcp-jack/webhook1/subscription", principal, canonical_url, name, arguments]` (spec 06 R8.4). The
canonical URL keeps `:port` because the port is never 443, and the JCS text of `arguments` is
`{"severity":"P1"}`. The id therefore changes with the driver-chosen port, and the driver passes it to both
executables; the sender still reports the id it derived so the two derivations can be compared.

Event bodies, exact bytes, no trailing newline:

```
{"eventId":"evt_1","name":"incident.created","timestamp":"2026-11-22T09:00:00Z","data":{"incidentId":"INC-1234","severity":"P1"},"cursor":"cursor_xyz"}
{"type":"gap","cursor":"cursor_7f3a"}
{"type":"terminated","error":{"code":-32024,"message":"Forbidden","data":{"reason":"Access revoked"}}}
{"type":"verification","challenge":"<nonce>"}
```

Webhook ids satisfy spec 06 R1.4. Where the SDK exposes an id seam (Go `sender.Message.WebhookID`, the TypeScript
`randomBytes` option) the executable must produce the derived id: for the 0-based message index `i` of a scenario,
the 32 characters after the prefix are taken from `d = SHA-256(utf8("mcp-jack-interop-webhook/id/" + <scenario> +
"/" + i))`, character `j` being `ALPHABET[d[j] % 62]` with
`ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"`. The prefix is `msg_` for an event
and for a raw body, `msg_gap_`, `msg_terminated_` or `msg_verification_` for the control envelope of that name. A
retry reuses the id unchanged. Where the SDK draws the id internally and exposes no seam (Rust, section 10 gap 3)
the id is free; it must still satisfy the grammar and stay unchanged across the retries of one message, so the
scenario table pins grammar and stability, never those 32 characters.

Server Card document the driver writes for `--card-file`:

```json
{"remotes":[{"url":"https://mcp.example.test/mcp","extensionsInfo":{"io.modelcontextprotocol/events":{"webhooks":{"signingKeys":{"keys":[{"kty":"OKP","crv":"Ed25519","x":"<base64url of the fixture public key>","kid":"<fixture kid>","use":"sig","alg":"EdDSA"}]},"egressIpRanges":["198.51.100.0/24"]}}}}]}
```

The receiver derives its accepted key set from that document with the SDK's Server Card decision
(`webhook.FetchDecision` / `webhook::card::fetch_decision` / `fetchDecision`), as if a `200` response carrying
`Content-Type: application/mcp-server-card+json` had been fetched from `default_card_url(--card-mcp-url)` for the
same origin. The HTTP fetch of spec 06 R7.2 is not performed (section 10, gap 5). The configured MCP server key
(`--mcp-server-kid`, and the raw key when the SDK takes one) must be applied at the JWK step, so a card that only
publishes the server key yields no accepted key.

## 4. Sender executable (`webhook_sender`)

### 4.1 Invocation

```text
webhook_sender --scenario <id> --url <https-url> --aud <aud> --clock-file <file>
               --secret-seed <text> --messages <kind>[,<kind>...]
               [--subscription-id <sub_...>] [--signing-seed-hex <64 hex>]
               [--jack-seed-hex <64 hex>] [--allowlist <https-url-prefix>]...
               [--allowed-range <cidr>]... [--resolver-file <file>]
               [--rebind-address <ip>] [--body-file <file>]
               [--tls-ca <pem-file>] [--tls-ca-der <der-file>]
```

- `--url` is the callback URL the driver gives: the receiver's address, or the relay's address in the scenarios
  that use one. `--scenario` only feeds the id derivation and is echoed.
- `--messages` is the ordered list of messages the process sends, one delivery each: `event`, `gap`,
  `terminated` or `raw`. Default `event`. `raw` sends the exact bytes of `--body-file`.
- `--signing-seed-hex` enables `v1a` and `v2a` with that Ed25519 key as the current key (no previous key).
  Without it the emission set is `v1` only.
- `--jack-seed-hex` enables `Jack-Webhook-Auth` (`w1`) with that key. Without it there is no `w1` header.
- `--allowlist` is one operator allowlist entry (spec 06 R5.7, repeatable) for the endpoint verification gate. The
  driver passes the callback URL itself, so route 2 verifies the pair without any verification POST. Without it the
  gate runs its full order and falls through to the challenge handshake (route 5).
- `--subscription-id` overrides the id used everywhere on the wire (header, `v2a` content, `w1` signing string,
  result line). It never changes the derived id the process reports.
- `--secret-seed` is required. The secret bytes are derived as in section 3; the executable never decodes a
  `whsec_` literal.

### 4.2 stdout protocol

The process prints exactly two lines, and no other line, in this order:

1. the ready line, first, before any delivery:
   `{"ready":true,"role":"sender","callback_url":"<--url>","derived_subscription_id":"<sub_...>"}`
2. the result line, last, exactly once:
   `{"event":"result","scenario":"<id>","role":"sender","callback_url":"<--url>","derived_subscription_id":"<sub_...>","results":[{"message":<i>,"kind":"event|gap|terminated|raw","webhook_id":"<id>","attempts":<n>,"accepted":<bool>,"http_status":<int|null>,"last_error":"<category>"|null}]}`

Nothing else reaches stdout: any additional line, whether a per-attempt line, a progress line or a warning, is a
contract violation of this section. There is no per-attempt line, and the driver treats a third line as a defect
and fails the scenario. Every attempt is observed by the driver on the receiving side, where the wire evidence
lives: the receiver's delivery line for a scenario that reaches a receiver, and the relay's recorded request for a
scenario whose relay answers without forwarding (`retry-http-503`). That is the one observation every SDK supports
through its public API, and it is what makes a regression of an SDK retry loop fail the matrix instead of being
masked by the executable.

`http_status` is the status the sender read, `null` when no response arrived. `last_error` is a category of
section 4.4, `null` when accepted. `attempts` is the number of POSTs the message actually wrote, normalised by this
rule: the SDK's own attempt count is used as it is, except that a message refused before any request was written
reports `0`. That covers the Rust case where `Sender::deliver` increments `attempts` before a pre-connect policy
refusal and returns `SendAction::Final` without a `last_status`, and the Go case where `Deliver` counts a loop
iteration whose attempt refused locally: both report `0` when the result carries `ssrf_blocked_address` or
`ssrf_rebinding_blocked`, and their SDK count otherwise. Exit `0` whenever all messages ran, whatever the outcome.

### 4.3 What the sender must do

Per message, through the real SDK sender:

1. Build the message from section 3: body, kind, subscription id, `v1` secret, optional `v1a`/`v2a` key and
   `w1` key, `Principal`/`callback URL` pair, a one hour remaining TTL.
2. Run the SDK's **production delivery loop**, the one that waits, retries and classifies: Go `Sender.Deliver` with
   `SenderConfig.Now` and `SenderConfig.Sleep`; Rust `Sender::deliver` with the injected `Clock`; TypeScript
   `WebhookSender.deliver` with the `now` and `sleep` options. That loop performs the endpoint verification gate, the
   hardened address decision, the R1.1 header set, the emission order of R2.8, a fresh timestamp and signature per
   attempt, the R1.7 classification, the R1.8 schedule and the R1.9 category. The executable must not sign, resolve,
   schedule or classify a delivery itself, and must not replace the loop with its own attempt driving (for example
   Go `Attempt` plus `Decide`, which neither waits nor retries).
3. Name a delivery that ended without a response with section 4.4, and report only the result line. The wire
   evidence is not the executable's to produce: the receiver logs every POST it judged and the relay records every
   request it accepted, and section 7 has the driver check both.
4. A challenge POST is not a delivery: it never appears in the result line's `attempts` and is verified through the
   receiver's delivery lines, which are the oracle for the handshake.

### 4.4 Delivery categories (`last_error`)

`last_error` is the spec 06 R1.9 category, except that the two SSRF policy refusals are named apart from a plain
network failure, so the matrix can tell "the policy stopped it" from "the network refused it":

| category | when |
|---|---|
| `null` | accepted (a 2xx) |
| `http_4xx`, `http_5xx` | a non-2xx response, exactly as R1.7/R1.9 classify it |
| `timeout`, `tls_error` | the matching transport failure |
| `challenge_failed` | the endpoint verification refused the pair |
| `ssrf_blocked_address` | every answer was classified against the R6.5/R6.6 tables and rejected, so no connection was made |
| `ssrf_rebinding_blocked` | the validated answer and the connected peer, or the two resolutions, disagree (R6.9), so no request was written |
| `connection_refused` | a real connect or DNS failure, retryable |

`ssrf_blocked_address` and `ssrf_rebinding_blocked` are final, `connection_refused` is retryable, exactly as R1.9
reads `blocked_address`, `dns_rebinding` and a transport failure. Go and Rust collapse both policy refusals into
`connection_refused` in their delivery result, so the executable names the policy category with the SDK's own public
decision function, called BEFORE the delivery with exactly the inputs it gives the sender (the same injected resolver
answers, the same recheck answers, the same allowed ranges): Go `webhook.CheckDelivery`, Rust
`webhook::ssrf::delivery_decision`, TypeScript `checkDelivery({ url, answers, recheck, allowedRanges })`. A
`blocked_address` decision is reported as `ssrf_blocked_address`, `dns_rebinding` as `ssrf_rebinding_blocked`, and the
executable still runs the production delivery loop afterwards, which must then refuse without opening a connection;
any other decision leaves the category to the delivery result (`http_4xx`, `timeout`, `connection_refused`, ...).
The result line reports `last_error` as the pre-flight category when the pre-flight blocked, whatever the collapsed
delivery result says, and `attempts: 0`.

The driver proves the refusal on the wire: the shadow listener counts the connections it accepts, so a scenario that
is expected to refuse before connecting fails if anything was dialled (section 7).

`blocked_address` maps to `ssrf_blocked_address`, `dns_rebinding` to `ssrf_rebinding_blocked`; any other outcome of
that decision, and any transport failure, is `connection_refused`.

## 5. Receiver executable (`webhook_receiver`)

### 5.1 Invocation

```text
webhook_receiver --port <n> --tls-cert <pem> --tls-key <pem> --clock-file <file>
                 --secret-seed <text> --subscription-id <sub_...>
                 --callback-url <url> --aud <aud>
                 [--pending-secret] [--card-file <file>] [--card-mcp-url <url>]
                 [--enforce-server-identity] [--require-jack]
                 [--mcp-server-kid <kid>] [--enqueue-fail <n>]
```

- `--port` binds `127.0.0.1:<n>` (`0` means any free port). `--callback-url` is the exact URL the sender uses,
  which `w1` binds for this subscription id.
- `--secret-seed` registers the delivery secret for `--subscription-id`, and that id is routed (spec 06 R3.7,
  R3.8).
- `--pending-secret` registers the delivery secret as a **pending** entry of spec 06 R5.6 instead of a registered
  one: the secret is bound to `--callback-url` only, the subscription id is neither registered nor routed, and a
  `verification` envelope is the only body that entry may authenticate. A successful challenge binds the id and
  routes it, so the handshake is what grants the delivery. `--subscription-id` is still supplied and echoed; it only
  names the subscription the sender is about to create. The executable reports the effect of the flag through
  `subscription_known` (section 5.2), derived from its state.
- `--card-file` plus `--card-mcp-url` install the accepted Server Card keys of section 3; without them the accepted
  set is empty and `v1a`/`v2a` are advisory.
- `--enforce-server-identity` sets the R3.14 enforcement flag. `--require-jack` enables `w1` verification with
  `--aud`, the default 30 s window and `{"<subscription-id>": "<callback-url>"}` as the known callback map.
- `--mcp-server-kid` is the configured MCP server key id that `w1` and the card must never accept (R4.5, R7.3).
- `--enqueue-fail <n>` makes the first `n` durable enqueues fail, which the SDK answers `503 enqueue_failed` and
  records nothing (R1.10, R3.17). Default `0`.

### 5.2 stdout protocol

1. one ready line:
   `{"ready":true,"role":"receiver","port":<n>,"subscription_id":"<sub_...>","subscription_known":<bool>}`
   where `subscription_known` is `true` exactly when the subscription id the executable was given was already
   registered and routed in the receiver's own state when the listener started, and `false` when the executable
   holds only a pending secret (spec 06 R5.6) that routes nothing until a verification challenge. It is the result
   of looking that id up in the state the executable built, the SDK registry or routing table after construction,
   never a copy of the `--pending-secret` flag: the driver compares it against the scenario, so an echoed flag is
   caught in the challenge scenarios, which must report `false`. The driver fails a pending scenario whose ready
   line reports `true`, because then the handshake cannot have been what routed the id.
2. one delivery line per received POST, in arrival order:

```
{"event":"delivery","seq":<n>,"status":<int>,"code":<string|null>,"body_status":"accepted|duplicate|challenge"|null,
 "kind":"event|gap|terminated|verification"|null,"webhook_id":"<id>","subscription_id":"<id>",
 "webhook_timestamp":"<decimal>","challenge":"<nonce>"|null,"enqueued":<n>,"forwarded":["<b64u>",...],
 "headers":[["<name>","<value>"],...],"body_b64u":"<base64url of the exact body bytes>"}
```

`seq` counts from 0. `status` is the HTTP status the SDK answered and `code` its `error.code` or `null`.
`body_status` is read from the answer body: `{"status":"accepted"}` becomes `accepted`, `{"status":"duplicate"}`
becomes `duplicate`, `{"challenge":"..."}` becomes `challenge`, anything else `null`. `kind` describes the message
the SDK authenticated and dispatched, or `null` when the delivery was refused before the body was parsed, and
`challenge` is the echoed nonce or `null`. `headers` lists the header instances the listener received, with the
names as received; framing headers may be omitted. `body_b64u` is the exact body bytes the receiver judged, and the
**empty string** when the receiver refused on the declared `Content-Length` without reading (R1.2, R3.6).

`enqueued` and `forwarded` are mandatory on every delivery line; the driver fails a line that omits either, or
that carries a non-integer `enqueued` or a non-array `forwarded`. `enqueued` is the cumulative number of
messages the executable's durable enqueue callback has received for **forwarding**, counting every event, `gap`
and `terminated` body from the first delivery of the process up to and including this one, and never a
`verification` envelope (spec 06 R3.18 echoes it instead). `forwarded` carries, base64url and in order, the
bytes this delivery passed to the enqueue callback, and is empty when nothing was forwarded: the canonical JSON
text of the parsed payload (members sorted, no insignificant whitespace) for the Rust and TypeScript receivers,
the raw message bytes for the Go receiver. The driver therefore compares forwarded payloads by **parsed value**,
never by bytes, and requires each forwarded payload to equal the body of that delivery. Go invokes the enqueue
callback for control envelopes too, including the `verification` challenge, so the executable must filter them
out by `type: verification`: a verification envelope is echoed, never counted in `enqueued` and never forwarded.
Together they are what proves R1.10 and R3.16: a duplicate answers `2xx` without changing `enqueued`.

Any other request (a well-known document fetch, a health probe) answers `404` with
`{"error":{"code":"no_route","message":"not a delivery endpoint"}}` and is never logged. Responses are framed with
`Content-Length` and never with chunked transfer coding, because the relay reads exactly one `Content-Length`-framed
response per request (section 8). SIGTERM, SIGINT or stdin EOF stops the receiver with exit `0`.

### 5.3 How the receiver serves a delivery

The executable owns the TLS listener and turns one request into the SDK receiver's inputs: the header pairs as
received, the raw body bytes and the clock value. Before reading a body it applies R1.2's declared-length rule, so
an oversized declaration is answered `413 body_too_large` without a byte being buffered. It then asks the SDK
receiver and writes the SDK's status, `Content-Type`, `WWW-Authenticate` (401 only) and body verbatim. The
executable must not verify, parse, deduplicate, terminate or enqueue anything itself: it registers one durable
enqueue callback that only counts and stores the forwarded messages, and it applies `--enqueue-fail`.

## 6. Scenario to operation

`interop/webhook-scenarios.json` carries, per scenario, the sender configuration, the receiver configuration, the
relay preset and the expected outcomes. Message kinds, key material and the gate route are exactly the values in
that file; nothing else may be sent.

Each scenario also carries driver switches. `gap` maps a sender language to the reason that language's cell is
skipped: the driver prints `SKIP <id> (sender=<lang>: <reason>)`, counts the scenario out of that cell's total and
never reports it as a pass, so a declared SDK gap is visible but cannot hide a failure. `cross_check: false` turns
off the driver's comparison of the relay's recorded request with the matching receiver delivery line, which is needed
when the relay rewrites a header after signing (the ids then legitimately differ); every other scenario keeps that
comparison.

The expected outcomes are recursive subsets of the driver's own views, never of an executable's claims:
`expected.sender` is matched against the sender's result line (its `event` member removed), `expected.attempts`
positionally against the relay's recorded requests, and `expected.deliveries` positionally against the receiver's
delivery lines, each array with equal length. Every scenario whose sender reaches a relay states
`expected.attempts`, and an attempt record carries the same `signatures` shape as a delivery, recomputed by the
driver from the bytes the relay recorded.

| scenario | sender | receiver | what it proves |
|---|---|---|---|
| `deliver-v1` | allowlist, `v1` only, one `event` | registered secret, no card | R1.1 header set, `v1` over the raw body, 200 `accepted` |
| `deliver-w1` | allowlist, `v1` + `w1` (`newbie`) | card `newbie`, `--require-jack` | `w1` bound to aud, subscription and callback URL; card key discovery |
| `deliver-asymmetric` | allowlist, `v1` + `v1a` + `v2a` (`newbie`) | card `newbie`, `--enforce-server-identity` | R2.8: the emission order is exactly `v1 v1a v2a` and all three verify under enforced identity |
| `refuse-unpublished-signing-key` | allowlist, `v1` + `v1a`/`v2a` (`mallory`) | card `newbie`, enforce | a key the card does not publish never verifies: 401 `bad_server_signature` |
| `refuse-jack-server-key` | allowlist, `v1` + `w1` (`svc`) | card `newbie`, `--require-jack`, `--mcp-server-kid` = `svc` kid | R4.5: 401 `webhook_key_is_server_key` before the key lookup |
| `verify-challenge` | no allowlist, `v1` only | `--pending-secret` only: a pending secret and its callback URL, nothing registered or routed | R5.4-R5.6: one `verification` POST echoed, the challenge routes the id, then the event is enqueued |
| `verify-challenge-w1` | no allowlist, `v1` + `w1` | `--pending-secret`, `--require-jack` | the same handshake with the challenge itself `w1`-signed and verified against the pending entry's callback URL |
| `refuse-tampered-body` | allowlist, relay rewrites the body after signing | registered secret | 401 `bad_signature` over the tampered bytes |
| `refuse-tampered-header` | allowlist, relay rewrites `webhook-id` | registered secret | 401 `bad_signature` |
| `refuse-stale-timestamp` | allowlist, sender clock `t0` | receiver clock `t0 + 301` | 401 `stale_timestamp`, after the HMAC verified |
| `refuse-future-timestamp` | allowlist, sender clock `t0` | receiver clock `t0 - 301` | 401 `future_timestamp` |
| `refuse-unknown-subscription` | allowlist, `--subscription-id sub_0000000000000001` | registered secret | 401 `unknown_subscription` although the HMAC would verify |
| `refuse-unknown-envelope-type` | allowlist, `raw` body `{"type":"bogus"}` | registered secret | 401 is not enough: 400 `unknown_envelope_type` after authentication |
| `refuse-malformed-body` | allowlist, `raw` body that is not JSON | registered secret | 400 `malformed_body` after authentication |
| `refuse-body-too-large` | allowlist, relay declares `Content-Length: 262145` | registered secret | 413 `body_too_large` before reading: the logged body is empty |
| `dedup-repeated-delivery` | allowlist, relay replays the exact bytes | registered secret | 200 `accepted` then 200 `duplicate`, one enqueue |
| `control-gap` | allowlist, `gap` | registered secret | 200 `accepted`, `msg_gap_` id, exact envelope forwarded |
| `control-terminated` | allowlist, `terminated` then `event` | registered secret | 200 `accepted` then 410 `subscription_terminated` |
| `retry-http-503` | allowlist, relay answers `503` | none | four signed POSTs recorded by the relay at `t0`, `t0+30`, `t0+270`, `t0+870` with one unchanged `webhook-id`, `http_5xx`, abandoned |
| `retry-enqueue-failed` | allowlist, one `event` | `--enqueue-fail 1` | 503 `enqueue_failed` then 200 `accepted`, same id, timestamps 30 s apart |
| `ssrf-private-address` | allowlist, resolver answers `10.0.0.5` | registered secret, nothing may arrive | `ssrf_blocked_address`, final, zero POSTs at the relay or the receiver |
| `ssrf-dns-rebinding` | allowlist, resolver answers `127.0.0.1`, `--rebind-address 127.0.0.2` | registered secret, nothing may arrive | `ssrf_rebinding_blocked`, final, zero POSTs (skipped for the TypeScript sender, gap 2) |

## 7. What the driver checks

For every run the driver:

1. parses the sender's and the receiver's stdout, so neither executable's claims are trusted blindly: the ready
   lines must be well formed, the result line must be last, the receiver's ready port must be the one the driver
   chose, and its `subscription_known` member must agree with the scenario.
2. re-verifies every received delivery itself with independently pinned material: the `v1` HMAC over
   `webhook-id + "." + webhook-timestamp + "." + body` with the section 3 secret, `v1a` and `v2a` with the Ed25519
   public keys of the scenario's card set (`v2a` over the SHA-256 of `subscription-id + "." + id + "." + ts + "." +
   body`), and `w1` with the same card keys over the seven-line signing string of spec 06 R4.2. It records, per
   delivery, whether each scheme is present, how many entries it has, whether any entry verifies, and the emission
   order of the schemes as `signature_schemes`.
3. checks the R1.4 id grammar and the id prefix that belongs to the message kind, the R1.5 timestamp grammar, and
   that every delivery carries the effective subscription id.
4. takes the attempt evidence from the receiving side, never from the sender: the receiver's delivery lines for a
   scenario that reaches a receiver, or the relay's recorded requests for a scenario whose relay answers without
   forwarding. `expected.attempts`, which every relay-bearing scenario states, is matched positionally against the
   relay's records (`seq`, `webhook_timestamp`, `http_status`, `signature_schemes`, `webhook_id_prefix`,
   `same_webhook_id_as_previous` and `signatures`), which is how the retry schedule of R1.8 and the unchanged
   `webhook-id` of R1.4 are pinned.
5. proves the enqueue with `enqueued` and `forwarded`: a `2xx` raises `enqueued` by one and `forwarded` names the
   body, a duplicate leaves `enqueued` unchanged, and a `503 enqueue_failed` leaves it unchanged too.
   A refusal (any non-2xx, including `401`, `413` and `503`) must forward nothing, and one delivery forwards at
   most one message. A forwarded payload must equal the body of its delivery when compared by parsed value:
   canonical JSON text and raw bytes both parse to the same value.
6. compares the relay's records with the receiver's deliveries when both take part: same `webhook-id`, same
   `webhook-timestamp` and the same status for every forwarded request.
7. matches `expected.sender` against the result line, `expected.attempts` against the attempt evidence and
   `expected.deliveries` positionally against the receiver's delivery lines, each as a recursive subset (arrays:
   equal length, element-wise subsets), like the other matrices.
8. fails the cell on any harness problem: a nonzero exit, a missing ready or result line, an unparsable line.
9. runs the relay first where a scenario uses one: the relay binds before any URL is derived, the listening port
   it reports is the port the callback URL, the subscription id and every derived value carry, and the driver
   never allocates a port for the relay; the relay resolves its upstream, the receiver's port, lazily, after the
   receiver has proven it with its ready line.
10. takes the receiver's port from the receiver's command line and requires the ready line to report exactly that
    port; because a probed free port is released before the child binds, a receiver that fails to bind (no ready
    line) is retried on a fresh port, with the callback URL, the subscription id and every placeholder resolved
    again, at most three times, so the sender is never aimed at an endpoint nobody listens on.
11. requires every field a scenario names to be present in the observed view: a field missing from a delivery line
    or from a relay record fails by name instead of passing as a subset.
12. fails any sender output beyond the exactly two lines of section 4.2.
13. reads `expected.shadow_connections` as the fixed number of connections the shadow listener may accept, and the
    two SSRF scenarios fix zero on the shadow listener, zero requests recorded by the relay and zero deliveries.

## 8. Tamper relay

The relay is driver code, not a target. It listens on `127.0.0.1` with the same throw-away certificate, is the
sender's endpoint, and dials the receiver over TLS. The driver starts the relay before deriving any URL, which is
why `upstreamPort` may be a function of the still-unknown receiver port. The relay records its observation before
its preset acts, so `answer-503` and `drop` are still evidence for the driver. It reads one complete request (head
plus the declared body) and then applies its preset before forwarding, so it changes bytes **after** the sender
signed them:

| preset | effect |
|---|---|
| `pass` | forward unchanged |
| `tamper-body` | replace the first occurrence of `incident.created` with `incident.createX` in the body (same length) |
| `tamper-header` | replace the last character of the `webhook-id` value with another character of the same class |
| `inflate-length` | forward the head with `Content-Length: 262145` and the authentic body bytes unchanged |
| `repeat` | after relaying the first response, send the identical head and body again on a new upstream connection and record the second response |
| `answer-503` | never dial: answer `503` with `{"error":{"code":"enqueue_failed","message":"enqueue failed"}}` |
| `drop` | record the request and close the connection without any response, so the sender sees a transport failure |

Every preset, including `answer-503`, `repeat` and `drop`, records the request it accepted as
`{seq, webhook_id, webhook_timestamp, signature, body_b64u, status}` before it acts, where `signature` is the
`webhook-signature` header value and `status` the status the relay answered with or read upstream (`null` for
`drop`). That record is the driver's attempt evidence for a scenario without a receiver and its cross-check for a
scenario with one. The relay reads exactly one response per forwarded request, framed by `Content-Length`: a
response without a decimal `Content-Length` is not relayed and the attempt ends as a timeout for the sender. A
preset that cannot apply (a body without the marker, a request without `webhook-id`) forwards unchanged and
therefore fails the scenario that asked for it.

## 9. Self-test fakes

`interop/tools/fakes/webhook/` holds an independent implementation of this contract that uses no SDK:
`webhook-sign.mjs` (Ed25519/HMAC helpers and the section 3 derivations over `node:crypto`),
`fake-webhook-sender.mjs` and `fake-webhook-receiver.mjs`. They follow sections 2 to 6 exactly, including the TLS
files, the injected resolver, the virtual clock, the retry schedule and the receiver's first eighteen steps, and
they are never SDK evidence. `node interop/webhook.mjs --self-test` runs the matrix against them and proves that
the tamper and signature scenarios fail when the relay or the fakes are told to deviate.

## 10. Known gaps

These are statements about the SDKs' public API, discovered while writing this contract. None of them invents API;
each one names the option that is missing.

1. **Go: no TLS root option on the delivery client.** `webhook.DeliveryConfig` carries `AllowedRanges`, `Resolver`
   and `Dialer` only; the trusted roots are fixed to the system pool by an unexported constructor parameter. The Go
   sender therefore relies on the process environment variable `SSL_CERT_FILE`, which `crypto/x509` reads on Unix.
   Missing option: a root `*x509.CertPool` (or a `*tls.Config`) on `DeliveryConfig`.
2. **TypeScript: no rebinding seam on the hardened transport.** `HardenedTransport.request` resolves once, calls
   `checkDelivery` without the `recheck` member, and its peer assertion lives inside `defaultDialer`, whose connect
   address is by construction the validated one; an injected `dialer` is trusted without a peer check. A delivery
   therefore cannot be made to answer `dns_rebinding` through the public options. Missing option: a second-answer or
   peer-assertion hook on `HardenedTransportOptions`. Consequence: `ssrf-dns-rebinding` is declared skipped for the
   TypeScript sender.
3. **Rust: no webhook-id seam.** `Sender::deliver` draws the id with `subscription::random_webhook_id` and
   `OutgoingMessage` has no `webhook_id` field and no entropy source, so the derived id of section 3 cannot be
   produced. The matrix pins the grammar, the prefix and the id's stability across retries instead.
4. **Go: the challenge POST is invisible to the caller.** `Sender.Attempt` and `Sender.Deliver` run the gate
   internally, so the executable cannot log the verification POST. The receiver's delivery line is the oracle for
   the handshake in every language.
5. **No live Server Card fetch in this version.** The matrix runs no MCP origin, so the receiver is handed the card
   document (`--card-file`) and only the SDK's Server Card decision runs; the fetch rules of R7.2 (same origin, no
   redirect, 65536-byte cap, cache TTL) are not exercised here. Each SDK's own live path is covered by its unit
   tests and the card vectors, through the public entry points `webhook.NewCardSource` and `CardSource.Refresh`
   (Go), `CardSource` with `HttpCardTransport` (Rust) and `ServerCardKeySource.keys` (TypeScript). A later version of
   this matrix can serve the card over its own throw-away HTTPS origin and drop `--card-file`; this one does not.
