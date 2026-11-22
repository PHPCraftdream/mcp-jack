# 05. Signed streams (`s1`)

Status: modern profile of the 0.2.0 release for MCP revision 2026-07-28. Normative unless marked *informative*. This profile adds new identifiers only and never changes the frozen `mcp-jack/v1` wire bytes of [01-authentication.md](01-authentication.md).

The key words MUST, MUST NOT, SHOULD, MAY are used as in RFC 2119.

Today [01-authentication.md](01-authentication.md) section 5 and [02-authorization.md](02-authorization.md) section 2 refuse event streams with the signed `501 streaming_unsupported`. This document defines the opt-in replacement for the modern profile.

## 1. Opt-in and profile

### 1.1 The `Jack-Accept` request header

A client opts in per request with the unsigned request header `Jack-Accept`:

```
Jack-Accept = OWS token *( OWS "," OWS token )
OWS         = *SP
SP          = %x20
token       = 1*( %x2D / %x30-39 / %x41-5A / %x61-7A )
```

- `OWS` is zero or more SP (0x20). HTAB is not admitted by this grammar.
- A `token` is one or more characters from `A-Z`, `a-z`, `0-9` and `-`, compared case-sensitively (registered tokens are lowercase, so `S1` is not `s1`).
- All `Jack-Accept` header lines of the request are combined into one list.
- The stream is enabled if and only if the token `s1` appears at least once in that list. Other tokens (future schemes) are ignored. A line this grammar does not admit contributes no token, so it cannot enable a stream.
- The header is unsigned and MUST NOT appear in any signing string.

A request without the token keeps the v1 behaviour: the wrapped handler's `text/event-stream` response is replaced by the signed `501 streaming_unsupported` ([02-authorization.md](02-authorization.md) section 2). Stripping the header is therefore a denial of service only, and never a downgrade of authenticated bytes.

### 1.2 Where streams may exist

- A server MUST NOT send an `s1` stream to a client that did not opt in (1.1).
- A server MUST NOT relay an unsigned or unverified `text/event-stream` body in any profile.
- Streams exist only in the modern profile. A legacy-profile server ignores `Jack-Accept` and answers `501`.

### 1.3 Binding

The request and the `501` refusal keep the exact v1 bytes (`mcp-jack/v1/request`, `mcp-jack/v1/response`). A stream is bound to exactly one authenticated request: the open header signature binds the stream to that request's `sig`.

### 1.4 Routing rule

A response is a signed stream if and only if its status is `200` and its `Content-Type` media type is `text/event-stream` (media type compared case-insensitively, parameters ignored). Every other response is verified as a v1 response by [01-authentication.md](01-authentication.md) section 5 — this is how a signed `501` or `429` refusal reaches the client.

## 2. Response shape and grammars

### 2.1 Success response

On success the response carries exactly:

- status `200`;
- `Content-Type: text/event-stream`;
- `X-Accel-Buffering: no` (SHOULD; ignored by the client, it is a reverse-proxy hint, *informative*);
- exactly one `Jack-Auth` header carrying the open authentication value below.

```
Jack-Auth: s1 kid=<kid>,ts=<ts>,sid=<sid>,sig=<sig>
```

### 2.2 Grammar of the open value

Identical rules to [01-authentication.md](01-authentication.md) section 3: a single scheme, one SP, parameters separated by a single `,` with no whitespace, each parameter `name=value`, names lowercase and case-sensitive, value alphabet `A-Za-z0-9_-`. The parameter set is exactly `kid`, `ts`, `sid`, `sig`, each once, in any order.

| Parameter | Size | Encoding |
|---|---|---|
| `kid` | 32 bytes, 43 chars | canonical unpadded base64url (01 section 2) |
| `sid` | 16 bytes, 22 chars | canonical unpadded base64url |
| `sig` | 64 bytes, 86 chars | canonical unpadded base64url |
| `ts` | at most 12 digits | canonical unsigned decimal: no sign, no leading zeros except `0` |

`base64url` is RFC 4648 section 5, unpadded and canonical, as defined in 01 section 2. Any deviation from this section is `stream_malformed_auth`.

### 2.3 Scheme precedence

The scheme is examined first, on the raw header bytes, before any parameter or character-encoding check:

| Raw scheme | Outcome |
|---|---|
| `s1` | the value continues to the parameter rules of 2.2 |
| `s` + digits, or `v` + digits, other than `s1` | `stream_unsupported_version` |
| anything else | `stream_malformed_auth` |

So `s2` and `v1` are both `stream_unsupported_version`, even when their parameters are malformed or carry bytes outside the value alphabet.

### 2.4 `sid`

`sid` is 16 bytes from a CSPRNG, base64url encoded, unique per stream instance. It MUST differ between two streams, even two streams for the same request. It names the stream in every frame signing string. It is not a session and carries no state.

### 2.5 Open signing string

Exactly six lines of UTF-8 joined with a single LF and no trailing LF:

```
mcp-jack/stream1/open
<status>
<request-sig>
<kid>
<ts>
<sid>
```

| Field | Value |
|---|---|
| `status` | decimal status code, `200` for an accepted stream, no leading zeros |
| `request-sig` | the `sig` parameter of the `Jack-Auth` v1 request header that opened the stream, not the whole header |
| `kid`, `ts`, `sid` | the open header values as sent |

`sig` = `base64url(Ed25519_sign(server_private_key, signing_string))`.

### 2.6 Frames

The body is a sequence of SSE events (WHATWG HTML, "server-sent events"), one JSON-RPC message per data-bearing event. A `message` frame is the byte sequence below (LF shown; the server MUST write LF only):

```
event: message
data: <JSON-RPC message>
jack: seq=<seq>,ts=<ts>,sig=<sig>
<blank line>
```

- The `event` field line MAY be omitted by a sender and then means the SSE default event type `message`; the Jack sender always writes it.
- The `jack` field line is an unknown SSE field for a generic parser and carries the authentication.
- The `data` field line MAY be repeated; the server writes one `data` line per LF-separated piece (2.10).

### 2.7 `jack` field grammar

The value is `<name>=<value>` pairs separated by a single `,` with no whitespace; names are lowercase and case-sensitive; the parameter set is exactly `seq`, `ts`, `sig`, each once, in any order; values use only `A-Za-z0-9_-`.

| Parameter | Value |
|---|---|
| `seq` | canonical unsigned decimal, no leading zeros except `0`, at most 15 digits, less than 2^53 |
| `ts` | as in 2.2 |
| `sig` | as in 2.2 |

Any violation is `stream_bad_frame`. Exactly one `jack` field line MUST be present per event; zero or two `jack` lines is `stream_bad_frame`.

### 2.8 `event` field

At most one `event` field per event, with the value exactly `message` or `jack-end`. Two `event` lines, or any other value, is `stream_bad_frame`.

### 2.9 Frame kind

The frame kind is derived from the data, not signed:

- the data value of a `message` frame MUST be non-empty;
- the data value of the `jack-end` frame MUST be empty (2.16).

A frame whose `event` value contradicts the emptiness of its data (`event: message` with empty data, or `event: jack-end` with non-empty data) is `stream_bad_frame`. This is why the kind is not part of the signing string: the kind is a function of signed bytes.

### 2.10 Data value

The values of the event's `data` field lines, joined with a single LF and no trailing LF, interpreted as UTF-8 (RFC 3629). For example `data: {"a":` followed by `data: 1}` gives `{"a":\n1}`.

Zero `data` lines give the empty value. Two or more consecutive empty `data` lines give one or more LFs and are valid only if the joined value matches the rule of 2.9. Invalid UTF-8 anywhere in a field value is `stream_bad_frame`.

A frame's data value MUST NOT contain a raw CR (0x0D): JSON requires CR and LF inside strings to be escaped, and a raw CR outside a string is insignificant whitespace. A server whose handler produced CRLF or CR normalises them to LF before splitting into `data` lines; a client reads any CR in the body as a line terminator (2.14).

A `data` value may contain LF (a multi-line JSON text or any other byte sequence); the MCP layer, not this layer, decides whether the joined value is valid JSON. The data value is not required to be a JSON-RPC message: this document constrains framing and authentication only.

### 2.11 `id` and `retry`

The `id` and `retry` fields MUST NOT appear on a frame. A server drops them from the handler's output; a client that receives one aborts with `stream_bad_frame`. They would change the SSE reconnect and last-event-id state that Jack does not sign, and the transport has no `Last-Event-ID` resumption.

### 2.12 Comments

A line whose first byte is `:` is a comment. It belongs to no event, is ignored wherever it appears (including between the field lines of one event), carries no data and is unsigned. A server uses them only as keep-alive lines such as `:` followed by LF. A comment MUST NOT be delivered to the MCP layer.

### 2.13 Unknown fields

Field names other than `event`, `data`, `id`, `retry` and `jack` are ignored per the SSE rule: they carry no data, are not signed, and MUST NOT be delivered to the MCP layer. A line with no `:` is a field with an empty value, so a bare `jack` line fails 2.7 (`stream_bad_frame`).

### 2.14 Line endings and BOM

- The server MUST emit LF.
- The client MUST accept `\r\n`, `\n` and a lone `\r` as line terminators.
- Terminators are not part of any field value and therefore never part of a signing string, so the same events verify identically under any accepted line ending.
- At most one U+FEFF byte order mark at the very start of the body is ignored and is not signed.

### 2.15 Frame signing string

Exactly six lines of UTF-8 joined with a single LF and no trailing LF:

```
mcp-jack/stream1/frame
<sid>
<seq>
<ts>
<prev>
<data-hash>
```

- `prev` is the open `sig` for `seq` 0 and the previous frame's `sig` for every later frame, so the frames form one hash chain rooted in the open header.
- `seq` starts at 0 and increases by exactly 1.
- `data-hash` = `base64url(SHA-256(UTF-8 bytes of the data value of 2.10))`. The empty value hashes as the SHA-256 of the empty byte string.
- `sid` and `kid` never change within one stream.

### 2.16 End frame

The last event of every complete stream is:

```
event: jack-end
data:
jack: seq=<n>,ts=<ts>,sig=<sig>
<blank line>
```

It has empty data (2.9), its own `seq` (one more than the previous frame), its own fresh `ts`, and its signature chains over the previous frame's `sig`. After it the server MUST close the body and MUST NOT write another byte. A stream without it is incomplete. A client that sees any further event after it aborts with `stream_out_of_order`; 2.9 keeps this from being forgeable, because the end frame cannot be turned into a message frame.

### 2.17 Data value size

`frameMaxBytes` bounds the byte length of the **data value** of one `message` frame (2.10) as UTF-8, not the bytes the event occupies on the wire. A `jack-end` frame has the empty data value, so its size is 0. A frame whose data value exceeds the cap is `stream_frame_too_large` (4.3 step 1).

### 2.18 Transport signal frame

A `message` frame whose data is exactly this JSON object is a Jack transport signal, not an MCP message:

```
{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"<code>","limit":<n>}}
```

- A `message` frame is a transport signal if and only if its data value is byte-for-byte that template with `<code>` replaced by one member of the signalled set and `<n>` by a canonical decimal integer: `0` or `[1-9][0-9]*`, value at most 9007199254740991. The signalled set is currently exactly `stream_frame_too_large` (4.6).
- Anything else is an ordinary `message` frame delivered to the MCP layer (2.6): a different `method`, any extra, missing or reordered member at any level, any extra whitespace, a non-string `code`, a `code` that is not a member of the signalled set, or a `limit` written as `1e3`, `1000.0`, `+1000`, `01000` or with whitespace.

The signal frame is short: with the minimum `frameMaxBytes` of 3.2 it always fits below the cap. Client handling of a signal is step 6 of 4.3.

## 3. Server rules (signer)

### 3.1 Key discipline

The server signs the open header and every frame with the key whose `kid` it puts in the open header; never another key. The strict Ed25519 rules of [01-authentication.md](01-authentication.md) sections 2 and 4 apply unchanged.

### 3.2 Frame size cap

- `frameMaxBytes`, default 1048576 (1 MiB), configurable; it MUST be at least 1024, so a transport signal frame (2.18) always fits below the cap.
- A handler message whose data value exceeds the cap is not forwarded. The server writes one signed `message` frame whose data is exactly the 2.18 signal with `code` = `stream_frame_too_large` and `limit` = the configured cap as canonical decimal, then writes the end frame, then closes.
- The signal frame is the LAST message of the stream: no MCP final response (6.3) is written before or after it, so a stream closed for this reason never completes its MCP request, and the client ends with `stream_frame_too_large` (4.3 step 6).
- The body cap of [01-authentication.md](01-authentication.md) section 3.1 still bounds a non-streaming response.
- The cap measures the data value of 2.17, so a legal 1 MiB handler message is accepted while one byte more is signalled.

### 3.3 Concurrency limit

`maxConcurrentStreams` per authenticated identity, configurable, default 4. A request that would exceed it is refused before any stream byte is written: HTTP `429` and the signed v1 JSON response ([01-authentication.md](01-authentication.md) section 5) whose body is exactly

```
{"jsonrpc":"2.0","id":<id>,"error":{"code":-32603,"message":"stream_limit_exceeded"}}
```

where `<id>` is the request's JSON-RPC id, as the same JSON lexeme as in the request. The request nonce is consumed, as for every post-auth refusal. A released stream (end frame written, handler returned, or client disconnect) frees its slot, and the slot MUST be released on every path, including errors.

### 3.4 Maximum duration

- `maxStreamDurationMs`, configurable, default 3600000 (1 h).
- When it is reached the server stops forwarding, writes the final JSON-RPC response of the request if it has not been written yet and it can still write (6.3), then writes the end frame with a `ts` below the opening key's cutoff (section 5), then closes.
- That is a complete Jack stream; whether the MCP request completed depends on whether the final response was written (6.3). The MCP client re-opens with its stored cursor per the MCP rules (*informative*: `subscriptions/listen`, `events/stream`).
- A server MUST NOT exceed the duration silently and MUST NOT write an unsigned byte.
- This close is not the 3.2 signal close: the final-response rule of 6.3 applies to it.

### 3.5 Heartbeats

- `heartbeatMs` is milliseconds; the client window `W` of 01 section 4 is seconds. The server MUST grant `heartbeatMs <= floor(W * 500)` where `W` is the server's own configured response-verification window (default 30 s), and MUST clamp a larger client suggestion rather than honour it. With the default `W` the grant is at most 15000 ms.
- The deployment contract makes the server's `W` equal to the client's `W`, exactly as the clock requirement of 01 section 6 makes their clocks agree; no negotiation is added.
- A heartbeat is an ordinary signed `message` frame (an MCP `notifications/events/heartbeat` on an events stream, or whatever the request's stream carries).
- The server MUST NOT rely on comment keep-alives for liveness state; a comment keeps the TCP connection alive only (*informative*).
- The client-side consequence is 4.5: the default idle timeout of 90000 ms is three times the MCP-recommended 30 s heartbeat and at least six times any legal grant.

### 3.6 Nonce

The request nonce is verified and, in the durable profile, committed before the first response byte is written. A stream never extends the nonce lifetime and never re-uses the nonce.

### 3.7 Cancellation

When the client closes the connection, or after the server writes the end frame, the server MUST cancel the handler's request context, so the MCP rule "closing the stream cancels the request" holds (*informative* source: the Streamable HTTP transport page). It MUST NOT write further frames after the end frame.

### 3.8 Limits on where a stream may be written

A server MUST NOT write an `s1` stream for a request whose body was not a request (a JSON-RPC notification gets `202`), and MUST NOT offer streams in the legacy profile (1.2).

Configured defaults:

| Setting | Default | Rule |
|---|---|---|
| `frameMaxBytes` | 1048576 | 3.2 |
| `maxConcurrentStreams` | 4 | 3.3 |
| `maxStreamDurationMs` | 3600000 | 3.4 |
| `heartbeatMs` | at most `floor(W * 500)` milliseconds | 3.5 |

## 4. Client verification

### 4.1 Routing

Per 1.4: status `200` with `text/event-stream` selects this path; every other response goes through [01-authentication.md](01-authentication.md) section 5. The open header is verified first; if it fails no frame is read and no message is delivered (`frames_verified` 0).

### 4.2 Open header

In this order, stopping at the first failure, with the code from the closed list in 4.6:

| # | Check | `code` |
|---|---|---|
| 1 | `Jack-Auth` absent | `stream_missing_auth` |
| 2 | header present more than once, or 2.2 grammar violated (including the `sid`, `kid`, `ts` and `sig` encodings) | `stream_malformed_auth` |
| 3 | scheme is not `s1` (2.3) | `stream_unsupported_version` |
| 4 | `kid` is neither the pinned server key nor a rotation-known key | `stream_unknown_server_key` |
| 5 | `abs(now - ts) > W` | `stream_out_of_window` |
| 6 | a successor activation `A` is known for `kid` and `ts >= A` (section 5) | `stream_after_cutoff` |
| 7 | signature does not verify over 2.5 | `stream_bad_signature` |

As in 01 section 5, the scheme is examined first: step 3 applies before the parameter rules of step 2.

### 4.3 Each frame

In this order, stopping at the first failure:

| # | Check | `code` |
|---|---|---|
| 1 | frame grammar 2.6-2.13, including the size of 2.17 against `frameMaxBytes` | `stream_bad_frame`, or `stream_frame_too_large` for size |
| 2 | `seq` equals the expected next value (0 for the first frame) | `stream_out_of_order` |
| 3 | `abs(now - ts) <= W` and `ts` not below the previous frame's `ts` (the end frame included) | `stream_stale_frame` |
| 4 | a successor activation `A` is known for `kid` and `ts >= A` | `stream_after_cutoff` |
| 5 | signature verifies over 2.15 with the chained `prev` | `stream_bad_signature` |
| 6 | the frame is a 2.18 transport signal | the signal's `code` after the frame is verified |

The signal frame counts in `frames_verified`. The client MUST NOT deliver it to the MCP layer and MUST NOT verify any later frame: the end frame that follows is neither required nor counted, so a signal-terminated stream never ends in `stream_truncated`. A frame that only looks like a signal is an ordinary message (2.18, step 6 does not apply). A signal-terminated stream carries no final response, so its MCP request never completes (9) and the vector field mcp_complete is false.

The client samples its clock per frame, so a stream may live far longer than `W` (*informative*). Silence is bounded by 4.5, not by the window.

### 4.4 Truncation

If the body ends before an end frame has been verified, the terminal code is `stream_truncated`. Nothing after the failing frame is delivered to the MCP layer, and every frame that already verified stays valid and delivered: the failure is per stream, not per body, so a `subscriptions/listen` caller keeps the messages it received.

An ended body is the only source of `stream_truncated`; a connection that is still open and silent is 4.5.

### 4.5 Idle timeout

A client MUST end the stream with `stream_idle` when no frame has been verified for `streamIdleMs` (milliseconds). The deadline runs from the moment the open header was verified and restarts at every verified frame, heartbeats and transport signals included, so a valid opener followed by silence longer than `streamIdleMs` ends with `stream_idle` and `frames_verified` 0. A silence exactly equal to `streamIdleMs` is still alive; one millisecond more is idle, and a frame that arrives after the deadline is not verified. `streamIdleMs` defaults to 90000 (three times the MCP-recommended 30 s heartbeat, and at least six times any legal `heartbeatMs` grant of 3.5); it is configurable. The Jack layer does not parse MCP, so an SDK that has seen a granted `heartbeatMs` SHOULD tighten `streamIdleMs` to three times that grant (7, informative). A closed body is 4.4. Comments and unknown fields reset nothing: only a verified frame restarts the deadline, and the check also covers the time from the last verified frame to the last byte the client received plus any measured trailing silence, so a stream that delivers a comment and then falls silent still ends with `stream_idle`. An SSE event is complete only at its terminating blank line (2.6): the arrival time used above is the arrival of the byte that completes that line, so a frame whose final newline arrives late is late.

### 4.6 Codes

These codes are client-side only and never appear in HTTP, like the codes of 01 section 5. The closed list is exactly these thirteen:

- `stream_missing_auth`
- `stream_malformed_auth`
- `stream_unsupported_version`
- `stream_unknown_server_key`
- `stream_out_of_window`
- `stream_bad_signature`
- `stream_bad_frame`
- `stream_out_of_order`
- `stream_stale_frame`
- `stream_truncated`
- `stream_idle`
- `stream_frame_too_large`
- `stream_after_cutoff`

An implementation MUST NOT invent further codes for the rules of this document. The codes a server may signal in a 2.18 frame are a subset of this list, currently only `stream_frame_too_large`.

### 4.7 Verify before parsing

The client MUST verify a frame before parsing its JSON: the data of a frame reaches the MCP layer only after step 5 of 4.3.

## 5. Server-key rotation interplay

### 5.1 Server side

A stream is signed by the key that opened it; frames carry no `kid`. The server MUST end the stream with the end frame before the opening key's cutoff `A_next`, the successor activation of the rotation vocabulary of [server-key-rotation.md](candidate/server-key-rotation.md) section 4, and MUST NOT sign any frame with `ts >= A_next`. At equality the old key is already ineligible.

### 5.2 Client side

A client that knows a successor activation for the stream's `kid` MUST reject an open header or a frame whose `ts` is at or after it with `stream_after_cutoff` (4.2 step 6, 4.3 step 4), even though the signature verifies.

The end frame is a frame for this rule as well: an end frame whose ts is at or after the cutoff is rejected with `stream_after_cutoff`. A stream that reaches the cutoff therefore has no valid end frame and cannot complete, and `stream_after_cutoff` takes precedence over `stream_truncated`.

### 5.3 No continuation

A client never re-signs, never switches `kid` mid-stream, and never continues after `stream_after_cutoff`. Re-opening the request with the stored cursor is the MCP client's job (*informative*: the MCP specification already requires it after any break).

## 6. SDK transport mapping

### 6.1 Re-emission to an official MCP client

An SDK that wraps an official MCP client MUST re-emit only verified data, as plain SSE, one event per verified `message` frame, in order, with LF line endings and exactly these bytes:

```
event: message
data: <first LF-separated piece>
data: <second LF-separated piece, if any>
<blank line>
```

One `data: ` line per LF-separated piece of the data value, an empty piece written as `data:` alone, then one blank line. The re-emitted stream carries no `jack:` field, no `jack-end` event, no comment line the SDK did not verify, and never a 2.18 transport signal.

### 6.2 stdio consumer

A stdio consumer (the Go bridge) MUST write each verified `message` frame as exactly one stdout line: the data value followed by one LF. If a verified data value contains a raw CR (0x0D) or a raw LF (0x0A), the consumer MUST abort the stream with `stream_bad_frame`, MUST NOT write a partial line, and MUST keep the frames already written valid. JSON text cannot carry a raw newline inside a token, and a whitespace newline would break the line framing.

### 6.3 Server-initiated close

This section covers every server-initiated close except the 3.2 oversize signal, which is the last message of its stream and never carries a final response (3.2).

When the server ends a stream it did not finish — the duration of 3.4, shutdown or a policy decision — and the stream carries the response of a request, the server SHOULD write that request's final JSON-RPC response as the last `message` frame before the end frame, whenever it can still write. For `events/stream` that response is exactly

```
{"jsonrpc":"2.0","id":<id>,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":<id>}}}
```

with `<id>` the request's JSON-RPC id in the same JSON lexeme as the request. A stream completes its MCP request only when the last message before the end frame is a JSON-RPC response object: `"jsonrpc":"2.0"`, an `id` equal to the id of the request that opened the stream, exactly one of a `result` or an `error` member, and no `method` member. A stream whose body ended without a verified `jack-end` is `stream_truncated` (4.4) and is never MCP-complete. Anything else — a notification last, a response for another id, a missing `jsonrpc`, or both `result` and `error` — leaves the request incomplete and the MCP client re-issues it. The server MUST NOT write a final response after the end frame.

## 7. MCP mapping (*informative*)

**Request-scoped stream.** A single request may answer with an SSE stream: the server sends `notifications/progress` and `notifications/message` before the final JSON-RPC response, and the final response terminates the stream.

**`subscriptions/listen`.** The request opens a long-lived stream of the change notifications the client opted into with its `notifications` filter. The server sends `notifications/subscriptions/acknowledged` first and delivers nothing before it.

**`events/stream`.** The request opens one long-lived stream per subscription. The server sends `notifications/events/active` first, then `notifications/events/event`, `notifications/events/heartbeat` and `notifications/events/error` as they occur, and `notifications/events/terminated` when the subscription ends.

**Cancellation.** On HTTP the client cancels by closing the stream; `notifications/cancelled` is the stdio mechanism and is not used on a signed stream.

**`notifications/events/list_changed`.** This notification is delivered on a `subscriptions/listen` stream, and only when the client opted in.

**Body content.** The JSON-RPC message bytes of a frame are exactly the handler's bytes, one object per event; Jack adds nothing to the body.

## 8. Security considerations (*informative*)

- **Truncation.** An attacker who drops the end frame yields `stream_truncated`, never a silent success.
- **Reordering.** Reordering is blocked by the hash chain plus `seq`.
- **Replay into another stream.** Replaying frames into another stream is blocked by `sid` in every frame signing string together with the fresh `sid` per instance.
- **Cross-request splice.** A splice from another request is blocked by `request-sig` in the open signing string.
- **Withholding.** Withholding frames is bounded twice: a withheld frame is stale once it is older than `W` (4.3 step 3), and a peer that stays silent trips `stream_idle` (4.5) even while the connection stays open.
- **Long streams.** A long-lived stream is not a long-lived signature, because every frame is freshly timestamped within `W`.
- **Reverse proxies.** Buffering needs `X-Accel-Buffering: no` and LF-terminated blank lines to flush events.
- **Unsigned bytes.** Keep-alive comments and unknown fields are unsigned and therefore carry nothing.
- **Clock budget.** The client window must be at least the network delay budget of the deployment.
- **Compromised key.** A compromised server key forges everything; this document adds no new claim.

## 9. Conformance

The normative vectors are generated by `spec/tools/modern/streams/index.mjs` into:

- `spec/fixtures/modern/stream-vectors.json` — client verification vectors: the raw response bytes as base64url chunks plus the expected terminal state.
- `spec/fixtures/modern/stream-build-vectors.json` — server-signing known-answer vectors: the complete stream bytes for the opener and the frames.

The generated case table lists which vector covers which rule. A vector whose intended outcome disagrees with the independent reference implementation fails generation loudly. Every numbered rule of sections 1-6 is either mapped to at least one vector in the generated case table or listed in the exemption table below; the generator and its self-checks fail when a rule is neither.

Fields of the client verification file:

| Field | Content |
|---|---|
| `id` | vector identifier |
| `description` | what the vector covers |
| `state` | `now`, `window_seconds`, `pinned_server_kid`, `pinned_server_public_key`, `request_sig`, `request_id` (the JSON-RPC id of the request that opened the stream, needed for 6.3), `successor_activation` (number or `null`), `frame_max_bytes`, optional `frame_nows` (per-frame clock samples; the last value repeats), `stream_idle_ms` (milliseconds, default 90000, 4.5) |
| `response` | `status`, `headers` as name/value pairs, `stream_b64u` as the ordered list of body chunks |
| `silent_after_ms` | optional integer milliseconds: the connection stays open and silent for that long after the last body byte, with no end frame required; `silent_after_ms` is compared together with the time from the last verified frame to the last byte the client received: the terminal is `stream_idle` when that sum exceeds `state.stream_idle_ms`, and otherwise the vector models a live observation the harness stopped reading and its terminal is `{"state":"ok"}`. A silence exactly at the threshold is still alive, so `ok` here implies no MCP-level completion and `mcp_complete` stays false. |
| `arrival_ms` | optional array parallel to `response.stream_b64u`: milliseconds after the opener was verified at which each chunk arrives; omitted means all chunks arrive at once; the idle rule of 4.5 is evaluated against these times |
| `consumer` | optional, `mcp` by default or `stdio` for 6.2 |
| `data_fill` | optional `{"byte":"x","count":N}`; every element of `response.stream_b64u` equal to the literal marker `@data_fill@` expands to N copies of the ASCII byte before parsing, which keeps a 1 MiB frame boundary vector small |
| `expect` | `messages` (the data values delivered to the MCP layer, in order; an entry may be either the delivered string or a `data_fill` marker object `{"data_fill":{"byte":"x","count":N}}` that expands to the same repeated-byte value) and `terminal`, either `{"state":"ok"}` or `{"state":"error","code":...,"frames_verified":<n>}`; `frames_verified` counts every event that passed verification, including the end frame; optional `mcp_complete` (boolean, 6.3): true only when terminal is `{"state":"ok"}`, the vector carries no `silent_after_ms` (a live observation never completes), and the last delivered message is a JSON-RPC response object for `state.request_id` |

Fields of the build file:

| Field | Content |
|---|---|
| `input` | `request_sig`, `kid`, `status`, `sid`, `open_ts` (the server signing time of the open header, whole seconds), `frames` as `{seq,ts,data}` |
| `expect` | `jack_auth`, `open_signing_string`, `frames` as `{seq,ts,prev,data_hash,signing_string,sig}`, `stream_b64u` as the whole body |

The generator's independent reference implementation lives in `spec/tools/modern/streams/reference.mjs` and its `node:test` self-checks in `spec/tools/modern/streams/streams.test.mjs`; the client file's `state.frame_nows[i]` is the clock sample used to verify frame `i`, and the last value repeats for later frames.

Every vector whose `silent_after_ms` is absent models a body that ended at its last byte (4.4); a vector with the field models a connection that stayed open (4.5).

Sources (*informative*):

- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions
- https://modelcontextprotocol.io/extensions/events/overview
- https://github.com/modelcontextprotocol/ext-events (`specification/beta/events/events.mdx`)
- https://modelcontextprotocol.io/seps/3415-events-extension
- https://html.spec.whatwg.org/multipage/server-sent-events.html

## Exemptions

The rules below cannot be tested at the stream level; each names the SDK-level test that must carry it (work item M2 of the design).

| rule | why a stream vector cannot test it | SDK-level test that must carry it |
|---|---|---|
| `1.1` | the opt-in header is request-side; no response byte depends on it | server middleware: `Jack-Accept` token parsing and the 501 fallback |
| `1.2` | requires a server that misbehaves (an unsolicited or unsigned stream) | server middleware: refusal path |
| `1.4` | a non-`s1` response is not a stream vector; it is a client dispatcher decision | client dispatcher: v1 response path for 429 and for 200 with a JSON media type |
| `3.1` | server key choice is internal; a client only sees the result | server signer: the open and every frame use one key |
| `3.3` | the concurrency limit is a server-side admission decision | server middleware: 429 `stream_limit_exceeded` before any byte |
| `3.4` | the duration is a server timer | server signer: close shape and final response before the end frame |
| `3.5` | the grant is a server configuration choice | server signer: `heartbeatMs <= floor(W * 500)` and clamping |
| `3.6` | nonce commitment happens before the response | server middleware: durable nonce before the first byte |
| `3.7` | cancellation is observed by the handler, not on the wire | server middleware: context cancellation on client disconnect |
| `3.8` | which requests may open a stream is a request-side decision | server middleware: notification POST and legacy profile |
| `4.1` | the routing decision sees a response that is not a stream | client dispatcher (same test as `1.4`) |
| `5.1` | the server decides the cutoff and the close | server signer: no frame at or after `A_next`, close before it |
| `6.1` | re-emission is a byte transformation of already-verified data | SDK re-emission unit test against the 6.1 bytes |
