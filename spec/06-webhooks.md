# 06. Webhooks

Status: draft v0.2 for the 0.2.0 release line, 2026-11-22. Normative unless marked *informative*.

The key words MUST, MUST NOT, SHOULD, MAY are used as in RFC 2119.

Sources: MCP revision 2026-07-28 [changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog); [Events extension](https://github.com/modelcontextprotocol/ext-events) at c77b84395eff0ae32f53b0516c2214fe276ed050 (specification/beta/events/events.mdx); [SEP-3415](https://modelcontextprotocol.io/seps/3415-events-extension); [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md) at 3d65b1824b6697f05a5a4584e7062bd23512fc8e; [Server Card extension](https://github.com/modelcontextprotocol/ext-server-card) at 28db12c9b4a379489d46e49bf1bd4a991f05c9b7; [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/); [IANA IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry/).

This document is the webhook-delivery specification of the mcp-jack modern profile for MCP revision 2026-07-28 and the official Events extension. It adds a new profile only: it introduces new identifiers and a new server-to-client channel and changes no `mcp-jack/v1` byte. [01-authentication.md](01-authentication.md), [02-authorization.md](02-authorization.md) and [03-user-management.md](03-user-management.md) stay frozen as accepted at commit `c8ea1a0b37e68ab6dcdfb19fd0e427668cf1f343`. No SDK implements this profile yet. (informative)

## 1. Model and roles

Three roles take part. The **sender** is the wrapped MCP server acting through Jack's webhook sender; it owns subscriptions and events and issues every outbound POST. The **receiver** is the client-side endpoint that accepts a delivery, in Jack a `WebhookReceiver` or the `jack events receive` command. A third shape, a forward proxy or relay that receives deliveries and serves events to clients by poll or push, is a valid receiver but is informative and adds no rule here.

| role | party | wire position |
|---|---|---|
| sender | the wrapped MCP server through Jack's webhook sender | issues every POST, holds subscriptions and retry state |
| receiver | the client-side endpoint, `WebhookReceiver` or `jack events receive` | answers every POST, holds routing and dedup state |
| forward proxy | an optional relay in front of the consumer | a receiver that re-publishes to clients by poll or push |

One outbound HTTPS `POST` carries one message to one subscription. The channel does not use `Jack-Auth`: the `mcp-jack/v1` request and response signatures do not apply to it, and a receiver never asks for one. A delivery is authenticated by the Standard Webhooks signatures of section 2 and, when configured, by the Jack signature of section 4.

- `R1.1` Delivery request profile. Method `POST`; scheme `https` only. `Content-Type: application/json`. Exactly these headers are present: `webhook-id`, `webhook-timestamp`, `webhook-signature`, `X-MCP-Subscription-Id`, and `Jack-Webhook-Auth` when a `w1` key is configured (section 4). Header names are case-insensitive on receipt; a sender emits lowercase `webhook-*` and the exact mixed case `X-MCP-Subscription-Id` and `Jack-Webhook-Auth`. No other header is required, and `User-Agent` is unspecified.

| header | emitted spelling | required |
|---|---|---|
| webhook id | `webhook-id` | always |
| attempt timestamp | `webhook-timestamp` | always |
| signatures | `webhook-signature` | always |
| subscription | `X-MCP-Subscription-Id` | always |
| Jack signature | `Jack-Webhook-Auth` | when a `w1` key is configured |

A complete delivery, with `<b64>`, `<kid>` and `<sig>` standing for the encoded values:

```
POST /hooks/alice HTTP/1.1
Host: hooks.example.test
Content-Type: application/json
webhook-id: msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f
webhook-timestamp: 1795338000
webhook-signature: v1,<b64> v1a,<b64> v2a,<b64>
X-MCP-Subscription-Id: sub_a3f1c8e2b0d49f7e
Jack-Webhook-Auth: w1 kid=<kid>,sig=<sig>

{"eventId":"evt_789","name":"incident.created","timestamp":"2026-11-22T09:00:00Z","data":{"incidentId":"INC-1234","severity":"P1"},"cursor":"cursor_xyz"}
```

- `R1.2` Body size. The raw body MUST be at most 262144 bytes (256 KiB). A receiver MUST answer `413` with `body_too_large`, before reading the body, when the body is larger or the declared `Content-Length` is larger. A sender MUST treat `413` as final for that message.

- `R1.3` Body types. A JSON object with a top-level `type` member is a **control envelope**; the only types are `gap`, `terminated` and `verification`, and any other value is `unknown_envelope_type`. A JSON object without `type` is an `EventOccurrence` and MUST carry `eventId`, `name`, `timestamp` and `data`, and MAY carry `cursor` as a string or `null`. A body that is not a JSON object is `malformed_body`. Examples, in the order event occurrence, `gap`, `terminated`, `verification`:

```
{"eventId":"evt_789","name":"incident.created","timestamp":"2026-11-22T09:00:00Z","data":{"incidentId":"INC-1234","severity":"P1"},"cursor":"cursor_xyz"}
{"type":"gap","cursor":"cursor_7f3a"}
{"type":"terminated","error":{"code":-32024,"message":"Forbidden","data":{"reason":"Access revoked"}}}
{"type":"verification","challenge":"<nonce>"}
```

`<nonce>` stands for the 22-character value of section 5's nonce rule. The first object is an `EventOccurrence`; the other three are control envelopes.

- `R1.4` `webhook-id` grammar: `^[A-Za-z0-9_-]{8,128}$`, and the value never contains `.` or whitespace. A sender emits `msg_` followed by 32 characters of `[A-Za-z0-9]` for an event, and `msg_<type>_` followed by 32 characters of `[A-Za-z0-9]` for a control envelope, `<type>` being one of the three types. The value carries at least 120 bits of entropy, identifies one message on one subscription, is reused unchanged across retries of that message, is unique per (message, subscription), and MUST NOT be derived from `eventId`.

| shape | example prefix | body |
|---|---|---|
| event message | `msg_` | 32 characters of `[A-Za-z0-9]` |
| `gap` envelope | `msg_gap_` | 32 characters of `[A-Za-z0-9]` |
| `terminated` envelope | `msg_terminated_` | 32 characters of `[A-Za-z0-9]` |
| `verification` envelope | `msg_verification_` | 32 characters of `[A-Za-z0-9]` |

- `R1.5` `webhook-timestamp` grammar: `^(0|[1-9][0-9]{0,11})$` — Unix time in whole seconds, decimal, no sign, no leading zeros (`0` alone is allowed), at most 12 digits. It is regenerated on every attempt, together with the signature, so that a retry is never rejected by a freshness window.

- `R1.6` Sender timeouts. Connect 10 s; response 10 s after the request is written; one attempt never exceeds 20 s. A timeout is the category `timeout`.

| phase | cap |
|---|---|
| connect | 10 s |
| response, after the request is written | 10 s |
| one whole attempt | 20 s |

- `R1.7` Status classification by the sender. `2xx` is the only acceptance. Every outcome maps to exactly one row, and `final for that webhook-id` means the sender abandons that one message on that subscription and records `lastError`:

| status or failure | sender outcome | finality | category |
|---|---|---|---|
| `2xx` | accepted and done | final for that webhook-id | none |
| `3xx` | refused, never followed | final for that webhook-id | `http_4xx` |
| `410` | final failure for that delivery only | final for that webhook-id | `http_4xx` |
| `413` | the body was rejected | final for that webhook-id | `http_4xx` |
| `425` | retryable | retry | `http_4xx` |
| `503` | retryable | retry | `http_5xx` |
| `429` | retryable and throttled | retry | `http_4xx` |
| `502` | retryable and throttled | retry | `http_5xx` |
| `504` | retryable and throttled | retry | `http_5xx` |
| any other `4xx` | failure `http_4xx` | final for that webhook-id | `http_4xx` |
| any other `5xx` | failure `http_5xx` | retry | `http_5xx` |
| transport failure (DNS, connect, TLS) | retryable with the matching category | retry | `connection_refused`, `tls_error` or `timeout` |

`410` is a final failure for that delivery only, and `413` likewise: the sender records `lastError` `http_4xx`, does not retry that `webhook-id`, and does not change the subscription, its `deliveryStatus` or its routing. No single delivery outcome removes a subscription. (informative: the upstream Standard Webhooks text tells a sender to disable its endpoint on `410`; MCP 2026-07-28 requires the opposite, a non-retryable failure for that delivery with the subscription unaffected, so that advice does not apply to this profile)

- `R1.8` Retry schedule, as an exact function: `attempt(k) = t0 + [0, 30, 270, 870][k-1]` seconds for `k = 1..4`. That is four attempts with delays 0, 30, 240 and 600 s, no jitter; the last attempt is at `t0 + 870 s` and never later than `t0 + 900 s`. A `Retry-After` header on a retryable response postpones the next attempt to `max(scheduled, response_time + retry_after)` but never past `t0 + 900`; `Retry-After` in HTTP-date form is ignored. Time during which delivery is suspended does not consume the schedule. After attempt 4 the message is abandoned for the receiver's watermark. A sender MUST NOT retry a `410` or `413` message.

| attempt | delay after the previous attempt | time since `t0` |
|---|---|---|
| 1 | none, the first attempt | `t0 + 0 s` |
| 2 | 30 s | `t0 + 30 s` |
| 3 | 240 s | `t0 + 270 s` |
| 4 | 600 s | `t0 + 870 s` |

- `R1.9` `lastError` is a closed list of exactly six categories: `connection_refused`, `timeout`, `tls_error`, `http_4xx`, `http_5xx`, `challenge_failed`. Jack's internal outcomes without an official category map as follows: `blocked_address` and `dns_rebinding` map to `connection_refused`; `redirect_refused` maps to `http_4xx`. A delivery refused by section 6 before any request is sent is final for that message and records `connection_refused` (blocked address, rebinding) or `http_4xx` (refused redirect); the subscription and its routing stay as they were. `lastError` never contains raw response bodies, headers or status lines.

- `R1.10` Acknowledgement and durable enqueue. A receiver MUST NOT return `2xx` before the message is durably enqueued or persisted, and a `2xx` is returned only after a successful enqueue. When its durable enqueue fails the receiver MUST answer `503` with code `enqueue_failed` and MUST NOT record the `webhook-id`, so that the sender's retry of the same message is processed exactly once. A `2xx` means the sender need not retry. Delivery is at least once between sender and receiver.

## 2. Standard Webhooks signatures

MCP webhook delivery is a profile of Standard Webhooks. Jack adds only the `w1` header of section 4 and the receiver response profile of section 3.

- `R2.1` Secret value. The secret is supplied by the client in `events/subscribe` `delivery.secret`, is never generated by the server, and is one per subscription. It is the literal prefix `whsec_` followed by RFC 4648 section 4 standard base64 (`A-Za-z0-9+/` with `=`, total length a multiple of 4, canonical: re-encoding the decoded bytes reproduces the remainder exactly), decoding to 24-64 bytes inclusive. A value is rejected with `invalid_secret` when the prefix is missing or different (`WHSEC_`, `whsk_`), when it contains base64url characters `-` or `_`, when padding is missing or extra, when trailing bits are non-zero, when the decoded length is 23 or 65, or when it contains whitespace or any character outside the alphabet. A secret MUST be unique per subscription: one secret for exactly one subscription, a reuse the receiver cannot detect.

| value shape | result |
|---|---|
| `whsec_` then canonical standard base64 of 24-64 bytes | accepted |
| `WHSEC_...`, `whsk_...`, no prefix | `invalid_secret` |
| any `-` or `_` in the base64 part | `invalid_secret` |
| length not a multiple of 4, or padding misplaced | `invalid_secret` |
| non-zero unused trailing bits | `invalid_secret` |
| decoded length 23 or 65 | `invalid_secret` |

- `R2.2` `v1` signature. `v1,` followed by canonical standard base64 of `HMAC-SHA256(key, content)`, where `key` is the decoded secret bytes and `content` is the UTF-8 bytes of `webhook-id + "." + webhook-timestamp + "." + body`, `body` being the raw request body bytes. A 32-byte MAC therefore always renders as 44 characters ending `=`. Comparison MUST be constant time over the decoded 32 bytes.

| component | exact value |
|---|---|
| `webhook-id` | the header value as sent, ASCII |
| separator | one `.` (0x2E) |
| `webhook-timestamp` | the header value as sent, ASCII digits |
| separator | one `.` (0x2E) |
| `body` | the raw request body bytes as received |

- `R2.3` The content covers the raw body exactly as sent: no parsing, no re-serialization, no whitespace change, no Unicode normalization. A receiver MUST NOT re-serialize the parsed JSON before or during verification; an implementation that does fails every delivery whose bytes it changes.

- `R2.4` `webhook-signature` grammar. One or more entries separated by exactly one SP (U+0020); each entry is `<scheme>,<value>` with no whitespace anywhere; `<scheme>` matches `[A-Za-z0-9]+` and is case-sensitive; `<value>` is canonical standard base64. No leading or trailing space, no empty entry, no comma inside the value. A header repeated on the wire is `duplicate_webhook_header`. Unknown schemes are preserved for the scheme check of section 3 and are never dropped silently by the parser.

- `R2.5` `v1a` is deprecated upstream in favour of `v2a`; Jack supports it. Value: `v1a,` followed by canonical standard base64 of `Ed25519_sign(webhook_key, utf8(webhook-id + "." + webhook-timestamp + "." + body))`, over the raw content, with no hash and no endpoint id, exactly as `v1a` was originally defined.

- `R2.6` `v2a`. Value: `v2a,` followed by canonical standard base64 of `Ed25519_sign(webhook_key, SHA-256(utf8(endpoint_id + "." + webhook-id + "." + webhook-timestamp + "." + body)))`, where `endpoint_id` is the subscription id defined in section 8, the ASCII value carried in `X-MCP-Subscription-Id`, which contains no `.`. Jack chooses the subscription id as the endpoint id because it is stable, not user controlled and already on the wire, so the receiver needs no out-of-band per-endpoint string beyond the subscription id it already routes on. (informative: that choice is a Jack decision, not a requirement of the upstream text)

Three schemes therefore share a shape but not a content:

| scheme | signed content | key | status in this profile |
|---|---|---|---|
| `v1` | `webhook-id` `.` `webhook-timestamp` `.` body | decoded secret bytes, HMAC-SHA256 | required |
| `v1a` | the same content, raw | webhook signing key, Ed25519 | supported, deprecated upstream |
| `v2a` | subscription id `.` `webhook-id` `.` `webhook-timestamp` `.` body, SHA-256 first | webhook signing key, Ed25519 | supported, preferred upstream |

- `R2.7` Multi-signature acceptance. One or more signatures may be present for each scheme, and the receiver accepts a scheme if any of its entries verifies. `v1` requires at least one entry that verifies with a registered secret for the subscription. `v1a` and `v2a` are advisory: an endpoint that does not enforce server identity ignores them entirely, still applying the grammar and decoding checks of section 3 but never failing a delivery because of them; an endpoint that enforces server identity requires at least one `v1a` or `v2a` entry that verifies with an accepted Server Card key (section 7), trying every accepted key.

| scheme | identity not enforced | identity enforced |
|---|---|---|
| `v1` | at least one entry must verify | at least one entry must verify |
| `v1a` | ignored after the grammar and decoding checks | an accepted key must verify some entry |
| `v2a` | ignored after the grammar and decoding checks | an accepted key must verify some entry |

- `R2.8` Sender emission set and order. Entries are space-delimited, current-first: all `v1,` entries (current secret, then the previous secret while the rotation grace of section 8 is open), then for the current signing key `v1a,` then `v2a,`, then for the previous signing key while rotation publishes both `v1a,` then `v2a,`. The three shapes, as exact header values, with `<b64>` standing for the encoded value named in each line:

```
v1,<b64>
v1,<b64> v1a,<b64> v2a,<b64>
v1,<new b64> v1,<old b64> v1a,<new b64> v2a,<new b64> v1a,<old b64> v2a,<old b64>
```

A sender MUST NOT emit an empty entry and MUST NOT reorder these groups.

## 3. Receiver verification

Verify before parse. Until step 17 below, a receiver reads only the raw header bytes, the four or more header values and the raw body; nothing is parsed, dispatched or logged as trusted before then.

| input | read at | used for |
|---|---|---|
| header names | steps 1 and 2 | presence and duplication |
| `webhook-id` value | step 3 | grammar and later dedup |
| `webhook-timestamp` value | steps 4 and 13 | grammar and freshness |
| `X-MCP-Subscription-Id` value | steps 5, 7 and 8 | grammar, secret selection, routing |
| declared `Content-Length` | step 6 | size refusal before reading |
| raw body bytes | steps 6, 12, 14 and 15 | size, HMAC, asymmetric and Jack signatures |
| parsed body | step 17 | field validation and dispatch |

Error responses carry a JSON object with exactly one `error` member, itself carrying `code` and `message`, with `Content-Type: application/json`, as the example at the end of this section shows, and MUST NOT reveal more than the code, so an attacker-chosen URL cannot read a verification oracle out of Jack.

A receiver MUST perform these steps in order and stop at the first failure.

| step | check | HTTP | `code` | rule |
|---|---|---|---|---|
| 1 | any of the four required headers absent | 400 | `missing_webhook_header` | `R3.1` |
| 2 | any of them present more than once | 400 | `duplicate_webhook_header` | `R3.2` |
| 3 | `webhook-id` grammar | 400 | `malformed_webhook_id` | `R3.3` |
| 4 | `webhook-timestamp` grammar | 400 | `malformed_webhook_timestamp` | `R3.4` |
| 5 | `X-MCP-Subscription-Id` grammar `^sub_[0-9a-f]{16}$` | 400 | `malformed_subscription_id` | `R3.5` |
| 6 | body size and declared `Content-Length` | 413 | `body_too_large` | `R3.6` |
| 7 | secret selection for the subscription id | 401 | `unknown_subscription` | `R3.7` |
| 8 | routing of the subscription id | 503 | `subscription_not_routed` | `R3.8` |
| 9 | `webhook-signature` grammar | 400 | `malformed_signature_header` | `R3.10` |
| 10 | scheme set | 400 | `unsupported_signature_scheme` | `R3.11` |
| 11 | value decoding lengths | 400 | `malformed_signature` | `R3.12` |
| 12 | `v1` HMAC over the raw body with the selected secret or secrets | 401 | `bad_signature` | `R3.13` |
| 13 | freshness on the receiver clock, after the HMAC | 401 | `stale_timestamp`, `future_timestamp` | `R3.9` |
| 14 | asymmetric verification when server identity is enforced | 401, 503 | `bad_server_signature`, `no_server_keys` | `R3.14` |
| 15 | `w1` verification when configured | 401, 400 | the section 4 codes | `R3.15` |
| 16 | deduplication by `webhook-id` | 200 | none, answers `duplicate` | `R3.16` |
| 17 | parse, field validation and dispatch | 400 | `malformed_body`, `unknown_envelope_type` | `R3.18` |
| 18 | terminated routing, enqueue and success bodies | 410, 503, 200 | `subscription_terminated`, `enqueue_failed`, none | `R3.17` |

Notes on the steps that need more than a cell.

Step 7, secret selection: a registered secret for the subscription id, or, for a body whose `type` would be `verification` and only then, one of the pending entries of section 5, each a `(secret, callback url)` pair; candidate selection additionally requires that the id grammar is valid. No secret at all is `401 unknown_subscription`. Selection happens before parsing, so the discriminator is "the header id is not routed and at least one pending entry exists": a pending-secret verification attempt is authorised by the HMAC at step 12, and if that HMAC fails the answer is `bad_signature`, never `unknown_subscription`. This is the only ambiguity-free reading and it is the required one.

Step 8, routing: a non-`verification` body whose subscription id the receiver has not been told to route is `503 subscription_not_routed`, which is retryable. A verification body is exempt because it is answered in place. Step 7 already established the case: a pending secret means a verification candidate, a routed secret makes the check vacuous. If step 12 succeeds on the pending-secret path and step 17 finds a body that is not a `verification` envelope, the answer is `503 subscription_not_routed` and never a `2xx`. (informative: replacing the success keeps the order table exact without parsing before authentication)

Step 12, `v1`: the entries are verified as `R2.2` states, as a constant-time comparison over the decoded 32 bytes of `HMAC-SHA256(secret, webhook-id "." webhook-timestamp "." body)`, with every secret selected at step 7. A receiver MUST verify the HMAC before the freshness window of step 13, so a request that is both stale and badly signed answers `401 bad_signature`; `stale_timestamp` and `future_timestamp` are only ever answered for a message whose HMAC already verified.

Step 13, freshness: `now - webhook-timestamp > 300` is `401 stale_timestamp`; `webhook-timestamp - now > 300` is `401 future_timestamp`. The window is 300 s, symmetric, on the receiver clock. `R3.9` fixes the precedence normatively: a receiver MUST evaluate the HMAC of step 12 before this window, so a message that fails both answers `bad_signature` and never a timestamp code.

Step 14: a mismatch is `401 bad_server_signature`. Enforcement switched on with a card that yields no accepted key is `503 no_server_keys`.

Step 15, `w1`: the header grammar and window of section 4, then the key boundary, then the signature. A `kid` equal to the configured `mcp_server_kid`, or a key whose raw 32-byte public key equals the configured MCP server key, is never accepted: the answer is `401 webhook_key_is_server_key`, checked after header parsing and before the key lookup of section 7. On the pending-secret path of section 5 the signature is verified with the pending entry's callback URL and the subscription id from `X-MCP-Subscription-Id`, and a pending entry without a callback URL when `w1` is configured is `bad_jack_signature`.

Step 16, deduplication: a `webhook-id` already answered with a `2xx` is answered `200 {"status":"duplicate"}` with no forwarding and no state change. The id is recorded only at the moment a `2xx` is returned, so a failed verification or a `503` never poisons it. Accepted ids are remembered for at least 1200 s.

Steps 17 and 18, the post-dedup sequence, in this exact order: parse and validate the body, which answers `400 malformed_body` for a body that is not a JSON object or for any envelope field that fails validation and `400 unknown_envelope_type` for a `type` outside the three types → a subscription id the receiver has marked terminated answers `410 subscription_terminated` with nothing recorded and nothing delivered → a failed durable enqueue answers `503 enqueue_failed` with nothing recorded, so the sender's retry is therefore processed exactly once, as `R1.10` requires → dispatch: a `verification` envelope is echoed and never forwarded, a `terminated` envelope is forwarded and marks the subscription id terminated and the receiver stops routing it, so every later delivery for that id is answered `410` with code `subscription_terminated`, never a `2xx` and never a retry, `gap` envelope bodies and event occurrences are forwarded unchanged, and an event or a forwarded envelope is acknowledged with `200 {"status":"accepted"}` only after the enqueue succeeded. Dedup runs first, so a retried copy of an already accepted message is `duplicate` and never `410`. Field validation is part of the parse step and each violation is `400 malformed_body`: an event occurrence needs `eventId` a string, `name` a string, `timestamp` a string, `data` present as any JSON value, and `cursor` absent, a string or `null`; a `gap` needs `cursor` a string or `null`; a `terminated` needs `error` an object with `code` an integer and `message` a string, and `data` optional and, when present, an object. `cursor` and `eventId` are forwarded unchanged. Events are deduplicated by `(subscription id, eventId)` only for the consumer's convenience and never instead of the `webhook-id` dedup of step 16. Success responses carry `Content-Type: application/json` and, beyond the `accepted` body above, exactly `{"status":"duplicate"}` for a duplicate and exactly `{"challenge":"<nonce>"}` for an echoed verification envelope, with no other member. `401` responses SHOULD include `WWW-Authenticate: Webhook-Signature`.

| case | status | body |
|---|---|---|
| event or forwarded envelope, durably enqueued | 200 | `{"status":"accepted"}` |
| `webhook-id` already answered with a `2xx` | 200 | `{"status":"duplicate"}` |
| echoed `verification` envelope | 200 | `{"challenge":"<nonce>"}` |
| verified message for a subscription id marked terminated | 410 | `{"error":{"code":"subscription_terminated","message":"subscription terminated"}}` |
| verified message whose durable enqueue failed | 503 | `{"error":{"code":"enqueue_failed","message":"enqueue failed"}}` |
| any failure in the table above | its row | the error object with the row's code |

The closed code list of a Jack receiver is the following, and no other code is used by it:

| `code` | HTTP | retryable | meaning |
|---|---|---|---|
| `missing_webhook_header` | 400 | no | a required header is absent |
| `duplicate_webhook_header` | 400 | no | a required header is present more than once |
| `malformed_webhook_id` | 400 | no | `webhook-id` grammar violated |
| `malformed_webhook_timestamp` | 400 | no | `webhook-timestamp` grammar violated |
| `malformed_subscription_id` | 400 | no | the header id is outside `^sub_[0-9a-f]{16}$` |
| `body_too_large` | 413 | no | raw body or declared `Content-Length` above 262144 bytes |
| `unknown_subscription` | 401 | no | neither a registered nor a pending secret applies |
| `subscription_not_routed` | 503 | yes | an event or forwarded envelope for an id not routed yet |
| `subscription_terminated` | 410 | no | a delivery for a subscription id the receiver has marked terminated |
| `stale_timestamp` | 401 | no | the timestamp is more than 300 s old |
| `future_timestamp` | 401 | no | the timestamp is more than 300 s ahead |
| `malformed_signature_header` | 400 | no | the signature header grammar is violated |
| `unsupported_signature_scheme` | 400 | no | a scheme other than `v1`, `v1a`, `v2a` |
| `malformed_signature` | 400 | no | a value that does not decode to 32 (`v1`) or 64 (`v1a`, `v2a`) bytes |
| `bad_signature` | 401 | no | no `v1` entry verifies with the selected secret |
| `bad_server_signature` | 401 | no | no asymmetric entry verifies while identity is enforced |
| `no_server_keys` | 503 | yes | identity is enforced and the card yields no accepted key |
| `missing_jack_auth` | 401 | no | `w1` is configured and the header is absent |
| `malformed_jack_auth` | 400 | no | the header is outside the grammar of section 4 |
| `webhook_key_is_server_key` | 401 | no | a `w1` `kid` names the configured MCP server key |
| `unknown_webhook_key` | 401 | no | `kid` is not an accepted card key |
| `jack_timestamp_out_of_window` | 401 | no | the `w1` timestamp is outside the Jack window |
| `bad_jack_signature` | 401 | no | the `w1` signature does not verify |
| `webhook_key_mismatch` | 401 | no | the required `jack.server.webhook_key` cross-check disagrees with the card |
| `webhook_key_missing` | 401 | no | the cross-check is required and the server returned no tool result |
| `enqueue_failed` | 503 | yes | the durable enqueue failed, so the message is not acknowledged |
| `malformed_body` | 400 | no | the body is not a JSON object, or an envelope field fails validation |
| `unknown_envelope_type` | 400 | no | `type` is present but is not one of the three types |

Each of the five additions has exactly one reading. `webhook_key_is_server_key` (`R3.15`) answers a `w1` header that names the configured MCP server key id, and it is decided after header parsing and before key lookup. `webhook_key_mismatch` and `webhook_key_missing` belong to the optional cross-check of `R7.6` and are answered only by a receiver that requires it. `subscription_terminated` (`R3.17`) is the one answer given to every later delivery for a subscription id already marked terminated, and it is never retryable. `enqueue_failed` (`R3.17`, `R1.10`) is retryable because the sender must redeliver a message that was never durably accepted.

An error answer is exactly the rejection body and nothing else:

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
WWW-Authenticate: Webhook-Signature

{"error":{"code":"bad_signature","message":"signature does not verify"}}
```

The `message` text is free, but it MUST NOT name the selected secret, a header value, a response body of an earlier attempt or any other byte the receiver holds.

A receiver MUST answer the challenge with `2xx` even when its profile is "reject everything else": the verification path of section 5 is the one place where a body is verified before its id is known. A status code that a WAF in front of the receiver would return is out of scope of this document. (informative)

## 4. Jack `w1` signature

```
Jack-Webhook-Auth: w1 kid=<kid>,sig=<sig>
```

- `R4.1` Header grammar. Scheme literal `w1`, one space, parameters separated by a single `,` with no whitespace, parameter set exactly `kid` and `sig` once each in any order, values `[A-Za-z0-9_-]` (base64url unpadded), `kid` 43 characters, `sig` 86 characters. Any violation is `malformed_jack_auth`; the scheme is examined first, and a scheme other than `w1` is `malformed_jack_auth`.

| parameter | length | alphabet | occurrences |
|---|---|---|---|
| `kid` | 43 characters | `[A-Za-z0-9_-]` | exactly one |
| `sig` | 86 characters | `[A-Za-z0-9_-]` | exactly one |

- `R4.2` Signing string. Seven lines joined with LF, no trailing LF: the literal first line `mcp-jack/webhook1/delivery`, then `aud`, the subscription id, `webhook-id`, `webhook-timestamp`, `callback-url`, and `body-hash`, in that order and with nothing else. `body-hash = base64url(SHA-256(raw body bytes))`, 43 characters; `sig = base64url(Ed25519_sign(webhook_key, signing_string))`.

A concrete shape for a delivery to `https://hooks.example.test/hooks/alice`, with `<hash>` standing for the 43-character body hash:

```
mcp-jack/webhook1/delivery
https://svc.example.test
sub_a3f1c8e2b0d49f7e
msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f
1795338000
https://hooks.example.test/hooks/alice
<hash>
```

A trailing slash, a different letter case in the host or a rewritten default port would change the signed bytes, which is why the callback url is signed as sent rather than in canonical form.

- `R4.3` Binding. `aud` is the Jack audience the receiver is configured with, as in [01-authentication.md](01-authentication.md) section 3.1, never taken from the request. `callback-url` is the exact `delivery.url` byte string the subscription was created with: no normalization, no trailing-slash change, no case folding. The subscription id is the value in `X-MCP-Subscription-Id`; `webhook-id` and `webhook-timestamp` are the header values as sent. A delivery captured at one receiver therefore cannot be replayed to another URL, subscription or audience.

| field | source | normalization |
|---|---|---|
| `aud` | receiver configuration | none, never from the request |
| subscription id | `X-MCP-Subscription-Id` as sent | none |
| `webhook-id` | header as sent | none |
| `webhook-timestamp` | header as sent | none |
| `callback-url` | the exact `delivery.url` the subscription was created with | none |
| `body-hash` | raw body bytes | none |

- `R4.4` Window. `|now - webhook-timestamp| <= jack_window`, where `jack_window` is the Jack response window of [01-authentication.md](01-authentication.md) section 4 (default 30 s, never more than 120 s), independent of the 300 s Standard Webhooks window. Because every attempt carries a fresh timestamp the shorter window costs nothing. The failure is `jack_timestamp_out_of_window`, checked after `unknown_webhook_key` and before the signature.

- `R4.5` Key. The dedicated webhook signing key, selected by `kid` from the accepted Server Card key set of section 7. `kid = base64url(SHA-256(raw 32-byte public key))`, the convention of [01-authentication.md](01-authentication.md) section 2. The MCP server response key is never used and is never published in the card. The receiver configuration carries the MCP server key id (`mcp_server_kid`) and optionally its raw public key, and a webhook signing key whose `kid`, or whose raw 32-byte public key, equals that configured MCP server key MUST be rejected: a `w1` header naming that `kid` is `401 webhook_key_is_server_key`, checked after header parsing and before the key lookup, and a Server Card JWK set that contains that key yields no accepted key, the key being dropped with reason `mcp_server_key` (section 7).

- `R4.6` Presence. `w1` is on every delivery and every verification POST when the deployment configures a webhook signing key. A receiver configured with such a key MUST require it: absent is `missing_jack_auth`. A receiver without a configured key ignores the header entirely, its grammar included.

## 5. Endpoint verification

Endpoint verification exists because the HMAC secret is client-chosen: it proves that the endpoint's own subscriber sent a delivery, and it proves nothing about whether the endpoint wanted the subscription. The routes below, after the cache, are the only ways to establish that intent.

| order | route | evidence |
|---|---|---|
| 1 | verification cache | a prior success for the same `(principal, canonical_url)` |
| 2 | operator allowlist | an entry of the sender's own configuration matches |
| 3 | out-of-band hook | the application's own confirmation mechanism returns true |
| 4 | well-known document | the origin publishes the covered path prefixes |
| 5 | challenge handshake | the endpoint echoes a single-use nonce |

- `R5.1` A sender MUST NOT deliver any event, `gap` or `terminated` message to a `(principal, canonical_url)` pair before that pair is verified by one of the four routes below; the challenge POST itself is not an event delivery. Verification is mandatory because a client-supplied secret stops deception but not flooding.

- `R5.2` Routes are tried in this fixed order and the first success wins: verification cache, operator allowlist, out-of-band hook, well-known document, challenge handshake. The result is cached per `(principal, canonical_url)`, never per subscription, name or arguments, so varying `arguments` cannot multiply verification POSTs and one principal's verification never waives another's. The cache entry lives as long as the subscription's TTL; it is in-memory soft state and is redone after a restart, and a server that persists no-expiry subscriptions MUST persist the verification status with them.

- `R5.3` Challenge nonce. 16 bytes from a CSPRNG, `base64url` unpadded (22 characters), fresh per attempt, single use, valid for 600 s from issue, compared in constant time over the decoded 16 bytes. A nonce is bound to the attempt's `(principal, canonical_url)`; a second echo of the same nonce, or an echo for another pair, MUST NOT verify.

| property | value |
|---|---|
| source | 16 bytes from a CSPRNG |
| encoding | `base64url`, unpadded, 22 characters |
| lifetime | 600 s from issue |
| reuse | single use per attempt and per pair |
| comparison | constant time over the decoded 16 bytes |

- `R5.4` Echo. The endpoint answers `2xx` with a JSON object whose `challenge` member is a string equal to the nonce; other members are ignored. The answer body is at most 4096 bytes and a larger one is a mismatch. A non-`2xx` status, an absent or invalid body, a wrong value, an expired nonce and a reused nonce are all `challenge_failed`; raw endpoint bodies, headers and status lines never surface.

- `R5.5` The challenge is sent inside the `events/subscribe` call that first needs it, before the subscribe result is returned, with the subscription headers (the `w1` header included when configured) and the `X-MCP-Subscription-Id` of the subscription being created, an id the receiver has not been given yet. A failed handshake fails that call with `CallbackEndpointError`, whose `data.reason` is a category from section 1 (`challenge_failed` for a mismatch, the connection category for an unreachable endpoint); the subscription is not created.

- `R5.6` Receiver side. A pending secret entry is a `(secret, callback url)` pair: the receiver registers a secret together with the callback URL under which it expects the challenge, because `w1` binds the callback URL and the subscription id is not yet known. A verification envelope whose id is not yet routed is verified against those pending entries: the `v1` HMAC with the entry's secret and, when `w1` is configured, the `w1` signature with the pending entry's callback URL and the subscription id from `X-MCP-Subscription-Id`; if `w1` is configured and the entry has no callback URL, the answer is `bad_jack_signature`. If one entry verifies, the receiver echoes the nonce and MAY bind the header id to that secret immediately, and it never forwards the envelope. If none verifies it answers `401 bad_signature`. This is the only case where a body is verified before its id is known.

- `R5.7` Allowlist route. Operator-configured entries, each an absolute `https` URL prefix: `https://`, then the host, then an optional `:` plus port, then an optional path; the host may be `*.` followed by a parent domain (matches one or more labels, never the parent itself); host compared case-insensitively, port compared after defaulting to 443, path compared byte-wise case-sensitively as a prefix at a segment boundary (a path of `/` matches every path; `/hooks` matches `/hooks` and `/hooks/x` but not `/hooksx`); no query, fragment or userinfo in an entry. A match verifies and short-circuits.

| entry | url | match |
|---|---|---|
| `https://hooks.example.test/hooks` | `https://hooks.example.test/hooks` | yes |
| `https://hooks.example.test/hooks` | `https://hooks.example.test/hooks/x` | yes |
| `https://hooks.example.test/hooks` | `https://hooks.example.test/hooksx` | no |
| `https://hooks.example.test/hooks` | `https://hooks.example.test:8443/hooks` | no, the port differs |
| `https://*.example.test/hooks` | `https://a.b.example.test/hooks` | yes, one or more labels |
| `https://*.example.test/hooks` | `https://example.test/hooks` | no, never the parent itself |

- `R5.8` Out-of-band route. An application hook `(principal, canonical_url) -> bool`, called at most once per verification attempt, its `true` verifying the pair. The hook is the application's own mechanism (dashboard registration, e-mail confirmation) and is not specified further.

- `R5.9` Well-known route. The origin serves the path `/.well-known/mcp-webhook-receiver.json` over `https` on its own host and port, with `{"receivers":["/hooks/"]}` as the body. Fetch rules: the fetch MUST use the hardened path of section 6 (`https`, resolve and validate at fetch time, no redirects) and MUST return HTTP `200`; a `204`, `3xx`, `4xx` or `5xx` response is `document_fetch_failed` with reason `status_<n>` for that status. The body MUST be at most 8192 bytes, and a larger body is `document_fetch_failed` with reason `too_large`. The body is a JSON object with `receivers` an array of 1-64 strings, each rooted at `/`, at most 1024 characters, with no `?`, `#`, control character, `.` or `..` segment; anything else invalidates the whole document. Cached per origin with TTL `min(max-age, 300)` seconds, and 300 s when the max-age is absent or unparsable.

- `R5.10` Matching. A canonical url is covered if and only if a `receivers` entry is a byte prefix of its path at a segment boundary (`/hooks/` covers `/hooks/a`; `/hooks` covers `/hooks` and `/hooks/a` but not `/hooksx`); the path is compared exactly as sent, case-sensitively, with no percent-decoding, normalization or trailing-slash insertion; the origin must be the delivery origin. Control of the origin is the proof of intent.

| `receivers` entry | url path | covered |
|---|---|---|
| `/hooks/` | `/hooks/a` | yes |
| `/hooks/` | `/hooks` | no, the trailing slash is required |
| `/hooks` | `/hooks` | yes |
| `/hooks` | `/hooks/A` | yes, the entry is a prefix and the case matches |
| `/hooks` | `/Hooks/a` | no, case matters |
| `/hooks` | `/hooksx` | no, not a segment boundary |
| `/hooks` | `/hooks%2Fa` | no, no percent-decoding |

- `R5.11` A callback url whose path contains a `.` or `..` segment, or a percent-encoded form of either (`%2e`, `%2E`, and any case variant of `%2e%2e`), is `invalid_callback_url` with reason `dot_segment` at subscribe time and at delivery time; the sender never normalizes paths.

- `R5.12` Every verification POST and every well-known fetch uses the same hardened path as deliveries (section 6) and SHOULD be rate-limited per destination host. A cached verification does not expire because of delivery failures.

## 6. Delivery-time network rules, SSRF

A webhook sender is a request-forgery primitive pointed at its own network, so every outbound connection is decided by the rules of this section, for deliveries, challenges and the well-known document alike.

- `R6.1` `https` only: any other scheme (`http`, `ftp`, empty) is `scheme_not_https`. There is no port-based exception; a non-default port is allowed.

- `R6.2` URL parts. No userinfo (`invalid_callback_url`, reason `userinfo`), no fragment (reason `fragment`), a host present (reason `empty_host`), an explicit port in 1-65535 else `invalid_callback_url` reason `port`, a path that is empty or starts with `/`, and no control character, space or raw non-ASCII anywhere in the URL (`invalid_callback_url`, reason `character`).

| part | rule | failure |
|---|---|---|
| scheme | `https` only | `scheme_not_https` |
| userinfo | absent | `invalid_callback_url` reason `userinfo` |
| fragment | absent | `invalid_callback_url` reason `fragment` |
| host | present | `invalid_callback_url` reason `empty_host` |
| host literal | a bracketed IPv6 literal without a zone id, or an LDH name | `invalid_callback_url` reason `host` |
| port | absent or 1-65535 | `invalid_callback_url` reason `port` |
| path | empty or starting with `/` | `invalid_callback_url` reason `character` |
| bytes | no control character, space or raw non-ASCII | `invalid_callback_url` reason `character` |

- `R6.3` Host forms. An IP literal is either a canonical dotted-quad (four decimal octets 0-255, no leading zeros, no sign, no whitespace) or a bracketed IPv6 literal (the two tables below). Anything else must be an ASCII LDH name: labels of 1-63 characters `[A-Za-z0-9-]` with no leading or trailing `-`, at most 253 characters, at least two labels, and the last label not all-numeric. Exactly one trailing `.` is stripped before the name is used and uppercase is lowercased. Non-ASCII (IDN in Unicode) is `not_a_hostname`; senders must send A-labels. Decimal, octal (`0177.0.0.1`), hexadecimal (`0x7f.0.0.1`), short (`127.1`), single-integer (`2130706433`), over-long-dotted (`1.2.3.4.5`) and empty-label (`a..b`) forms are all `not_a_hostname` and are never reinterpreted as an address.

| spelling | outcome |
|---|---|
| `198.51.100.7` | IP literal, classified by the IPv4 table |
| `[2001:db8::1]` | IPv6 literal, classified by the IPv6 table |
| `hooks.example.test` | LDH name, resolved at delivery time |
| `hooks.example.test.` | the single trailing dot is stripped, then an LDH name |
| `127.1` | `not_a_hostname` |
| `2130706433` | `not_a_hostname` |
| `0x7f.0.0.1` | `not_a_hostname` |
| `0177.0.0.1` | `not_a_hostname` |
| `1.2.3.4.5` | `not_a_hostname` |
| `a..b` | `not_a_hostname` |
| `hook.example.test` in Unicode with a non-ASCII label | `not_a_hostname` |

- `R6.4` IPv4 literal handling. The dotted-quad is parsed and classified directly, without a resolver.

- `R6.5` IPv4 block table. Each row carries the registry's **Globally Reachable** value, and the `reason` is always the row's registry name in snake_case. The decision over the whole table, on both families, is one rule: `allow` when the longest matching row is globally reachable and `reject` otherwise; an address in no row is `allow` with reason `global`. The table is exhaustive for this profile and MUST be updated with [the registry](https://www.iana.org/assignments/iana-ipv4-special-registry/).

| block | registry name | globally reachable |
|---|---|---|
| 0.0.0.0/8 | `this_network` | false |
| 10.0.0.0/8 | `private_use` | false |
| 100.64.0.0/10 | `shared_address_space` | false |
| 127.0.0.0/8 | `loopback` | false |
| 169.254.0.0/16 | `link_local` | false |
| 172.16.0.0/12 | `private_use` | false |
| 192.0.0.0/24 | `ietf_protocol_assignments` | false |
| 192.0.0.0/29 | `ipv4_service_continuity_prefix` | false |
| 192.0.0.8/32 | `ipv4_dummy_address` | false |
| 192.0.0.9/32 | `pcp_anycast` | true |
| 192.0.0.10/32 | `turn_anycast` | true |
| 192.0.0.170/32 | `nat64_dns64_discovery` | false |
| 192.0.0.171/32 | `nat64_dns64_discovery` | false |
| 192.0.2.0/24 | `documentation` | false |
| 192.31.196.0/24 | `as112_v4` | true |
| 192.52.193.0/24 | `amt` | true |
| 192.88.99.0/24 | `deprecated_6to4_relay_anycast` | false |
| 192.168.0.0/16 | `private_use` | false |
| 192.175.48.0/24 | `as112_direct_delegation` | true |
| 198.18.0.0/15 | `benchmarking` | false |
| 198.51.100.0/24 | `documentation` | false |
| 203.0.113.0/24 | `documentation` | false |
| 224.0.0.0/4 | `multicast` | false |
| 240.0.0.0/4 | `reserved` | false |
| 255.255.255.255/32 | `limited_broadcast` | false |

- `R6.6` IPv6 block table, with the same reachable column and the same decision rule as `R6.5`: `allow` when the longest matching row is globally reachable, `reject` otherwise, and `allow` with reason `global` for an address in no row.

| block | registry name | globally reachable |
|---|---|---|
| ::/128 | `unspecified` | false |
| ::1/128 | `loopback` | false |
| ::/96 | `ipv4_compatible_deprecated` | false |
| ::ffff:0:0/96 | `ipv4_mapped` | false |
| 64:ff9b::/96 | `nat64_well_known` | true |
| 64:ff9b:1::/48 | `nat64_local_use` | false |
| 100::/64 | `discard_only` | false |
| 2001::/23 | `ietf_protocol_assignments` | false |
| 2001::/32 | `teredo` | false |
| 2001:1::1/128 | `pcp_anycast` | true |
| 2001:1::2/128 | `turn_anycast` | true |
| 2001:2::/48 | `benchmarking` | false |
| 2001:3::/32 | `amt` | true |
| 2001:4:112::/48 | `as112_v6` | true |
| 2001:10::/28 | `orchid` | false |
| 2001:20::/28 | `orchidv2` | false |
| 2001:30::/28 | `drone_remote_id` | false |
| 2001:db8::/32 | `documentation` | false |
| 2002::/16 | `six_to_four` | false |
| 2620:4f:8000::/48 | `as112_direct_delegation` | true |
| 3fff::/20 | `documentation` | false |
| 5f00::/16 | `srv6_sid` | false |
| fc00::/7 | `unique_local` | false |
| fe80::/10 | `link_local` | false |
| ff00::/8 | `multicast` | false |

The `2001::/23` entry contains the more specific 2001::/32 `teredo`, 2001:2::/48 `benchmarking`, 2001:3::/32 `amt`, 2001:4:112::/48 `as112_v6`, 2001:10::/28 `orchid`, 2001:20::/28 `orchidv2` and 2001:30::/28 `drone_remote_id` rows, so the longest match selects one of them rather than the enclosing row; 2001:db8::/32 `documentation` and 3fff::/20 `documentation` are separate registry entries outside 2001::/23. The source is [the IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry/) and the table MUST be updated with it. The `::/96` entry is a Jack addition and not an IANA entry: the registry lists only `::/128` and `::1/128`, and the remaining `::/96` addresses are the deprecated IPv4-compatible form, which is never globally reachable.

- `R6.7` Translation and tunneling forms. Two chains inherit the embedded decision and two do not. IPv4-mapped `::ffff:a.b.c.d` is decided by the embedded IPv4 address: the reason is `ipv4_mapped/<ipv4 reason>` when that address is inside an IPv4 row and `ipv4_mapped` when it is inside none, and an allowed mapped address inherits the embedded decision, so it is `allow` exactly when the embedded address is `allow`. NAT64 `64:ff9b::a.b.c.d` follows the same rule, with `nat64_well_known/<ipv4 reason>` and `nat64_well_known`, and an allowed NAT64 address inherits the embedded decision the same way. 6to4 `2002::/16` and Teredo `2001::/32` never inherit anything: both are always `reject`, with the row's own name, `six_to_four` and `teredo`, as the single reason string everywhere, and no embedded address is decoded into the reason. `64:ff9b:1::/48` has no fixed embedding and is `reject` with `nat64_local_use`.

| address | decision | reason |
|---|---|---|
| `::ffff:127.0.0.1` | reject | `ipv4_mapped/loopback` |
| `64:ff9b::10.0.0.1` | reject | `nat64_well_known/private_use` |
| `2002:7f00:1::` | reject | `six_to_four` |
| `2001:0:4136:e378::` | reject | `teredo` |
| `64:ff9b:1::1` | reject | `nat64_local_use` |
| `192.0.0.9` | allow | `pcp_anycast` |
| `2620:4f:8000::1` | allow | `as112_direct_delegation` |

The first five rows are rejected: the mapped and NAT64 addresses inherit a non-reachable embedded block, and the 6to4, Teredo and local-use NAT64 rows are non-reachable themselves. The last two are allowed because `192.0.0.9/32` `pcp_anycast` and `2620:4f:8000::/48` `as112_direct_delegation` are marked globally reachable in the registries.

- `R6.8` Resolution and connection. Resolve at delivery time, never only at subscribe time; collect every answer and validate each. If any answer's decision is `reject` the attempt is refused with `blocked_address` and the reason of the first failing answer in resolver order. Connect to the first `allow` address, send the original host name in `Host` (with `:port` when not 443) and the same name in TLS SNI, and verify the certificate against that name. An IP-literal host is its own name: `Host` carries the bracketed literal and no SNI extension is sent, and the certificate is verified against the IP address. No HTTP proxy from the environment; connection and read caps follow section 1's timeout rule.

| stage | action |
|---|---|
| 1 | resolve the host at delivery time and collect every answer |
| 2 | classify every answer against both tables, applying the translation chains |
| 3 | refuse the attempt on the first failing answer in resolver order |
| 4 | pick the first allowed answer and connect to that exact address |
| 5 | send the original host name in `Host` and in TLS SNI, verify the certificate against it |

- `R6.9` Rebinding. The address actually connected to MUST equal the validated address. If the resolver returns a different address between validation and connect, or the connected peer differs, the attempt is refused with `dns_rebinding` and is not retried on the new address.

- `R6.10` Redirects are never followed, for deliveries and for the well-known document. Any `3xx` is `redirect_refused`, final for that message. A `Location` header is never read.

- `R6.11` Operator override. `allowedRanges`, a list of up to 64 CIDR blocks (IPv4 `a.b.c.d/0-32`, IPv6 `hex::/0-128`), is checked after the registry tables; a match overrides a block and the pair is `allowed` with reason `allowed_range`. Malformed entries are ignored. The override is never applied to a host spelling rejected by the host-form rule above and never to a non-`https` scheme.

## 7. Server Card key discovery

- `R7.1` Location. `remotes[i].extensionsInfo["io.modelcontextprotocol/events"].webhooks.signingKeys` is a JWK set `{"keys":[...]}`; `remotes[i].extensionsInfo["io.modelcontextprotocol/events"].webhooks.egressIpRanges` is an optional array of CIDR strings. The `webhooks` object is found on the remote entry whose substituted `url` is the MCP endpoint the client uses: same origin, preferring the exact path and then the longest path prefix. Presence or absence of the `extensionsInfo` entry states or denies nothing about support for the Events extension, which is negotiated at runtime. An entry without `webhooks.signingKeys` yields no keys, and that is not an error in itself.

- `R7.2` Fetch. The card URL comes from the AI Catalog entry at the MCP origin's `/.well-known/ai-catalog.json`, the entry with `type` `application/mcp-server-card+json` and either `url` or inline `data`, or from the reserved default `server-card` path under the MCP streamable-HTTP url. The card MUST be fetched over `https` from the same origin as the MCP endpoint, MUST NOT follow a redirect (same-origin included, as `redirect_refused`), MUST be at most 65536 bytes, and MUST complete within 10 s of wall clock: a fetch whose measured `elapsed_ms > 10000` is `timeout`, and it SHOULD be requested with `Accept: application/mcp-server-card+json`. A card from another origin, or one reached through a cross-origin redirect, MUST be discarded as `cross_origin`. An inline `data` card in a catalog entry MUST NOT be used for keys. The card is cached per origin for at most 300 s, respecting `Cache-Control: max-age` when smaller.

- `R7.3` JWK validation, each key independently: `kty` `"OKP"`, `crv` `"Ed25519"`, `x` canonical unpadded base64url decoding to exactly 32 bytes, the key a strict Ed25519 public key (canonical encoding, prime-order subgroup, not the identity, as [03-user-management.md](03-user-management.md) section 2), `kid` present and equal to `base64url(SHA-256(x))`, `use` absent or `"sig"`, `alg` absent or `"EdDSA"`, unknown members ignored. A key equal to the configured MCP server key, by `kid` or by raw 32-byte public key, is rejected with reason `mcp_server_key` (`R4.5`), so a card that publishes the server key yields no accepted key from that member. `kid` MUST be unique within the accepted set: on a duplicate every key with that `kid` is rejected as `duplicate_kid`. A rejected key never verifies anything; if none remains, the enforcement answer is `no_server_keys` at the asymmetric step of section 3.

| member | required value |
|---|---|
| `kty` | `"OKP"` |
| `crv` | `"Ed25519"` |
| `x` | canonical unpadded base64url of exactly 32 bytes |
| `kid` | present, equal to `base64url(SHA-256(x))` |
| `use` | absent, or `"sig"` |
| `alg` | absent, or `"EdDSA"` |
| any other member | ignored |

- `R7.4` Rotation. The new key is published alongside the old; while both are present both are trusted, so a delivery may verify with either and rotation needs no re-delivery. A key removed from the card is no longer trusted once the cached card is refreshed, and a delivery signed with it then fails `bad_server_signature` or `unknown_webhook_key`. A sender MUST keep the old key published for at least the retry window of section 1 plus the window of section 4.

| moment | published keys | accepted keys |
|---|---|---|
| before rotation | the current key | the current key |
| during rotation | the current key and the new key | both |
| after the retry window | the new key | the new key |

A delivery already in flight during rotation verifies with either key, so rotation never depends on a re-delivery.

- `R7.5` `egressIpRanges` is advisory egress allowlisting for receiver-side firewalls and never a substitute for the signatures. Entries are validated as CIDRs of the same shape as the operator override of section 6; malformed entries are dropped and recorded. The member is optional.

- `R7.6` `jack.server.webhook_key` cross-check (optional). A Jack server exposes a read-only native tool `jack.server.webhook_key`, callable by any authenticated caller like `jack.server.key`, with no arguments. Its result is exactly `{"webhook_key":{"signing_keys":{"keys":[...]},"egress_ip_ranges":[...]}}`, where `signing_keys` is the same JWK set the Server Card publishes, under a subset rule: the tool MUST NOT publish a key the card does not publish, so the tool narrows the card and never widens it. A receiver that already holds a Jack-authenticated channel to the server MAY require both sources to agree, comparing the keys as canonical JSON, members sorted by `kid` and reduced to `kty`, `crv`, `x` and `kid`. A mismatch is `401 webhook_key_mismatch`; a required check with no tool result, because the server predates the tool, is `401 webhook_key_missing`; a receiver that does not require the check ignores the tool and its answer. This cross-check never replaces the same-origin card rule of `R7.2`: a key the card does not publish is never accepted, whatever the tool answered.

## 8. Principal mapping and subscription lifecycle

- `R8.1` Subscription key `(principal, canonical_url, name, arguments)`. `principal` is the verified Jack identity name of [02-authorization.md](02-authorization.md), the `name` of the verified key, stable across `jack.key.rotate`, never the `kid`. All four components are immutable for the lifetime of the subscription; `events/subscribe` with the same key is an idempotent upsert that refreshes the TTL and replaces the secret and the mutable fields, and a different value of any component is a different subscription. `events/unsubscribe` addresses the subscription by the same key, and the derived id is never accepted as input. Both methods require an authenticated principal and answer `Forbidden` otherwise.

| component | source | mutable |
|---|---|---|
| `principal` | the verified Jack identity name | no |
| `canonical_url` | `delivery.url` rendered in canonical form | no |
| `name` | `params.name` | no |
| `arguments` | `params.arguments` under canonical JSON | no |

- `R8.2` Canonical url form, used in the key, in `callback-url` of section 4 and in the verification cache: scheme `https` lowercase; host lowercased in A-label form with one trailing dot removed; `:port` only when it is not 443; the path exactly as supplied, with an empty path becoming `/`; `?` plus the query exactly as supplied when non-empty; never userinfo or fragment. The subscriber's original string is what the Jack signature covers, so a sender MUST keep both strings: it signs `delivery.url` byte for byte as sent and keys on the canonical form, and it MUST NOT rewrite either string. A `delivery.url` byte-identical to its canonical form is what clients SHOULD send, and the receiver compares `callback-url` against the exact string it registered.

- `R8.3` `arguments` canonical JSON is RFC 8785 (JCS): object members sorted by UTF-16 code unit order of the keys, no whitespace, ECMAScript number serialization, and only `"`, `\` and control characters escaped. An absent `arguments` and an explicit `null` are the same key. `arguments` that are not JSON objects, arrays or primitives of finite value are `invalid_arguments`.

- `R8.4` Derived id: `id = "sub_" + lowercase hex of SHA-256 over the UTF-8 bytes of JCS(["mcp-jack/webhook1/subscription", principal, canonical_url, name, arguments])`, truncated to the first 16 hex characters (64 bits), 20 characters total, grammar `^sub_[0-9a-f]{16}$`. This pins the value for all three SDKs. Two worked examples: principal `alice`, canonical_url `https://hooks.example.test/hooks/alice`, name `incident.created`, arguments `{"severity":"P1"}`, whose JCS input is `["mcp-jack/webhook1/subscription","alice","https://hooks.example.test/hooks/alice","incident.created",{"severity":"P1"}]`, yields the id of the vector `sub-id-worked-example-1` in `spec/tools/modern/webhooks/vectors/subscription.mjs`; principal `alice`, canonical_url `https://hooks.example.test:8443/hooks/alice?tenant=1`, name `email.received`, arguments absent, whose JCS input is `["mcp-jack/webhook1/subscription","alice","https://hooks.example.test:8443/hooks/alice?tenant=1","email.received",null]`, yields the id of the vector `sub-id-worked-example-2` in `spec/tools/modern/webhooks/vectors/subscription.mjs`. The generated vector file pins the concrete 20-character value of each of the two ids, so both examples are reproducible byte for byte. The id is a routing handle and not a capability.

- `R8.5` TTL. `ttlMs` in the request absent means the server default (`3600000` ms in Jack); an integer is a suggested lifetime; `null` means no expiry. A finite `ttlMs` MUST be a non-negative integer (fractional, negative or non-integer values are `invalid_arguments`). The grant is `min(max(ttlMs, 60000), 86400000)` for a finite suggestion and `null` for `null`. `refreshBefore` is the grant rendered as an ISO 8601 UTC timestamp with second precision (`YYYY-MM-DDTHH:MM:SSZ`), or `null`. The grant is authoritative and is re-issued on every refresh, and a client MUST refresh before it. The response fields (informative):

| field | type | meaning |
|---|---|---|
| `id` | string | the derived id of the subscription, a routing handle |
| `refreshBefore` | string or `null` | the authoritative grant |
| `cursor` | string or `null` | the safe-to-persist watermark |
| `truncated` | boolean | delivery started later than the supplied cursor |
| `deliveryStatus` | object, optional | `active`, `lastDeliveryAt`, `lastError`, and optionally `failedSince`, `throttled`, `retryAfterMs` |

How the grant is computed:

| `ttlMs` in the request | grant | `refreshBefore` |
|---|---|---|
| absent | the server default, `3600000` ms in Jack | the default rendered as a timestamp |
| `30000` | clamped up to `60000` ms | the clamp rendered as a timestamp |
| `3600000` | `3600000` ms | one hour after the issue |
| `172800000` | clamped down to `86400000` ms | one day after the issue |
| `null` | no expiry | `null` |

- `R8.6` Secret rotation. On refresh with a new `delivery.secret` the new secret becomes current and the previous one keeps signing deliveries for 300 s of grace, then is dropped; the entry order is that of section 2, and only two secrets are ever active. There is no server-initiated rotation.

- `R8.7` `gap`. The body is exactly `{"type":"gap","cursor":"<fresh>"}` and the `webhook-id` is `msg_gap_` followed by 32 characters of `[A-Za-z0-9]`. It is sent when a gap is detected between refreshes; the receiver persists the cursor and treats it as `truncated: true`.

- `R8.8` `terminated`. The body is exactly `{"type":"terminated","error":{"code":-32024,"message":"Forbidden","data":{"reason":"Access revoked"}}}`, with `data` optional and, when present, an object, `code` an integer and `message` a string, and the `webhook-id` is `msg_terminated_` followed by 32 characters of `[A-Za-z0-9]`. It is sent when the subscription ends because authorization was revoked or the subscription is being dropped; the subscription no longer exists on the server, the receiver must stop routing the id, and every later delivery for it is answered `410 subscription_terminated` (`R3.17`). The sender re-checks the principal's registration and revocation status at delivery time and on refresh, and terminates rather than delivering to a revoked principal.

| server-side event | subscription afterwards | message to the receiver |
|---|---|---|
| refresh before `refreshBefore` | continues, TTL granted again | none |
| `refreshBefore` passes without a refresh | gone | none, the sender simply stops |
| authorization revoked | gone | `terminated` |
| subscription dropped, for example after sustained failure | gone | `terminated` |
| `events/unsubscribe` | gone | none, the delivery stops immediately |

- `R8.9` `cursor` is opaque, at most 512 characters, printable ASCII `0x21-0x7E`, and `null` when the event type does not support replay. It is a safe-to-persist watermark, is forwarded unchanged, is returned in every subscribe and refresh response, and is never ahead of unacknowledged events. `eventId` deduplication is scoped to the subscription.

## 9. Security considerations (informative)

- **Secret leakage.** The secret is chosen by the client and scoped to one subscription, so a leaked secret exposes one endpoint and no other. The server never generates or logs it, and the subscribe body that carries it is a signed `mcp-jack/v1` body over TLS.

- **Flooding.** An attacker who subscribes a victim's URL with an attacker-chosen secret still floods the victim, because each forged-looking delivery is a real POST. Endpoint verification is mandatory for exactly this reason, and the per-`(principal, canonical_url)` cache bounds attacker-induced traffic to one POST per pair.

- **Replay.** The 300 s window bounds a captured delivery, `webhook-id` deduplication bounds a replay inside it, the challenge nonce is single use, and the Jack signature binds audience, callback url and subscription so a delivery captured at one receiver cannot be replayed at another.

- **Why both signatures.** HMAC proves "the endpoint's own subscriber sent this" and works with off-the-shelf verifiers. The Jack signature proves "this Jack server sent it" and keeps working after the secret leaks.

- **Why the MCP server key is never used for the asymmetric schemes.** Those signatures have no domain separation, a different rotation lifetime, and a cross-protocol risk: the same key would be verifiable in contexts Jack never intended. The dedicated webhook key has none of these properties.

- **Untrusted payloads.** Event data is data, never instructions. `lastError` is a category and never a response oracle, so an attacker who controls a URL cannot read the endpoint's answers through Jack.

- **SSRF is the primary risk.** Any sender is a request-forgery primitive pointed at its own network. The four verification routes do not weaken it: all four resolve and validate at fetch time, and the challenge and well-known POSTs use the same hardened path as deliveries.

- **Canonicalization.** The key uses a canonical url while the signature covers the original string, so an implementation cannot quietly normalize a path and still pass verification. That split is deliberate: it keeps the subscription key stable without letting a rewrite change what was signed.

- **Clock and suspension.** A receiver clock outside the 300 s window rejects legitimate deliveries; the fresh timestamp per attempt bounds the damage to one retry cycle. Suspension pauses the retry clock, so a long outage does not silently consume the four attempts.

- **TLS.** TLS is required but does not replace the signatures; it protects the secret and the payload in transit and nothing more.

## 10. Conformance

The generated vector files below are normative test cases for this document, generated by the webhooks family generator under `spec/tools/modern/webhooks/`; the parent integrates them into `spec/fixtures/modern/` and `spec/tests/CASES.md`.

| file | covers |
|---|---|
| `webhook-signature-vectors.json` | secret grammar, `v1`, `v1a`, `v2a`, emission order and rotation |
| `webhook-w1-vectors.json` | header grammar, signing string, binding, window, key selection |
| `webhook-receiver-vectors.json` | the eighteen verification steps and the closed code table |
| `webhook-endpoint-verification-vectors.json` | the four routes, nonce and echo, allowlist and well-known matching |
| `ssrf-vectors.json` | both address tables, host spellings, mapped and NAT64 chains, redirect refusal |
| `webhook-subscription-vectors.json` | subscription key, canonical form, JCS, derived id, TTL, rotation, `gap`, `terminated`, cursor |
| `server-card-keys-vectors.json` | card location, fetch rules, JWK validation, duplicate `kid`, rotation, `egressIpRanges`, the server-key rejection and the optional `jack.server.webhook_key` cross-check |

The vectors use the fixture identities of `spec/fixtures/keys.json`: `newbie` as the deployed webhook signing key, `newbie2` as its rotation predecessor, `newbie3` as its successor, and `mallory` as a key that is never published. They use the fixed clock of the other fixture families. Fixture keys are test-only and must never be used outside tests.
