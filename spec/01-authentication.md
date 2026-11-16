# 01. Authentication

Status: draft v0.1. Normative unless marked *informative*.

The key words MUST, MUST NOT, SHOULD, MAY are used as in RFC 2119.

## 1. Model

mcp-jack authenticates every HTTP request and every response with an Ed25519 signature. There is no bearer token and no session: a captured message cannot be reused outside its time window, against another server, or with a different body.

Confidentiality and server-certificate validation are delegated to TLS. Implementations MUST use HTTPS for any non-loopback connection. The signatures here provide authentication, integrity, replay protection and an audit identity; they do not replace TLS.

## 2. Keys and encodings

- Signature algorithm: Ed25519 (pure EdDSA, RFC 8032). There is no algorithm negotiation.
- A public key is its 32-byte raw encoding. A key is only acceptable if it is a canonical encoding of a point in the prime-order subgroup that is not the identity ([03-user-management.md](03-user-management.md) section 2). Registries MUST reject other keys at load time.
- Signature verification MUST be strict: a signature whose scalar S is not below the group order L is invalid, even if the verification equation holds; a signature whose R is the canonical encoding of a small-order point (one of the eight points of order dividing 8) is invalid as well. This rules out malleated signatures and makes all implementations agree.
- `kid` (key id) = `base64url(SHA-256(public_key_bytes))`.
- `base64url` is RFC 4648 section 5, **unpadded and canonical**: a decoder MUST reject padding, characters outside `A-Za-z0-9_-`, and encodings whose unused trailing bits are not zero (the decode-then-encode round trip must reproduce the input).
- Sizes: `kid` 32 bytes (43 chars), `nonce` 16 bytes (22 chars), `sig` 64 bytes (86 chars).

## 3. Request authentication

A request MUST carry exactly one `Jack-Auth` header:

```
Jack-Auth: v1 kid=<kid>,ts=<ts>,nonce=<nonce>,sig=<sig>
```

Grammar rules (strict; any violation is `malformed_auth`):

- the scheme is the literal `v1`, followed by one space, then parameters separated by a single `,` with no whitespace;
- each parameter is `name=value`; names are lowercase and case-sensitive; the value uses only `A-Za-z0-9_-`;
- the parameter set is exactly `kid`, `ts`, `nonce`, `sig`, each once, in any order;
- `ts` is a Unix time in whole seconds, decimal, no sign, no leading zeros (`0` is allowed), at most 12 digits;
- `nonce` is 16 bytes from a CSPRNG, fresh for every request;
- a scheme of the form `v` + digits other than `v1` is `unsupported_version`; any other scheme is `malformed_auth`. The scheme is examined first, on the raw header bytes, before any character-encoding check: a header whose scheme is `v2` is `unsupported_version` even if its parameters are malformed or carry bytes outside the `A-Za-z0-9_-` value alphabet, because the grammar of other versions is unknown.

### 3.1 Signing string

The signed message is the UTF-8 encoding of these eight lines joined with a single LF (U+000A), with no trailing LF:

```
mcp-jack/v1/request
<method>
<target>
<aud>
<kid>
<ts>
<nonce>
<body-hash>
```

| Field | Value |
|---|---|
| `method` | HTTP method exactly as sent (e.g. `POST`). |
| `target` | The origin-form request target as sent on the wire: path plus `?query` if present, no fragment, byte-for-byte (no normalisation, no re-encoding). It MUST NOT contain control characters. The signed target is the bytes of the request target exactly as received, before any decoding: no percent-decoding, normalisation or re-encoding is applied. It consists only of the bytes 0x21 to 0x7E; a client percent-encodes everything else, so a space, a control character, DEL or a byte of 0x80 or above never occurs in a valid target. A request whose target is absolute-form, authority-form or asterisk-form, or contains a byte outside 0x21 to 0x7E, MUST be rejected before verification with `400 invalid_request` (unsigned); an HTTP server library that refuses such a request line itself answers its own `400`, which is equivalent. A fragment, the first `#` and everything after it, is not part of the target: a conforming client never sends one, and a server drops it before verification (some HTTP stacks drop it while parsing the request line). |
| `aud` | The audience identifier configured on the server and in the client (for example `https://svc.example.test`). The server compares against its own configuration, never against the `Host` header, so the check survives reverse proxies. `aud` MUST NOT contain control characters (bytes below 0x20 or 0x7f). |
| `kid`, `ts`, `nonce` | The header values as sent. |
| `body-hash` | `base64url(SHA-256(body_bytes))` over the exact request body bytes. An empty body is hashed as an empty byte string, so the field is never empty (it is the encoding of the SHA-256 of zero bytes). |

`sig` = `base64url(Ed25519_sign(private_key, signing_string))`.

The body is hashed and verified before it is parsed, and the hash always covers the bytes exactly as sent: a body is never re-serialized, for example to drop or merge duplicate member names (02 section 2), before verification. Servers SHOULD enforce a maximum body size before hashing.

## 4. Request verification

A server MUST perform these steps in order and stop at the first failure. Failure responses use the status and code below and MUST NOT reveal more than the code.

| # | Check | HTTP | `code` |
|---|---|---|---|
| 1 | Header absent | 401 | `missing_auth` |
| 2 | Header present more than once, or violates section 3 grammar | 401 | `malformed_auth` |
| 3 | Version is not `v1` | 401 | `unsupported_version` |
| 4 | `kid` is not in the key registry (the single exception is enrollment, below) | 401 | `unknown_key` |
| 5 | Key not active: `now < not_before` or `now >= not_after` | 401 | `key_inactive` |
| 6 | `abs(now - ts) > window` (default 30 s, SHOULD NOT exceed 120 s) | 401 | `timestamp_out_of_window` |
| 7 | Signature does not verify over the recomputed signing string | 401 | `bad_signature` |
| 8 | `(kid, nonce)` already recorded and still live | 401 | `replayed_nonce` |
| 9 | Dispatch and identity hand-off, see [02-authorization.md](02-authorization.md) | 400/403/501 | see there |

Rules:

- **Enrollment exception.** A `kid` that is not registered is accepted at step 4 only for a `POST` `tools/call` of `jack.enroll`, whose arguments carry a `code` that names a live invite (read-only lookup, 03 section 3.2) and the public key whose hash is `kid`. Without a live invite the answer is the ordinary unsigned `401 unknown_key`, exactly as for any unknown `kid`. Steps 5-8 then run against that submitted key (step 5 is skipped because the key has no registry interval yet). The full procedure and its errors are in [03-user-management.md](03-user-management.md) section 3.2.
- **Request time.** A verifier's request time `now` is max(clock sample, the highest sample that verifier has seen); freshness (step 6) and the volatile nonce store use that effective time, so the clock never goes backwards within a process and a purged nonce cannot be accepted again after a step back; response timestamps use the raw sample, and the durable profile latches its own clock.
- Cheap checks run first (steps 1-6), so unauthenticated traffic costs a map lookup, not a signature verification.
- **Nonce recording.** The `(kid, nonce)` pair is recorded only after the signature has verified (step 7), so requests that fail verification cannot fill the cache. The enrollment exception is the one caveat: an unregistered `kid` is verified against the key carried by the request itself, but only when the request presents a live invite, so only the holder of a live invite can have a nonce recorded for an unknown `kid`; without one the answer is the ordinary `401 unknown_key` and nothing is recorded. The cache is thereby bounded by the number of live invites, but invite holders can still record nonces. A deployment MUST therefore still bound the rate of such requests and the size of the nonce cache. An entry is retained while `now <= ts + window` and `ts` may be up to `window` seconds ahead of `now`, so one entry can live for up to `2 * window + 1` seconds: the request rate times that lifetime must stay below the cache capacity. (The Go CLI gateway admits at most 64 requests per second, keeps at most 4096 nonces and limits the durable window to 30 s.) The check in step 8 and the insertion MUST be one atomic operation. After the entry expires no message with this `ts` can be accepted anyway.
- A request rejected at step 9 has still consumed its nonce.
- The nonce cache is scoped by `kid`: the same nonce from two keys does not collide.
- A deployment with several server instances behind one `aud` MUST share the nonce cache (or route each `kid` to one instance); otherwise a captured request can be replayed once per instance.
- Rejections use `Content-Type: application/json` and the body `{"error":{"code":"<code>","message":"<text>"}}`. `401` responses SHOULD include `WWW-Authenticate: Jack-Auth`.

## 5. Response authentication

The server signs its responses so that a client can detect a forged or altered answer (logs, status, config) even if TLS is terminated by an intermediary.

```
Jack-Auth: v1 kid=<server kid>,ts=<ts>,sig=<sig>
```

Same grammar rules as section 3, with the parameter set exactly `kid`, `ts`, `sig`.

Signing string (same encoding rules):

```
mcp-jack/v1/response
<status>
<request-sig>
<kid>
<ts>
<body-hash>
```

- `status` is the decimal HTTP status code.
- `request-sig` is the `sig` value of the request being answered; this binds the response to that request.
- `kid` is the server's key id; the client MUST have the server public key pinned in its configuration and MUST reject any other `kid`.

Client verification order, each failure being a client-side error. These codes are never sent over HTTP, so they have no HTTP status. As on the server, the scheme is examined first (step 3 applies before the parameter rules of step 2):

| # | Check | `code` |
|---|---|---|
| 1 | Header absent | `missing_auth` |
| 2 | Header repeated or malformed | `malformed_auth` |
| 3 | Version not `v1` | `unsupported_version` |
| 4 | `kid` is not the pinned server key | `unknown_server_key` |
| 5 | `abs(now - ts) > window` | `timestamp_out_of_window` |
| 6 | Signature does not verify | `bad_signature` |

Responses to requests that failed authentication MAY be unsigned. A client MUST NOT act on an unsigned or unverified response beyond reporting its status.

Streaming responses (for example event streams of logs) cannot carry a whole-body hash; in v0.1 a server refuses event streams with `501 streaming_unsupported` ([02-authorization.md](02-authorization.md) section 2) until the v0.2 session channel (open question Q1 in [README.md](README.md)).

## 6. Security considerations (informative)

- **Private-key storage is the real boundary.** A stolen signing key is as good as a stolen token. Implementations SHOULD keep keys in a non-extractable store (TPM, secure enclave, hardware token) or behind a signer agent that returns signatures without exposing the key.
- **Signing is not authorization.** An agent that can ask a signer for signatures can be tricked (prompt injection through log content) into requesting a dangerous operation. Signer agents should apply their own access rules and require human confirmation for destructive operations.
- **Domain separation.** The `mcp-jack/v1/request` and `mcp-jack/v1/response` prefixes prevent a signature from one context being valid in the other, or in another protocol using the same key.
- **No downgrade.** There is one algorithm and one version; unknown versions are rejected, not negotiated.
- **Clock.** Servers and clients need clocks within the window; a skewed client sees `timestamp_out_of_window`. Time synchronisation is a deployment prerequisite.
- **Error detail.** The codes above are intentionally specific for operability. `kid` is a hash of a public key, so confirming that a `kid` exists does not leak secrets.

## 7. Conformance

The vectors in `fixtures/request-vectors.json` and `fixtures/response-vectors.json` are normative test cases for this document; see [tests/README.md](tests/README.md).
