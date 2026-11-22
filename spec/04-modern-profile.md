# 04. Modern profile (MCP 2026-07-28)

Status: v0.2 draft for the 0.2.0 release line, dated 2026-11-22. Normative unless marked *informative*. The `mcp-jack/v1` request and response signatures of [01-authentication.md](01-authentication.md) and the dispatch rules of [02-authorization.md](02-authorization.md) are unchanged: this document only adds request-level selection and header rules around those same signed bytes and never reinterprets a v1 signature. The era rules run strictly after authentication.

The key words MUST, MUST NOT, SHOULD, MAY are used as in RFC 2119.

*Informative* — primary sources: [Streamable HTTP: request metadata](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http.md#request-metadata), [tools: `x-mcp-header`](https://modelcontextprotocol.io/specification/2026-07-28/server/tools.md#x-mcp-header), [events routing headers (SEP-2243)](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2243-http-standardization.md), [versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning.md), [`_meta` and error codes](https://modelcontextprotocol.io/specification/2026-07-28/basic/index.md#_meta), and the [2025-11-25 to 2026-07-28 changelog](https://github.com/modelcontextprotocol/specification/compare/2025-11-25...2026-07-28).

## 1. Model

MCP 2026-07-28 removes protocol-level sessions, the GET stream endpoint, `initialize` and `Last-Event-ID` resumability, and adds per-request metadata mirrored into HTTP headers.
Jack already parses the verified body, so it is the last component that can check that headers and body agree.

| Change in 2026-07-28 | Direction |
|---|---|
| Protocol-level sessions | removed |
| GET stream endpoint | removed |
| `initialize` handshake | removed |
| `Last-Event-ID` resumability | removed |
| Per-request metadata | added in `_meta` |
| Mirrors of that metadata | added as HTTP headers |

Three deployment profiles:

| Profile | Behaviour |
|---|---|
| `legacy` | Every request is served as legacy-era. Unchanged 0.1.x behaviour. |
| `modern` | Every request is served as modern-era. |
| `both` | The era is decided per request (`S3`, section 3). |

Definitions:

- **Legacy era** — MCP revisions that use `initialize`: `2025-11-25` and `2025-06-18`.
- **Modern era** — `2026-07-28` and later.
- **Profile** — a deployment setting, chosen once per server.
- **Era** — a per-request classification, decided in section 3.
- **Mirror** — an HTTP header carrying the value of a signed body field.

A profile is a deployment setting; an era is per request.
A request is authenticated exactly as in 01 sections 3-4 in both eras.
Headers are never signed: they are unsigned mirrors of a signed body, so they are validated, never trusted (section 7).
Header names are case-insensitive, values case-sensitive (RFC 9110).

## 2. Constants and grammars

```
MODERN-MIN = "2026-07-28"
version    = 4DIGIT "-" 2DIGIT "-" 2DIGIT
```

- `MODERN-MIN` is the first modern-era version.
- A `version` value is exactly 10 ASCII characters: four digits, `-`, two digits, `-`, two digits.
- `version` values compare byte-wise lexicographically, which is chronological for well-formed values.
- `2026-7-28`, `2026-07-28-draft` and `DRAFT-2026` are not `version` values.

| Value | Well-formed `version` |
|---|---|
| `2026-07-28` | yes |
| `2025-11-25` | yes |
| `2026-7-28` | no, one-digit month |
| `2026-07-28-draft` | no, extra suffix |
| `DRAFT-2026` | no, not digits |

Canonical header names, compared case-insensitively:

| Canonical name | Mirror of |
|---|---|
| `MCP-Protocol-Version` | `params._meta["io.modelcontextprotocol/protocolVersion"]` |
| `Mcp-Method` | `method` |
| `Mcp-Name` | `params.name` or `params.uri` (`S6`) |
| `Mcp-Param-{Name}` | one annotated tool argument (`C5`, `C6`) |

Field values (RFC 9110 section 5.5):

```
field-value = *( HTAB / SP / VCHAR )   ; 0x09, 0x20, 0x21-0x7E
```

- Permitted bytes: 0x09 (HTAB), 0x20 (SP), 0x21-0x7E (VCHAR).
- CR 0x0D, LF 0x0A, NUL 0x00, DEL 0x7F and every byte 0x80-0xFF violate the syntax.

| Bytes | Name | In field-value |
|---|---|---|
| 0x09 | HTAB | yes |
| 0x20 | SP | yes |
| 0x21-0x7E | VCHAR | yes |
| 0x00 | NUL | no |
| 0x0A | LF | no |
| 0x0D | CR | no |
| 0x7F | DEL | no |
| 0x80-0xFF | any high byte | no |

OWS: leading and trailing SP/HTAB of a received value is removed by the HTTP layer (RFC 9110 section 5.5).
Every value in this document and in the vectors is the value after that removal, and Jack does not trim further.

Base64 sentinel:

```
sentinel = "=?base64?" base64 "?="
base64   = *( ALPHA / DIGIT / "+" / "/" ) *2"="
```

- The markers `=?base64?` and `?=` are case-sensitive lowercase.
- `base64` is RFC 4648 section 4 standard base64: alphabet `A-Za-z0-9+/`, `=` padding to a multiple of four, canonical (decode-then-encode reproduces the text).
- The encoded bytes are the UTF-8 bytes of the text.
- The shortest sentinel is `=?base64??=` (11 characters); the markers never overlap.
- This is deliberately NOT the unpadded base64url of 01 section 2.

## 3. Profile selection and the era decision

| Profile | Era per request |
|---|---|
| `legacy` | Every request is legacy-era. |
| `modern` | Every request is modern-era. |
| `both` | Decided per request by `S3`. |

`S3` — era decision. This is the first rule that runs after authentication (01 section 4 steps 1-8) and after body classification (02 section 2), and it is a deliberate security rule, not a convenience: mirror headers are unsigned while the body is signed, so a decision taken from a header alone would let an on-path attacker strip one header and have a modern request processed by the legacy path. Any modern signal therefore selects the modern era, and any disagreement between the mirrors is then a signed refusal (`S4`), never a downgrade.

- Let `H` be the instances of `MCP-Protocol-Version` that are present (name compared case-insensitively).
- Let `M` be the string `params._meta["io.modelcontextprotocol/protocolVersion"]` when the body is a request or notification and that member is a string.
- The request is modern-era iff **any** instance in `H` is a well-formed `version` with `H >= MODERN-MIN`, or `M` is a well-formed `version` with `M >= MODERN-MIN`.
- Otherwise the request is legacy-era.

A repeated mirror header counts for the era test when any of its values is a well-formed modern version: ambiguity must not buy the legacy path, and in the modern era `S1` refuses the repetition.

`_meta` means `params._meta` only; a root-level `_meta` is never a mirror source.

The decision, as a table (profile `both`):

| `H` | `M` | Era | Follow-up |
|---|---|---|---|
| absent | absent | legacy | none |
| pre-2026 | absent | legacy | none |
| well-formed, `>= MODERN-MIN` | absent | modern | `S4` refuses the missing `_meta` |
| absent | well-formed, `>= MODERN-MIN` | modern | `S4` refuses the missing header |
| well-formed, `>= MODERN-MIN` | well-formed, `< MODERN-MIN` | modern | `S4` refuses the mismatch |
| malformed | well-formed, `>= MODERN-MIN` | modern | `S4` refuses the malformed header |
| malformed | absent or pre-2026 | legacy | none |

A request declaring a pre-2026 version in `H` (as 2025-06-18 and 2025-11-25 require) stays legacy-era.

Non-`POST` under `both`: there is no body, so only `H` counts.

A client-sent JSON-RPC *response* object (02 section 2 item 3) has no `method`, no `params` and therefore no `M`: it is classified by the same rule with `H` as its only mirror. It is not modern merely because it is a response object; when both mirrors are absent it is legacy-era like any other request, and in that case it is forwarded with its headers untouched (`S12` applies only in the modern era).

Legacy era: 01 and 02 apply byte-identically to 0.1.x. **No rule of section 5 runs — not even `S1`** — so a legacy-era request reaches the wrapped handler with its headers untouched, whatever their syntax, and `Mcp-Session-Id` and `Last-Event-ID` stay in place. This is the compatibility guarantee for 2025-11-25 and 2025-06-18 clients.

This rule supersedes `docs/design/mcp-2026-07-28.md` section 4.1 item 2, which required `MCP-Protocol-Version` to be present *and* equal to the `_meta` version before a request counted as modern. Under that rule, stripping one unsigned header moved a modern request to legacy handling; under this rule the era comes from either signed-or-unsigned signal and any disagreement is a signed `400 -32020`.

## 4. Value encoding

The rules of this section are used by both sides: `C3` is the encoder, `C4` the shared decoder (`S6` uses it).

Text conversion (type to header text):

| JSON type | Text |
|---|---|
| `string` | as-is |
| `integer` | decimal without `+`, without leading zeros, without fraction (`0`, `42`, `-7`) |
| `boolean` | lowercase `true` / `false` |

`C3` — the sentinel is needed iff the value is not the empty string and at least one holds:

- it contains a character outside 0x20-0x7E;
- its first or last character is SP;
- it begins with `=?base64?` and ends with `?=`.

So HTAB, every control character, DEL and every non-ASCII character are encoded, and so is a plain value that would otherwise be indistinguishable from a sentinel.

Result:

- When the sentinel is not needed, the header value is the text itself; the empty string produces an empty header value.
- Otherwise the header value is `=?base64?` + standard base64 of the UTF-8 bytes + `?=`.

When the sentinel is needed:

| Value | Sentinel needed | Because |
|---|---|---|
| `us-west1` | no | plain ASCII, no edge space |
| `Hello, 世界` | yes | non-ASCII |
| ` padded ` | yes | leading and trailing SP |
| `line1\nline2` | yes | LF is outside 0x20-0x7E |
| `a\tb` | yes | HTAB is outside 0x20-0x7E |
| `=?base64?literal?=` | yes | matches the sentinel pattern |
| empty string | no | produces an empty header value |
| `=?BASE64?SGVsbG8=?=` | no | the marker case differs, so it is not a sentinel |

Examples (exact):

| Value | Reason | Header value |
|---|---|---|
| `us-west1` | plain ASCII | `us-west1` |
| `Hello, 世界` | non-ASCII | `=?base64?SGVsbG8sIOS4lueVjA==?=` |
| ` padded ` | leading/trailing space | `=?base64?IHBhZGRlZCA=?=` |
| `line1\nline2` | newline | `=?base64?bGluZTEKbGluZTI=?=` |
| `=?base64?literal?=` | matches the sentinel pattern | `=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=` |

`C4` — decode:

- A value is a sentinel iff it begins with `=?base64?` and ends with `?=`.
- Otherwise it is plain and its text is the value itself; marker case matters, so `=?BASE64?SGVsbG8=?=` is plain.
- A sentinel's inner text MUST be canonical standard base64 as in section 2, and its bytes MUST be valid UTF-8 (RFC 3629: no overlong form, no encoded surrogate, no truncated sequence).
- Otherwise it is not decodable at all.
- An empty inner text decodes to the empty string.

Tolerance: a sender SHOULD use the plain form when section 4 allows it; a receiver compares decoded texts and MUST accept a sentinel form of any value whose decoded text matches.

## 5. Server rules

These rules run after 01 section 4 steps 1-8 (authenticated, nonce recorded) and after 02 section 2 (body classification, unchanged and era-neutral; its `400 invalid_request`, `403 operation_denied`, `403 admin_required` and `501 streaming_unsupported` refusals keep the 01 section 4 body shape `{"error":{"code":...,"message":...}}`).

The era decision (`S3`, section 3) runs first. Every other rule of this section runs **only in the modern era**, in the order of the table below, and the first failure decides. A request that `S3` classifies as legacy-era is forwarded untouched: no rule here, `S1` included, may refuse it.

| Rule | Scope |
|---|---|
| `S3` | After authentication, before every other rule |
| `S1` | Modern era, every request |
| `S2` | Modern era |
| `S4` | Modern era, request or notification |
| `S5` | Modern era |
| `S6` | Modern era |
| `S7` | Modern era |
| `S8` | Modern era, every request |
| `S9` | Modern era |
| `S10` | Refusals of `S1`, `S2`, `S4`, `S5`, `S6` |
| `S11` | Modern era, notifications |
| `S12` | Modern era, client-sent response objects |

| # | Rule | Check | HTTP | JSON-RPC code | Reason tokens |
|---|---|---|---|---|---|
| 1 | `S3` | Era decision | — | — | — |
| 2 | `S1` | Header syntax | 400 | -32020 | `header_value_invalid`, `header_repeated` |
| 3 | `S2` | Method | 405 | -32600 | `method_not_allowed` |
| 4 | `S4` | Version mirror | 400 | -32020 | `version_header_missing`, `version_header_malformed`, `version_meta_missing`, `version_mismatch` |
| 5 | `S5` | `Mcp-Method` | 400 | -32020 | `method_header_missing`, `method_header_mismatch` |
| 6 | `S6` | `Mcp-Name` | 400 | -32020 | `name_header_not_applicable`, `name_source_missing`, `name_header_missing`, `name_header_bad_encoding`, `name_header_mismatch` |
| 7 | `S7` | `Mcp-Param-*` | forward | — | — |
| 8 | `S8` | Session headers | strip | — | — |
| 9 | `S9` | Forward | forward | — | — |

`S1` — header syntax (modern era).

- For `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name`: at most one instance per request.
- A second instance (name compared case-insensitively) is `header_repeated`.
- The value of those three and of every recognised `Mcp-Param-{Name}` header MUST satisfy the field-value syntax, otherwise `header_value_invalid`.
- A header named exactly `Mcp-Param-` has an empty `{Name}` and is therefore not a recognised parameter header: it is forwarded like any unknown header.

Rationale: a value outside the syntax cannot be validated at all, and Jack must never forward attacker-chosen raw bytes into the wrapped handler. This rule runs only in the modern era because a legacy-era request must stay byte-identical to 0.1.x, where these headers carry no meaning.

`S2` — method (modern era).

- A method other than `POST` gets `405` with `Allow: POST`, code `-32600`, reason `method_not_allowed`, and `id` `null` (a non-`POST` request carries no JSON-RPC id); the response is signed per `S10`.
- In the legacy era 02 section 2 item 1 is unchanged (`GET` accepted).

`S3` — era decision; it runs first, see section 3.

`S4` — version mirror (modern era, request or notification). In order:

| # | Condition | reason |
|---|---|---|
| 1 | Header absent | `version_header_missing` |
| 2 | Value is not a well-formed `version` | `version_header_malformed` |
| 3 | `params._meta["io.modelcontextprotocol/protocolVersion"]` absent or not a string | `version_meta_missing` |
| 4 | Values differ byte-wise | `version_mismatch` |

Row 1 applies to requests only; `S11` covers notifications.

Jack MUST NOT keep a list of supported protocol versions and MUST NOT answer `UnsupportedProtocolVersionError` itself: a well-formed version below `MODERN-MIN` under profile `modern` is forwarded and the wrapped handler answers `-32022`.
The core protocol answers `-32602` for a missing required `_meta` field; Jack answers `-32020` first because it validates the mirror before the handler sees the body.

`S5` — `Mcp-Method` (modern era).

- Absent → `method_header_missing`.
- Present and not byte-equal to the body `method` → `method_header_mismatch` (values case-sensitive: `Tools/Call` is a mismatch).

`S6` — `Mcp-Name` (modern era). Source field per method, exactly:

| Method | Source field |
|---|---|
| `tools/call` | `params.name` |
| `prompts/get` | `params.name` |
| `events/poll` | `params.name` |
| `events/stream` | `params.name` |
| `events/subscribe` | `params.name` |
| `events/unsubscribe` | `params.name` |
| `resources/read` | `params.uri` |
| every other method, including `events/list`, `server/discover`, `tools/list`, `subscriptions/listen` | none |

In order:

| # | Condition | reason |
|---|---|---|
| 1 | No source field and header present | `name_header_not_applicable` |
| 2 | Source field exists but the body value is absent or not a string | `name_source_missing` |
| 3 | Source field exists and header absent | `name_header_missing` |
| 4 | Value not decodable per `C4` | `name_header_bad_encoding` |
| 5 | Decoded text not byte-equal to the source string (no case folding, no Unicode normalization) | `name_header_mismatch` |

Jack MUST NOT accept `Mcp-Name` on a method without a source field: there is no body value it could mirror. A method in the table whose body value is missing or not a string is refused with `name_source_missing` rather than forwarded, because the mirror cannot be validated at all.

`S7` — `Mcp-Param-*` (modern era).

- Every `Mcp-Param-*` header is forwarded unchanged: name, value bytes, order and repetition preserved.
- Jack MUST NOT decode these values and MUST NOT compare them with `params.arguments`, because it does not know tool schemas.
- The wrapped handler validates them against the tool's `inputSchema` and answers `-32020` itself; its refusal is signed like any response and the nonce is already consumed.
- A missing `Mcp-Param-*` for an annotated argument present in the body is therefore the handler's `-32020`, not Jack's.
- An intermediary that does not recognize such a header MUST forward it (RFC 9110).

`S8` — session headers (modern era).

- Every `Mcp-Session-Id` and `Last-Event-ID` header is removed before the wrapped handler sees the request; names compared case-insensitively, all instances removed.
- Jack never mints or echoes a session id.
- In the legacy era both are left untouched (2025-11-25 sessions keep working).

`S9` — forwarding (modern era).

- The handler receives the exact verified body bytes, the original method and target, and the original header list in original order minus the `S8` removals.
- Nothing else is added, removed or rewritten; header names keep their received casing.

`S10` — refusal shape.

- Every refusal of `S1`, `S2`, `S4`, `S5` and `S6` is signed with the v1 response signature of 01 section 5, so the client verifies it exactly like any normal response.
- The response carries `Content-Type: application/json` and one JSON-RPC error object with exactly these members: `{"jsonrpc":"2.0","id":<id>,"error":{"code":<code>,"message":"<message>"}}`.
- `<id>` is the request's `id` when the body is an acceptable JSON-RPC request object with a string or integer `id`, and `null` otherwise (always `null` for a non-`POST` request). The refusal never omits `id`.
- `<code>` and `<message>` are the fixed values of section 5.1; `<message>` MUST NOT echo any header or body value, so a refusal is not an oracle.
- JSON member order and insignificant whitespace are implementation-defined, because the signature covers whatever bytes an implementation sends.
- Every refusal here consumes the request's nonce (01 section 4 step 8 already recorded it; there is no rollback), exactly as 02 section 2 requires of every post-authentication refusal.
- Contrast the pre-authentication refusals of 01 section 4: unsigned, `{"error":{...}}` envelope. A signed JSON-RPC error with `jsonrpc` and `error.message` is what a client uses to recognise the modern era (`C9`); a bare `{"error":{"code":...}}` object is not.

`S11` — notifications (body with `method`, no `id`).

- The revision defines no header requirements for notification `POST`s, so in the modern era Jack requires no mirror header on a notification.
- A mirror header that is present is validated exactly as for a request, and a present `MCP-Protocol-Version` makes the `_meta` version required and equal.
- `S1` and `S8` apply to a notification in the modern era like to any other request.

`S12` — client-sent response objects: no mirror obligation; forwarded after `S1` and `S8`.

### 5.1 Reason table

Messages are verbatim and carry no trailing period.

| reason | HTTP | JSON-RPC code | message |
|---|---|---|---|
| `method_not_allowed` | 405 | -32600 | `HTTP method not allowed` |
| `header_value_invalid` | 400 | -32020 | `Header mismatch: a request metadata header value contains a character outside the HTTP field-value syntax` |
| `header_repeated` | 400 | -32020 | `Header mismatch: a request metadata header appears more than once` |
| `version_header_missing` | 400 | -32020 | `Header mismatch: MCP-Protocol-Version is missing` |
| `version_header_malformed` | 400 | -32020 | `Header mismatch: MCP-Protocol-Version is malformed` |
| `version_meta_missing` | 400 | -32020 | `Header mismatch: params._meta protocolVersion is missing` |
| `version_mismatch` | 400 | -32020 | `Header mismatch: MCP-Protocol-Version does not match params._meta protocolVersion` |
| `method_header_missing` | 400 | -32020 | `Header mismatch: Mcp-Method is missing` |
| `method_header_mismatch` | 400 | -32020 | `Header mismatch: Mcp-Method does not match the body method` |
| `name_header_not_applicable` | 400 | -32020 | `Header mismatch: Mcp-Name is not defined for this method` |
| `name_source_missing` | 400 | -32020 | `Header mismatch: the body has no string value for the Mcp-Name source field` |
| `name_header_missing` | 400 | -32020 | `Header mismatch: Mcp-Name is missing` |
| `name_header_bad_encoding` | 400 | -32020 | `Header mismatch: Mcp-Name is not a valid base64 sentinel encoding` |
| `name_header_mismatch` | 400 | -32020 | `Header mismatch: Mcp-Name does not match the body value` |

### 5.2 Handler-owned outcomes (*informative*)

Jack validates the mirrors and forwards the body; the wrapped handler owns everything below. They are listed so SDK authors know what a client sees, and they are not Jack refusals.

| Situation | Status | JSON-RPC code | Owner |
|---|---|---|---|
| Requested protocol version is not implemented | 400 | -32022 with `data.supported` and `data.requested` | handler |
| Requested RPC method is not implemented | 404 | -32601 | handler |
| A required `_meta` field is missing | 400 | -32602 | handler |
| A recognised `Mcp-Param-*` value disagrees with the body, or an annotated argument has no header | 400 | -32020 | handler |
| A resource does not exist | 200 | -32602 in the error body | handler |

## 6. Client rules

`C1` — `_meta`.

- Every request MUST carry `params._meta` with `io.modelcontextprotocol/protocolVersion` (the era's version string) and `io.modelcontextprotocol/clientCapabilities` (object; `{}` allowed).
- `io.modelcontextprotocol/clientInfo` SHOULD be present.
- A method that defines no other parameter still carries a `params` object holding `_meta`.
- `_meta` is never at the request root.

`C2` — headers.

- `MCP-Protocol-Version` carries the same version string.
- `Mcp-Method` carries the request's `method`.
- `Mcp-Name` is sent only for the `S6` methods, carrying the encoded source value.
- Emit in this order: `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, then one `Mcp-Param-{Name}` per valid annotation in `C6` order.
- Use the canonical spellings.

| Position | Header |
|---|---|
| 1 | `MCP-Protocol-Version` |
| 2 | `Mcp-Method` |
| 3 | `Mcp-Name`, only for an `S6` method |
| 4 and onward | one `Mcp-Param-{Name}` per valid annotation, in `C6` order |

`C3` value encoding and `C4` sentinel decoding: section 4.

`C5` — `x-mcp-header` validation, applied to every tool in a `tools/list` result on the Streamable HTTP transport.

- A definition with any violation is excluded from the result (not an error response; the other tools are unaffected) and the client SHOULD log the tool name and reason.
- Closed reason list, each mapped to its source constraint:

| reason | Source constraint |
|---|---|
| `annotation_name_not_string` | The value is not a JSON string. |
| `annotation_name_empty` | The value is the empty string. |
| `annotation_name_control` | The value contains a byte below 0x20 or 0x7F, including CR and LF. |
| `annotation_name_not_token` | The value fails `1*tchar` (RFC 9110 section 5.6.2); see the token set below. |
| `annotation_name_duplicate` | The value is case-insensitively equal to another `x-mcp-header` value in the same `inputSchema`. |
| `annotation_type_not_primitive` | The property's `type` is not exactly one of `string`, `integer`, `boolean`; a missing `type`, a `type` array, `number`, `object`, `array` and `null` are invalid. |
| `annotation_integer_range_invalid` | Type `integer` with `minimum` below -(2^53-1) or `maximum` above 2^53-1; absent bounds are valid because the runtime value is checked at projection time. |
| `annotation_not_statically_reachable` | The annotation is not on a property reachable from the schema root through `properties` member names alone: an annotation at the schema root, or one whose chain passes through `items`, `additionalProperties`, `patternProperties`, `contains`, `propertyNames`, `unevaluatedProperties`, `unevaluatedItems`, `dependentSchemas`, `not`, `if`/`then`/`else`, `oneOf`/`anyOf`/`allOf`, or a `$ref` target under `$defs`/`definitions`. |

The annotation is the `x-mcp-header` keyword of a property *schema*. A member whose name is literally `x-mcp-header` inside a name map (`properties`, `patternProperties`, `$defs`, `definitions`, `dependentSchemas`) is a property name, a pattern, a definition or a schema key, not an annotation. Property names MAY be empty: an empty `properties` key is legal and the annotation below it is reachable.

The `tchar` set is ``! # $ % & ' * + - . ^ _ ` | ~``, DIGIT and ALPHA.

- Chains of `properties` may be arbitrarily deep (`properties.a.properties.b` is valid).
- Validation is positional: where the annotation sits, not whether a value is reachable at run time.
- When one definition violates several constraints the tool is excluded either way and which token is reported is *informative*.
The same validation applies to an event type descriptor's `inputSchema` in an `events/list` result (`C11`).

`C6` — projection. For a tool that passed `C5`, for each annotation in depth-first document order of `properties` objects:

- Read the argument at the annotation's `properties` path; if any step is absent or the value is `null`, omit the header.
- Otherwise the value MUST match the annotated type (JSON string, JSON boolean, or a JSON number that is an integer within +/-(2^53-1)); if not, the client MUST NOT send the request and reports the client-side error `header_projection_invalid_value`.
- Encode per `C3` and add `Mcp-Param-{Name}`.

Projection never produces `Mcp-Name`, `Mcp-Method` or `MCP-Protocol-Version`.
Projection runs before signing; the body does not contain the headers.

The transport table, as a rule:

| Value in the arguments | Header |
|---|---|
| value present | the header MUST be included |
| value `null` or argument absent | the header MUST be omitted |

`C7` — native `jack.*` tools.

- In the modern era a native result is the 0.1.x result plus `resultType: "complete"` inside `result` and `result._meta["io.modelcontextprotocol/serverInfo"]` with Jack's implementation name and version.
- Arguments, error responses, audit records, admin gating and identity rules are unchanged.
- A legacy-era request gets a byte-identical result to 0.1.x: no `resultType`, no `_meta`.
- Jack adds `resultType` only in the modern era because a 2025-11-25 client does not expect it.
- Error responses carry no `resultType`.
- Jack MUST NOT change the shape of a forwarded result.

`C8` — `CacheableResult`.

- `ttlMs` and `cacheScope` are the wrapped server's hints.
- A Jack response is signed over the answering request's signature (01 section 5), so it is bound to exactly one request and cannot answer another.
- A client MAY cache a verified result privately, keyed by the exact request (method, params, era) and bounded by `ttlMs`.
- It MUST NOT use a shared cache or any HTTP cache, whatever `cacheScope` says, and MUST NOT serve a cached result to a different request, which would present a response bound to another request's signature.
- `ttlMs: 0` means the result MUST NOT be reused.

`C9` — era detection and fallback.

- A client configured `auto` sends its first modern request (a `server/discover` request makes this deterministic) and decides from the *verified* response (01 section 5), caching the era per origin (MAY persist it; re-probes if the cached assumption later fails).
- Decision table:

| Verified response | Era signal |
|---|---|
| 2xx | modern |
| `400` with a recognised modern JSON-RPC error (`-32020`, `-32021`, `-32022`) | modern |
| `400` with any other body, including a bare `{"error":{"code":...}}` object, an object without `jsonrpc`, an object without `error.message`, an array, a non-object, an empty body and any other code | legacy |
| `404` with a recognised JSON-RPC error `-32601` | modern; the server speaks the modern era but not that method |
| `404` without a recognised JSON-RPC error | legacy |
| `405` | legacy |
| any other status, unsigned, unverified or malformed response, network error | no signal; the operation fails |

- A **recognised JSON-RPC error** is a JSON object whose `jsonrpc` is exactly `"2.0"`, that has an `id` member (`null` allowed; the member must be present), and whose `error` is an object with an integer `code` and a string `message`. Anything else is not recognised: it neither selects an era nor proves a method missing. A bare `{"error":{"code":-32020}}` object is exactly the shape a legacy endpoint or an intermediary can produce, so it reads legacy.
- For `-32022` the `supported` list in `error.data` must be a non-empty array of strings that contains at least one version the client implements; the client then retries with those mutually implemented versions (`retry_with_supported`). Otherwise the outcome is `unsupported_version_no_overlap` and the operation fails.
- For a `400` that reads legacy the client falls back to `initialize` and stays legacy for that origin.
- Jack's own `{"error":{...}}` envelope is an object with no `jsonrpc` member whose `error.code` is a string, and it is never a modern-era signal. A body that does carry `jsonrpc: "2.0"` but whose `error.code` is not an integer is simply an unrecognised body and reads `no_modern_error`.

The outcome of a detection is one `{era, action, reason}` triple from this closed vocabulary; the vectors assert it verbatim:

| Outcome | `era` | `action` | `reason` |
|---|---|---|---|
| verified 2xx | `modern` | `stay_modern` | `null` |
| `400` with a recognised `-32020` or `-32021` | `modern` | `stay_modern` | `null` |
| `400` with a recognised `-32022` and a mutually implemented version | `modern` | `retry_with_supported` | `null`, plus `supported` |
| `400` with a recognised `-32022` and no mutual version | `modern` | `abort` | `unsupported_version_no_overlap` |
| `400` whose body is Jack's own envelope | `legacy` | `fallback_initialize` | `jack_envelope` |
| `400` with any other unrecognised body | `legacy` | `fallback_initialize` | `no_modern_error` |
| `404` with a recognised `-32601` | `modern` | `stay_modern` | `modern_method_not_found` |
| `404` without a recognised error | `legacy` | `fallback_initialize` | `no_modern_error` |
| `405` | `legacy` | `fallback_initialize` | `no_modern_error` |
| an unverified, unsigned or malformed response | `none` | `abort` | `unverified` |
| any other status, or a network error | `none` | `abort` | `no_era_signal` |

`C10` (SHOULD) — after a `-32020` refusal a client SHOULD fetch `tools/list` again, re-project and retry once, because the tool's `inputSchema` may have changed.

`C11` — event type descriptors. `x-mcp-header` annotations in an event type's `inputSchema` are validated exactly as in `C5` and projected exactly as in `C6`. An event type with a violation is excluded from the `events/list` result (the other types are unaffected, and the client SHOULD log the event name and reason); a valid one is projected for `events/poll`, `events/stream`, `events/subscribe` and `events/unsubscribe`, and for every `events/subscribe` refresh, from `params.arguments`.

`C12` (SHOULD) — after a `-32020` refusal for one of those methods the client SHOULD fetch `events/list` again, re-project and retry once, because the event type's `inputSchema` may have changed.

## 7. Security considerations (*informative*)

- **Headers are mirrors, not statements.** They are unsigned mirrors of a signed body, so they are validated not trusted, which is why a mismatch is a hard refusal rather than a repair: two components must never act on two different values, for example a load balancer routing on a tenant header while the handler executes another tenant's call.
- **Intermediary policy.** An intermediary that routes or rate-limits on `Mcp-Method`, `Mcp-Name` or `Mcp-Param-*` trusts client-chosen values, and its policy is only as good as the body check behind it, which is why the check must happen at the last hop the protocol controls.
- **The era decision is a fail-closed rule, not a policy knob.** Any modern signal selects the modern era, so a stripped header cannot downgrade a modern request, and an added one can only cause a refusal.
- **Sessions stay out.** Removing the session headers keeps a 2025-11-25 session mechanism out of a stateless revision.
- **Tool definitions are untrusted input.** `x-mcp-header` can promote a sensitive parameter into every intermediary's logs, so invalid definitions are dropped and servers SHOULD NOT annotate secrets.
- **No content oracle.** Fixed refusal messages prevent the refusal from becoming a content oracle.
- **No blind retry.** A `-32020` refusal is never retried blindly, because the header/body disagreement may be exactly what an attacker wants to preserve.

## 8. Conformance

Normative cases are four generated files:

| Case file | Family |
|---|---|
| `fixtures/modern/modern-request-vectors.json` | Request-level era, mirror, refusal-shape and by-reference cases |
| `fixtures/modern/header-encoding-vectors.json` | `C3` and `C4` value encoding |
| `fixtures/modern/x-mcp-header-vectors.json` | `C5`, `C6` and `C11` validation and projection |
| `fixtures/modern/era-detection-vectors.json` | `C9` era detection and fallback |

The generated case index is `tests/MODERN-HEADERS-CASES.md`.
The independent reference implementation under `tools/modern/headers/` (`reference.mjs`) recomputes every expected outcome in its `build()`.

Conventions of the family:

- Every request vector assumes an already authenticated request with a fixed clock and no nonce bookkeeping, because request authentication, nonce recording and legacy dispatch refusals are covered by `fixtures/request-vectors.json`.
- The family reuses the clock and audience constants of `tools/gen/core.mjs`.
- Every refusal expectation carries the full wire outcome: `signed`, `http_status`, `content_type`, `jsonrpc`, `id`, `error.code`, `error.message` and `consumes_nonce`. A vector that omits one of them is a defect in the generator, and the generator asserts the shape.

Every numbered rule is either covered by at least one vector or listed here with the SDK test that carries it (the generator and its tests enforce this partition):

| Rule | Why no vector | Carried by |
|---|---|---|
| `C7` | Native `jack.*` result shape is SDK behaviour in the merged 0.2.0 server | M1 per-SDK test `native_result_era_shape` |
| `C8` | Cache binding is the 01 section 5 `request-sig` binding, already vector-tested | `cache-replay` by-reference entry below and M1 test `client_cache_private_only` |
| `C10` | SHOULD-only retry flow | M1 test `client_header_resync` |
| `C12` | SHOULD-only events retry flow | M1 test `client_events_resync` |

The `modern-request-vectors.json` file also carries one **by-reference** entry, `cache-replay`, which records that a verified response bound to request A is rejected as the answer to request B by 01 section 5 (`request-sig`) and therefore cannot be served from a shared cache. It points at the existing cases `res-wrong-request-binding` and `res-accept` of `fixtures/response-vectors.json` instead of duplicating them.

A runner that disagrees with a vector disagrees with this document.
