# 02. Authorization

Status: draft v0.1. Normative unless marked *informative*.

mcp-jack wraps unmodified MCP, so it cannot know which tools a service exposes. After authentication has succeeded (step 9 of [01-authentication.md](01-authentication.md)) the protocol classifies the body, dispatches the reserved `jack.` tools, hands the verified caller identity to the wrapped MCP handler (section 3) and forwards everything else unchanged. There is no policy engine: what a caller may do inside MCP is decided by the consumers of the SDK from the verified identity (section 3). Authorization inside the protocol is only the `admin` flag (section 1, [03-user-management.md](03-user-management.md)).

## 1. Key registry

The server holds a registry of keys it trusts:

```json
{
  "version": 1,
  "aud": "https://svc.example.test",
  "keys": [
    {
      "kid": "<kid>",
      "public_key": "<base64url 32 bytes>",
      "name": "alice-laptop",
      "admin": true,
      "not_before": null,
      "not_after": null
    }
  ]
}
```

- A registry MUST be rejected at load time if: `version` is not 1 or the document or an entry has an unknown field; an entry's `public_key` fails the validity rules of 03 section 2; `kid` is not `base64url(SHA-256(public_key))`; `name` is invalid (03 section 1); two entries share a `kid` or a `name`; `admin` is present and is not a strict JSON boolean (`true` or `false`); an entry contains `kind` or `scopes` (legacy rejection: the load MUST fail with an error that names the offending member); or `not_before` / `not_after` is not a non-negative integer or `null`, or `not_before >= not_after`.
- `admin` is optional in documents and arguments and defaults to `false`. In every result it is always present, `false` included. One strict boolean: it gates exactly the `jack.admin.*` tools ([03-user-management.md](03-user-management.md) section 3.3) and nothing else. Ordinary MCP traffic is never gated by it.
- `not_before` / `not_after` are Unix seconds or `null`. A key is active when `not_before <= now < not_after` (`not_after` is exclusive; `null` means unbounded).
- `name` is a label, unique across the registry, used in audit records.
- Revocation is removal of the entry (or a past `not_after`). Rotation is adding the new key before removing the old one.
- Users and keys are created, changed and revoked through the protocol itself; see [03-user-management.md](03-user-management.md).

## 2. Evaluation and dispatch

After authentication succeeds:

1. An HTTP `GET` carries no JSON-RPC and is accepted (it opens a stream or fetches a resource). HTTP methods other than `GET` and `POST` are not defined by v0.1; a server SHOULD answer them with `405`.
2. For `POST` the body MUST be a single UTF-8 JSON-RPC 2.0 object, otherwise `400 invalid_request`. That covers: invalid UTF-8 (RFC 3629: overlong encodings, encodings of surrogate code points and truncated multibyte sequences are invalid before any JSON parsing), non-JSON, a non-object (including a batch array), a missing or wrong `jsonrpc` member, and an empty body. The object is one of:
   - a request or notification: a string `method`;
   - a response (the client answering a server-initiated request): no `method`, an `id`, and exactly one of `result` or `error`.
3. A response object passes; authentication alone authorizes it.
4. For a request or notification:
   - if `method` is `tools/call`, `params.name` MUST be a string, otherwise `400 invalid_request`;
   - a name with the `jack.` prefix goes to the protocol layer (see 03): a defined tool is handled there, with the admin tools gated by `admin` (`403 admin_required`, 03 section 7); an undefined `jack.`-prefixed name is `403 operation_denied`;
   - everything else — ordinary MCP methods and tools, including `tools/list`, `ping`, `notifications/*` and `resources/*` — is forwarded to the wrapped MCP handler unchanged: the protocol neither filters nor denies it, for any authenticated caller. There is no `tools/list` filtering.
5. In v0.1 the wrapper refuses event streams: a server MUST NOT relay a `text/event-stream` response from the wrapped handler; it answers instead with the signed `501 streaming_unsupported`. (Replaced by the v0.2 session channel, open question Q1 of [README.md](README.md).)

**Duplicate members.** Within one JSON object of the body, a member name MAY occur more than once. The object then has exactly one member per distinct name, and that member's value is the value of the **last** occurrence in document order; the occurrences are not merged, so a member that only an earlier occurrence carried is lost. Names are compared after unescaping (`"m\u0065thod"` and `"method"` are the same name). Resolution is per object: a duplicate inside `params` never changes an object nested within it, and the other way around. This rule applies to the body and, through it, to `params` and `params.arguments` (03 section 3); it does not apply to the registry document of section 1 or to the state file (03 section 10), whose loaders are operator-facing and have their own rules. Authentication is unaffected: the signature covers the exact request bytes (01 section 3.1), so a body with duplicate members is verified exactly as sent, never as parsed and re-serialized.

Every rejection at or after this step that passed authentication consumes the request's nonce.

| Status | `code` | Meaning |
|---|---|---|
| 400 | `invalid_request` | The body is not an acceptable JSON-RPC object, or `params.name` is not a string. |
| 403 | `operation_denied` | An undefined `jack.`-prefixed tool name. |
| 501 | `streaming_unsupported` | The wrapped handler produced a `text/event-stream` response. |

`403 admin_required` (03 section 7) is also produced at this step, for the admin tools.

Rejections use the JSON body defined in 01-authentication section 4.

## 3. Verified caller identity

After authentication (01 steps 1-8) succeeds and the body is classified and dispatched, the server SDK MUST pass the **verified caller identity** of the caller to the wrapped MCP handler. The identity is `{kid, name, admin}`: exactly the values of the caller's registry entry at verification time, the same snapshot authentication and the admin gate used.

- **Server-authenticated.** The identity is derived exclusively from the verification procedure and the server's registry. It MUST NOT be read from, influenced by, or overridable through any request-supplied header, query parameter, or body member.
- **Immutable to consumers.** The identity is a read-only snapshot. The SDK MUST NOT provide any public constructor, setter, or header/body mechanism by which handler code could fabricate or alter an identity that the SDK or other handlers would treat as verified.
- **Snapshot lifecycle.** Registry changes (revoke, `set_admin`, rotate, enroll) take effect for subsequent requests; an in-flight handler keeps its snapshot.
- **Not an authorization decision.** Identity is data, not a decision: the protocol performs no MCP access control; consumers implement their own rules from this identity. `admin` is included so consumers can mirror protocol-privileged callers in their own rules, but the protocol enforces nothing beyond the admin gate on `jack.admin.*`.
- **Availability.** The identity is available for every accepted request that reaches the wrapped handler (ordinary MCP on `POST`; `GET` where a handler runs). Native `jack.*` calls never reach the wrapped handler, so no identity is handed off for them.

*Informative* — per-language placement: Go, a value type in the request context under an unexported key with an SDK accessor; Rust, a typed request extension inserted by the tower layer; TypeScript, SDK-private request-associated storage exposed only through a read accessor returning a frozen snapshot; no writable identity symbol or setter is exported. The invariants above are normative for all three.

## 4. Out of scope for v0.1

- MCP access rules and rate limits.
- Matching on resource URIs and prompt names.
- Per-argument conditions.
- Delegation: a user issuing short-lived, narrower credentials to another key. It is not a protocol feature.
- Human approval flows and two-step changes for destructive operations.

Scopes, user kinds and the policy engine are removed from the protocol, not postponed; there is no plan to bring them back.
