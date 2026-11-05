# 02. Authorization

Status: draft v0.1. Normative unless marked *informative*.

mcp-jack wraps unmodified MCP, so it cannot know which tools a service exposes. Authorization is therefore a **server-configured policy** that maps MCP operations to scopes. It runs after authentication has succeeded (step 9 of [01-authentication.md](01-authentication.md)) and is deny-by-default.

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
      "kind": "human",
      "scopes": ["read"],
      "not_before": null,
      "not_after": null
    }
  ]
}
```

- A registry MUST be rejected at load time if: `version` is not 1 or the document or an entry has an unknown field; an entry's `public_key` fails the validity rules of 03 section 2; `kid` is not `base64url(SHA-256(public_key))`; `name` is invalid (03 section 1); two entries share a `kid` or a `name`; `kind` is neither `human` nor `agent`; `scopes` is not an array of distinct valid scopes; an `agent` entry holds `admin`; or `not_before` / `not_after` is not a non-negative integer or `null`, or `not_before >= not_after`.
- `not_before` / `not_after` are Unix seconds or `null`. A key is active when `not_before <= now < not_after` (`not_after` is exclusive; `null` means unbounded).
- `name` is a label, unique across the registry, used in audit records.
- `kind` is `"human"` (default) or `"agent"`; an `agent` key cannot hold `admin` (see 03).
- `scopes` lists the scopes the key holds. Revocation is removal of the entry (or a past `not_after`). Rotation is adding the new key before removing the old one.
- Users and keys are created, changed and revoked through the protocol itself; see [03-user-management.md](03-user-management.md).

## 2. Scopes

A scope is a string matching `^[a-z][a-z0-9_]*(:[a-z0-9_]+)*$` (for example `read`, `config:write`, `lifecycle`).

- Scopes are **flat**: holding one scope never implies another.
- `admin` is reserved for the user-management tools of the protocol (see 03). Policy rules cannot grant it.
- Which other scopes exist, and what they protect, is up to the deployment's policy.

## 3. Policy

The policy is a document owned by the server operator:

```json
{
  "version": 1,
  "rules": [
    { "match": { "method": "ping" }, "scope": null },
    { "match": { "method": "tools/list" }, "scope": null },
    { "match": { "method": "tools/call", "tool": "svc.config.set" }, "scope": "config:write" },
    { "match": { "method": "tools/call", "tool": "svc.*" }, "scope": "read" }
  ]
}
```

Rule fields:

| Field | Meaning |
|---|---|
| `match.method` | An MCP method name, exact or a pattern (below). |
| `match.tool` | Only with `method` equal to `tools/call`: the tool name, exact or a pattern. Omitted means any tool. |
| `scope` | The scope the key must hold, or `null` for "any authenticated key". |
| `effect` | Optional. `"allow"` (default) or `"deny"`. A `deny` rule has no `scope` and rejects the operation for every key. |

Patterns: `*` matches zero or more characters of any kind; every other character matches itself, case-sensitively. There are no other metacharacters.

Evaluation is **first match wins**, in document order, so exceptions go before the general rule. If no rule matches, the operation is denied.

A policy MUST be rejected at load time if: the document has a `version` other than 1 or an unknown field; a rule has an unknown field (in the rule or in `match`); `match.method` is missing or empty; `match.tool` is empty or present with a `method` that is not exactly `tools/call`; `effect` is neither `allow` nor `deny`; a `deny` rule has a `scope`; an `allow` rule has no `scope` (use `null` for "any authenticated key"); a `scope` is malformed; or a `scope` is `admin`, which only the protocol-native tools may require.

### 3.1 Protocol-native tools

Tool names beginning with `jack.` belong to the protocol (see 03). Requests for them are dispatched to the protocol layer and **never reach the policy**, so a policy can neither open nor close them. A server SHOULD warn at load time when a pattern could match a `jack.`-prefixed name.

## 4. Evaluation

After authentication succeeds:

1. An HTTP `GET` carries no JSON-RPC and is accepted (it opens a stream or fetches a resource; individual streams are scoped when they are defined). HTTP methods other than `GET` and `POST` are not defined by v0.1; a server SHOULD answer them with `405`.
2. For `POST` the body MUST be a single UTF-8 JSON-RPC 2.0 object, otherwise `400 invalid_request`. That covers: invalid UTF-8, non-JSON, a non-object (including a batch array), a missing or wrong `jsonrpc` member, and an empty body. UTF-8 is RFC 3629: overlong encodings, encodings of surrogate code points and truncated multibyte sequences are invalid before any JSON parsing. The object is one of:
   - a request or notification: a string `method`;
   - a response (the client answering a server-initiated request): no `method`, an `id`, and exactly one of `result` or `error`.
3. A response object is authorized by authentication alone.
4. For a request or notification:
   - if `method` is `tools/call`, `params.name` MUST be a string, otherwise `400 invalid_request`; a name with the `jack.` prefix goes to the protocol layer (see 03);
   - the policy is evaluated for `(method, tool)`; no matching rule or a matching `deny` rule is `403 operation_denied`;
   - a rule with a `scope` that the key does not hold is `403 insufficient_scope`;
   - otherwise the operation is authorized.
5. `tools/list` results SHOULD be filtered to the tools whose matching rule the calling key satisfies, plus the `jack.` tools the key may call.

Every authorization rejection still counts as having consumed the request's nonce.

| Status | `code` | Meaning |
|---|---|---|
| 400 | `invalid_request` | The body is not an acceptable JSON-RPC object, or `params.name` is not a string. |
| 403 | `operation_denied` | No rule allows the operation, or a `deny` rule matched. |
| 403 | `insufficient_scope` | A rule matched but the key lacks its scope. |

Rejections use the JSON body defined in 01-authentication section 4.

## 5. Out of scope for v0.1

- Matching on resource URIs and prompt names (the policy currently matches methods and tool names only).
- Per-argument conditions.
- Delegation: a human key issuing short-lived, narrower credentials to an agent key.
- Human approval and two-step changes for destructive operations.
