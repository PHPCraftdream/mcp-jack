# 02. Authorization

Status: draft v0.1. Normative unless marked *informative*.

Authorization runs after authentication has succeeded (step 9 of [01-authentication.md](01-authentication.md)). It is deny-by-default.

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
      "scopes": ["read"],
      "not_before": null,
      "not_after": null
    }
  ]
}
```

- `kid` MUST equal `base64url(SHA-256(public_key))`; a registry entry where it does not MUST be rejected at load time.
- `not_before` / `not_after` are Unix seconds or `null`. A key is active when `not_before <= now < not_after` (`not_after` is exclusive; `null` means unbounded).
- `name` is a free-form label used in audit records.
- Revocation is removal of the entry (or a past `not_after`). Rotation is adding the new key before removing the old one.

How the registry is distributed and reloaded is outside v0.1 (open question Q4).

## 2. Scopes

| Scope | Meaning |
|---|---|
| `read` | Observe: status, logs, metrics, read and validate configuration. |
| `config:write` | Change configuration. |
| `lifecycle` | `reload` and `restart`. |

Scopes are **not hierarchical**: `config:write` does not imply `read`, and `lifecycle` implies nothing. A key that needs several capabilities lists several scopes.

## 3. Operations and required scopes

Required scope per MCP tool (`tools/call`, selected by `params.name`):

| Tool | Scope |
|---|---|
| `jack.status` | `read` |
| `jack.logs.query` | `read` |
| `jack.metrics.get` | `read` |
| `jack.config.get` | `read` |
| `jack.config.validate` | `read` |
| `jack.config.set` | `config:write` |
| `jack.reload` | `lifecycle` |
| `jack.restart` | `lifecycle` |

MCP methods that need authentication only (any active key): `tools/list`, `ping`. A server SHOULD filter the `tools/list` result to the tools whose scope the calling key holds.

The tool names and their argument schemas are defined in a later document; this table fixes only the scope mapping.

## 4. Evaluation

After authentication succeeds:

1. A `GET` request carries no JSON-RPC and is accepted (it opens a stream or fetches a resource; individual streams are scoped when they are defined).
2. For any other method, the body MUST be one JSON-RPC 2.0 object, valid UTF-8. A non-JSON body, a non-object (including a batch array), an object without `"jsonrpc": "2.0"` and a string `method`, or an empty body is rejected: `400 invalid_request`.
3. If `method` is `tools/call`:
   - `params.name` MUST be a string, otherwise `400 invalid_request`;
   - the name is looked up as an **own** key of the tool table (names such as `__proto__` or `constructor` are not tools); a name that is not in the table is `403 unmapped_operation`;
   - if the key's `scopes` does not contain the required scope: `403 insufficient_scope`.
4. If `method` is in the authentication-only set, the request is authorized.
5. Any other method is `403 unmapped_operation`.

Rejections use the same JSON body as in 01-authentication section 4. Every authorization rejection still counts as having consumed the request's nonce.

## 5. Out of scope for v0.1

- Delegation: a human key issuing short-lived, narrower credentials to an agent key (planned as short-lived certificates signed by a registry key).
- Per-resource scopes (for example per-service or per-file).
- Human approval and two-step changes (`config.validate`, then `config.set` with confirmation).
