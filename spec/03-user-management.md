# 03. User management

Status: draft v0.1. Normative unless marked *informative*.

Users and their keys are managed through the protocol itself, as MCP tools, so that administrators, SDK clients and agents all use the same authenticated channel. Whoever generates a key pair, the server only ever receives the public key.

Tools in this document are **protocol-native**: their names start with `jack.`, they are handled by the mcp-jack layer and never reach the authorization policy ([02-authorization.md](02-authorization.md) section 3.1). A `jack.`-prefixed tool name that is not defined here is `403 operation_denied`.

## 1. Model

- A **user** is one registry entry: one public key plus a `name`, a `kind`, scopes and an optional validity interval. There is no separate account object in v0.1.
- `name` is a label unique across the registry, 1-64 characters from `[A-Za-z0-9._-]`.
- `kind` is `"human"` (default) or `"agent"`. An `agent` key MUST NOT hold the `admin` scope (section 6).
- A key holds scopes as defined in 02. The scope `admin` authorizes the `jack.admin.*` tools and nothing else.
- An **invite** is a single-use, expiring permission to enroll one key with a fixed set of scopes.

Registry entry fields: `kid`, `public_key`, `name`, `kind`, `scopes`, `not_before`, `not_after`.

## 2. Public-key validity

Before a public key is stored (enrollment, `jack.admin.user.create`, `jack.key.rotate`) and when a registry is loaded, a server MUST verify that it is exactly 32 bytes, a **canonical** encoding (the y coordinate is below 2^255 - 19), decodes to a point on the curve, and lies in the **prime-order subgroup** and is not the identity. This rejects small-order, mixed-order and non-canonical keys, for which a signature can verify for more than one message or key. A key that fails is `400 key_rejected`.

## 3. Tools

All arguments are in `params.arguments`. A tool result is an MCP `CallToolResult` whose `structuredContent` holds the object described below and `isError` is `false`. An argument that is missing, of the wrong type, or outside its stated range is `400 invalid_params`. Errors use the rejection body from 01-authentication section 4, with the codes in section 7.

### 3.1 Self-service (any active key, no scope)

| Tool | Arguments | Result |
|---|---|---|
| `jack.whoami` | none | `{kid, name, kind, scopes, not_before, not_after}` of the caller |
| `jack.key.rotate` | `public_key`, `proof` | `{kid}` of the new key |

`jack.key.rotate` replaces the caller's key with a new one, keeping `name`, `kind`, `scopes`, `not_before` and `not_after`. The request is signed by the old key as usual. `proof` is `base64url(Ed25519_sign(new_private_key, S))` where S is these lines joined with LF, without a trailing LF:

```
mcp-jack/v1/rotate
<aud>
<old kid>
<new kid>
<ts>
```

`ts` is the `ts` parameter of the request's `Jack-Auth` header. A wrong proof is `400 invalid_proof`; a new key that is already registered is `409 key_exists`. On success the old key is removed immediately.

### 3.2 Enrollment

`jack.enroll` is called by a holder of an invite whose key is not yet registered.

| Argument | Meaning |
|---|---|
| `code` | The invite code. |
| `name` | The name for the new entry. |
| `public_key` | The new public key, base64url. |

The request is signed by the **new key** and carries `kid` = `base64url(SHA-256(public_key))`; that signature is the proof of possession. This is the **only** operation for which an unknown `kid` is not rejected at step 4 of 01-authentication section 4. The server MUST process it in this order and stop at the first failure:

1. Steps 1-3 of 01 (header present, well formed, version).
2. Step 4 exception: if `kid` is not in the registry and the request is a `POST` `tools/call` of `jack.enroll` with a valid JSON-RPC body, take `public_key` from the arguments. Otherwise `401 unknown_key`.
3. The public key passes section 2 (`400 key_rejected`) and `kid` equals its hash (`401 unknown_key`).
4. Steps 6-8 of 01 (time window, signature verified with the **submitted** key, nonce recording).
5. The invite exists, has not expired, has not been used and has not been revoked: otherwise `403 invalid_invite`. All four cases return the same code.
6. `name` is valid and unused (`409 name_taken`); `kid` is not registered (`409 key_exists`).
7. Atomically: mark the invite used, add the entry with the invite's scopes, `kind` and `not_after`, `not_before` null. Result: `{kid, name, kind, scopes}`.

A request with an already registered `kid` takes the normal path; `jack.enroll` from a registered key is `409 key_exists`.

### 3.3 Administration (scope `admin`)

A key without `admin` is `403 insufficient_scope`.

| Tool | Arguments | Result |
|---|---|---|
| `jack.admin.user.list` | none | `{users: [entry, ...]}` |
| `jack.admin.user.get` | `kid` | an entry; `404 unknown_target` if absent |
| `jack.admin.user.create` | `name`, `public_key`, `scopes`, optional `kind`, `not_before`, `not_after` | `{kid}` |
| `jack.admin.user.set_scopes` | `kid`, `scopes` | the updated entry |
| `jack.admin.user.revoke` | `kid` | `{kid}` |
| `jack.admin.invite.create` | `scopes`, optional `kind`, `ttl_seconds`, `key_ttl_seconds` | `{invite_id, code, expires_at}` |
| `jack.admin.invite.list` | none | `{invites: [{invite_id, scopes, kind, created_by, created_at, expires_at}, ...]}` |
| `jack.admin.invite.revoke` | `invite_id` | `{invite_id}` |

An *entry* is `{kid, public_key, name, kind, scopes, not_before, not_after}`.

`jack.admin.user.create` is for the case where an administrator is given a public key; the private key never reaches the server.

Invites:

- `ttl_seconds` is an integer 1..604800, default 3600. `key_ttl_seconds`, if present, sets the enrolled key's `not_after` to the enrollment time plus that many seconds.
- `code` is 32 bytes from a CSPRNG, base64url. It is returned **once**, by `invite.create`, and never again.
- The server stores only `invite_id` = `base64url(SHA-256(code))`; `invite_id` is also how an invite is listed and revoked. A server MUST NOT log or persist `code`.
- An invite is single-use. Expired and used invites are not listed.

## 4. Administration rules

Evaluated after the `admin` scope check, in this order:

1. **No escalation.** Every scope that an operation adds (in `scopes` of `invite.create`, `user.create`, `user.set_scopes`) MUST be held by the caller, otherwise `403 scope_escalation`.
2. **Agent keys.** A key with `kind` `agent` MUST NOT be given `admin`, by any tool: `403 agent_admin_forbidden`.
3. **Protected targets.** An administrator MUST NOT modify or revoke an entry that holds a scope the administrator lacks: `403 forbidden_admin_target`. Removal of one's own entry is allowed subject to rule 4.
4. **Last administrator.** An operation that would leave no active entry holding `admin` (revoking or demoting the last one) is `409 last_admin`. "Active" means within `not_before` / `not_after` at the time of the operation.

Rule 1 applies per scope; a caller that holds `read` and `admin` can grant `read` and `admin` but not `lifecycle`.

## 5. Bootstrap

A server that has no `admin` key cannot be administered through the protocol. The first administrator is created out of band: the server SDK MUST provide a local operation (not reachable over the network, and not an MCP tool) that creates one invite with the `admin` scope (and `kind` `human`) and returns its code to the local operator. There MUST be no default credential and no built-in key.

## 6. Agents and the admin scope

An agent that reads untrusted content (logs, web pages, documents) can be steered into asking for privileged operations. For that reason:

- `agent` keys cannot hold `admin` (rule 2). A deployment SHOULD register automation as `agent` keys and keep human keys, ideally in a hardware-backed or confirmed signer, for administration.
- Signer agents SHOULD require human confirmation for `jack.admin.*` calls.

## 7. Error codes

| HTTP | `code` | Meaning |
|---|---|---|
| 400 | `invalid_params` | Missing, mistyped or out-of-range tool arguments. |
| 400 | `key_rejected` | Public key fails section 2. |
| 400 | `invalid_proof` | `jack.key.rotate` proof does not verify. |
| 403 | `invalid_invite` | The invite is unknown, expired, used or revoked. |
| 403 | `scope_escalation` | The operation would grant a scope the caller does not hold. |
| 403 | `agent_admin_forbidden` | `admin` requested for an `agent` key. |
| 403 | `forbidden_admin_target` | The target holds a scope the caller lacks. |
| 403 | `insufficient_scope` | The caller lacks `admin`. |
| 404 | `unknown_target` | `kid` or `invite_id` is not registered. |
| 409 | `name_taken` | The name is already used. |
| 409 | `key_exists` | The key is already registered. |
| 409 | `last_admin` | The operation would leave no active administrator. |

## 8. Audit

A server MUST record an audit event for every `jack.admin.*`, `jack.enroll` and `jack.key.rotate` call, successful or not, with: time, caller `kid` and `name` (or the submitted `kid` for enrollment), tool, target (`kid`, `invite_id` or name), outcome and, on failure, the `code`. Events MUST NOT contain invite codes or private keys. The destination (file, syslog, external sink) is implementation-defined.

## 9. Atomicity

The registry changes in this document (adding, changing or removing an entry, consuming an invite) MUST be atomic and take effect for the next request. Concurrent invocations that would each satisfy rule 4 individually but together violate it MUST be serialized so that the invariant holds.
