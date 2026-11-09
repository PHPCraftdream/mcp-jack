# 03. User management

Status: draft v0.1. Normative unless marked *informative*.

Users and their keys are managed through the protocol itself, as MCP tools, so that administrators, SDK clients and agents all use the same authenticated channel. Whoever generates a key pair, the server only ever receives the public key.

Tools in this document are **protocol-native**: their names start with `jack.`, they are handled by the mcp-jack layer and never reach the wrapped MCP handler ([02-authorization.md](02-authorization.md) section 2). A `jack.`-prefixed tool name that is not defined here is `403 operation_denied`.

## 1. Model

- A **user** is one registry entry: `{kid, public_key, name, admin, not_before, not_after}`. There is no separate account object in v0.1.
- `name` is a label unique across the registry, 1-64 characters from `[A-Za-z0-9._-]`.
- `admin` is a single flag: a strict JSON boolean (`true` or `false`), optional in documents and arguments with default `false`, always present in results. It authorizes the `jack.admin.*` tools and nothing else.
- An **invite** is a single-use, expiring permission to enroll one key with the invite's fixed `admin` flag.

## 2. Public-key validity

Before a public key is stored (enrollment, `jack.admin.user.create`, `jack.key.rotate`) and when a registry is loaded, a server MUST verify that it is exactly 32 bytes, a **canonical** encoding (the y coordinate is below 2^255 - 19), decodes to a point on the curve, and lies in the **prime-order subgroup** and is not the identity. This rejects small-order, mixed-order and non-canonical keys, for which a signature can verify for more than one message or key. A key that fails is `400 key_rejected`.

## 3. Tools

All arguments are in `params.arguments`. A tool result is an MCP `CallToolResult` whose `structuredContent` holds the object described below and `isError` is `false`. An argument that is missing, of the wrong type, or outside its stated range is `400 invalid_params`. In particular: `name` matches the pattern in section 1; `admin` MUST be a strict JSON boolean when present; `not_before` and `not_after` are non-negative integers or `null`, at most 999999999999 (12 digits, like `ts`), and `not_before` is below `not_after` when both are set; `kid` and `invite_id` are strings. An integer argument is read from its JSON text: it is an integer only when that text has no fractional part and no exponent, so `1` and `-0` are integers while `1.0` and `1e3` are not, and a JSON string or boolean is never a number. Errors use the rejection body from 01-authentication section 4, with the codes in section 7.

Unknown argument members have no effect: the arguments object is parsed with last-occurrence-wins semantics (02 section 2) and then read by exact name, so a stale `scopes` or `kind` member is silently inert and cannot escalate anything. Known members of the wrong type fail closed (`400 invalid_params`) — in particular a mistyped `admin`.

Duplicate argument names follow 02 section 2: the last occurrence wins and the occurrences are not merged, so an argument smuggled in by an earlier occurrence cannot survive into the call. The integer rule above reads the JSON text of that last occurrence.

### 3.1 Self-service (any active key)

| Tool | Arguments | Result |
|---|---|---|
| `jack.whoami` | none | `{kid, name, admin, not_before, not_after}` of the caller |
| `jack.key.rotate` | `public_key`, `proof` | `{kid}` of the new key |

`jack.key.rotate` replaces the caller's key with a new one, keeping `name`, `admin`, `not_before` and `not_after`. The request is signed by the old key as usual. `proof` is `base64url(Ed25519_sign(new_private_key, S))` where S is these lines joined with LF, without a trailing LF:

```
mcp-jack/v1/rotate
<aud>
<old kid>
<new kid>
<ts>
```

`ts` is the `ts` parameter of the request's `Jack-Auth` header. Checks run in this order: arguments (`400 invalid_params`), the new key (`400 key_rejected`), the proof (`400 invalid_proof`; a proof that is not a canonical 64-byte value is also `invalid_proof`), and only then whether the new key is already registered (`409 key_exists`). The proof is checked first so that a caller cannot learn which keys are registered without holding the matching private key. On success the old key is removed immediately. Rotation preserves `admin`, so it never trips the last-administrator rule (section 4).

### 3.2 Enrollment

`jack.enroll` is called by a holder of an invite whose key is not yet registered.

| Argument | Meaning |
|---|---|
| `code` | The invite code. |
| `name` | The name for the new entry. |
| `public_key` | The new public key, base64url. |

The invite supplies the `admin` flag of the new entry. The request is signed by the **new key** and carries `kid` = `base64url(SHA-256(public_key))`; that signature is the proof of possession. This is the **only** operation for which an unknown `kid` is not rejected at step 4 of 01-authentication section 4. The server MUST process it in this order and stop at the first failure:

1. Steps 1-3 of 01 (header present, well formed, version).
2. Step 4 exception: if `kid` is not in the registry and the request is a `POST` `tools/call` of `jack.enroll` with a valid JSON-RPC body, take `public_key` from the arguments. Otherwise `401 unknown_key`.
3. The public key passes section 2 (`400 key_rejected`) and `kid` equals its hash (`401 unknown_key`).
4. Steps 6-8 of 01 (time window, signature verified with the **submitted** key, nonce recording).
5. Arguments: `code` and `name` are strings and `name` is valid, otherwise `400 invalid_params`.
6. The invite exists, has not expired (`now < expires_at`), has not been used and has not been revoked: otherwise `403 invalid_invite`. All of these cases, and a `code` that is not a canonical base64url encoding of 32 bytes, return the same code, so a caller cannot tell them apart.
7. `name` is unused: otherwise `409 name_taken`. A failure here does not consume the invite.
8. Atomically: mark the invite used, add the entry with the invite's `admin` flag, `not_before` null and `not_after` from the invite's `key_ttl_seconds`. Result: `{kid, name, admin}`.

A request with an already registered `kid` takes the normal path; `jack.enroll` from a registered key is `409 key_exists`.

### 3.3 Administration (`admin`)

A caller whose entry does not have `admin` is `403 admin_required`.

| Tool | Arguments | Result |
|---|---|---|
| `jack.admin.user.list` | none | `{users: [entry, ...]}`, sorted by `name` |
| `jack.admin.user.get` | `kid` | an entry; `404 unknown_target` if absent |
| `jack.admin.user.create` | `name`, `public_key`, optional `admin`, `not_before`, `not_after` | `{kid}` |
| `jack.admin.user.set_admin` | `kid`, `admin` (required) | the updated entry |
| `jack.admin.user.revoke` | `kid` | `{kid}` |
| `jack.admin.invite.create` | optional `admin`, `ttl_seconds`, `key_ttl_seconds` | `{invite_id, code, expires_at}` |
| `jack.admin.invite.list` | none | `{invites: [{invite_id, admin, created_by, created_at, expires_at}, ...]}` |
| `jack.admin.invite.revoke` | `invite_id` | `{invite_id}` |

An *entry* is `{kid, public_key, name, admin, not_before, not_after}`; `admin` is always present in a result, `false` included. In `set_admin` the `admin` argument is REQUIRED: absent, `null` or non-boolean is `400 invalid_params`.

`jack.admin.user.create` is for the case where an administrator is given a public key; the private key never reaches the server.

Invites:

- `ttl_seconds` is an integer 1..604800, default 3600; the invite expires at `created_at + ttl_seconds` (valid while `now < expires_at`). `key_ttl_seconds`, if present, is an integer 1..31536000 and sets the enrolled key's `not_after` to the enrollment time plus that many seconds.
- `code` is 32 bytes from a CSPRNG, base64url. It is returned **once**, by `invite.create`, and never again.
- The server stores only `invite_id` = `base64url(SHA-256(code_bytes))`, computed over the 32 raw bytes of the code; `invite_id` is also how an invite is listed and revoked. A server MUST NOT log or persist `code`.
- An invite is single-use. Expired and used invites are not listed.
- The stored record is `{invite_id, admin, created_by, created_at, expires_at, key_ttl_seconds?}`; `admin` is optional with default `false` and a strict JSON boolean when present; `key_ttl_seconds` is present only when the invite sets a key expiry, and is then an integer 1..31536000 — JSON `null` is not accepted.

## 4. Administration rules

Every `jack.admin.*` tool runs these checks in this order and stops at the first failure:

1. the caller is an administrator (`403 admin_required`);
2. the arguments are valid (`400 invalid_params`);
3. any submitted public key is valid (`400 key_rejected`);
4. the target exists (`404 unknown_target`);
5. conflicts: the name is unused (`409 name_taken`), the key is not registered (`409 key_exists`);
6. the last-administrator rule (`409 last_admin`), evaluated against the registry as it would be after the change;
7. the change is applied atomically.

The rules:

1. **Any administrator may administer any entry.** An administrator may grant, revoke or change `admin` on any entry, including another administrator's and its own; self-demote and self-revoke are allowed. The only protection is the last-administrator rule.
2. **Last administrator.** An operation that would leave no active entry with `admin` — revoking it, setting its `admin` to `false`, or otherwise demoting it — is `409 last_admin`. "Active" means within `not_before` / `not_after` at the time of the operation. Rotation preserves `admin` and therefore never trips this rule.

## 5. Bootstrap

A server that has no administrator cannot be administered through the protocol. The first administrator is created out of band: the server SDK MUST provide a local operation (not reachable over the network, and not an MCP tool) that creates one invite with `admin` true and returns its code to the local operator. There MUST be no default credential and no built-in key.

## 6. Signer agents and administration (informative)

An agent that reads untrusted content (logs, web pages, documents) can be steered into asking for privileged operations. For that reason:

- Automation runs as ordinary users without `admin`; keys that may administer are kept in hardware-backed or confirmed signers where possible.
- Signer agents SHOULD require human confirmation for `jack.admin.*` calls.
- A stolen or prompt-injected signing key is as good as the identity behind it ([01-authentication.md](01-authentication.md) section 6).

## 7. Error codes

| HTTP | `code` | Meaning |
|---|---|---|
| 400 | `invalid_params` | Missing, mistyped or out-of-range tool arguments. |
| 400 | `key_rejected` | Public key fails section 2. |
| 400 | `invalid_proof` | `jack.key.rotate` proof does not verify. |
| 403 | `invalid_invite` | The invite is unknown, expired, used or revoked. |
| 403 | `admin_required` | The caller is not an administrator. |
| 404 | `unknown_target` | `kid` or `invite_id` is not registered. |
| 409 | `name_taken` | The name is already used. |
| 409 | `key_exists` | The key is already registered. |
| 409 | `last_admin` | The operation would leave no active administrator. |

## 8. Audit

A server MUST record an audit event for every `jack.admin.*`, `jack.enroll` and `jack.key.rotate` call that reaches the tool, successful or not, with: time, caller `kid` and `name` (or the submitted `kid` for enrollment), tool, target (`kid`, `invite_id` or name), outcome and, on failure, the `code`. Events MUST NOT contain invite codes or private keys. A call that reaches the tool is one that passed authentication (01-authentication steps 1-8); a call for an undefined `jack.` tool is not audited as a tool call. A server SHOULD also log rejected authentication attempts, at a level of detail of its choosing. The destination (file, syslog, external sink) is implementation-defined.

## 9. Atomicity

The registry changes in this document (adding, changing or removing an entry — including changing its `admin` flag — and consuming an invite) MUST be atomic and take effect for the next request. Concurrent invocations that would each satisfy the last-administrator rule individually but together violate it MUST be serialized so that the invariant holds.

## 10. State file

The server persists its state on disk as a document:

```json
{
  "version": 1,
  "keys": [],
  "invites": []
}
```

- `keys` holds registry entries exactly as defined in section 1 and [02-authorization.md](02-authorization.md) section 1 (`kid`, `public_key`, `name`, `admin`, `not_before`, `not_after`); `invites` holds the stored records of section 3.3.
- Load rules: `version` MUST be 1; unknown fields are rejected at load time on the document, on every entry and on every invite record; duplicate `kid`, duplicate `name` and duplicate `invite_id` are rejected; entries MUST satisfy the registry validity rules (public-key validity per section 2, `kid` = `base64url(SHA-256(public_key))`, a valid `name`, a strict-boolean `admin`, the time fields of the registry). For invite records: `invite_id` and `created_by` are non-empty strings, `created_at` and `expires_at` are non-negative integers with `created_at <= expires_at`, `admin` is an optional strict boolean, and `key_ttl_seconds` follows section 3.3 (absent or integer 1..31536000, never null). A missing file yields an empty store.
- **Legacy rejection.** A document, or any entry or record in it, containing `kind` or `scopes` MUST be rejected at load time with an error that names the offending member. A legacy file is never silently migrated, stripped, reset or overwritten: the server MUST refuse to start (or refuse the load) until the operator resolves it, and MUST NOT write the file back. The registry document of 02 section 1 follows the same entry rules; it carries `aud` and no invites.
