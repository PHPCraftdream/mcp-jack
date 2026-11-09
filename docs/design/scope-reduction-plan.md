# Scope reduction: implementation record (2026-11-08)

This is the decision record for the 2026-11-08 scope reduction, not a live implementation checklist. The specification and Go, Rust, and TypeScript SDKs implement the reduced contract in baseline `b13b972`. Shared interop matrix acceptance, packaged-consumer checks, and coverage/fuzz evidence remain pending parent CI. No local generator, build, test, or validation is claimed here.

## Current contract

- mcp-jack authenticates and integrity-protects messages, prevents replay, manages protocol users/keys, audits operations, and supplies immutable verified identity `{kid, name, admin}` to the wrapped handler.
- Authenticated ordinary MCP requests pass through unchanged. Application code authorizes them from the verified identity; `admin` gates reserved `jack.admin.*` tools only.
- User and invite creation accept optional strict-boolean `admin` defaulting false; enrollment inherits invite value. `set_admin` requires a strict boolean. Records and results include `admin`, including false. Last-active-admin protection remains.
- User `kind`, scopes, the policy engine, and the service-management profile are removed. Legacy user/state `kind` or `scopes` records are rejected without migration or rewrite.
- The user-key transfer envelope `type` discriminator is independent of user `kind`; the transfer contract and fixture are unchanged.

## Current evidence boundary

Shared request interop scenarios are defined in `interop/scenarios.json`, the current source of truth. The harness implements verified-identity forwarding through the ordinary handler and malformed required-boolean admin-input controls; matrix acceptance remains pending parent CI. Preserve ordinary MCP pass-through, verified identity hand-off, protocol admin gates, strict request/response signing, trust, freshness/replay, signed errors, and last-active-admin behavior.

The existing SDK test source is distinct from integration evidence: Go root/client/server/userkey tests; Rust integration tests under `rust/tests/`; TypeScript tests under `ts/test/`; shared contract fixtures under `spec/fixtures/`. Parent CI evidence for this baseline remains pending. No release, tag, publication, dependency, or version change is implied.

## Historical design questions

- **Q1:** authenticated session channel is a future v0.2 direction. Authentication and confidentiality are distinct; the current per-request signed-message behavior stays until a separate versioned design exists. Transport, TLS relationship, lifetime/rekeying, session replay protection, and multi-instance state remain open. No channel is implemented.
- **Q3:** server-key rotation is separate future work and is not implemented. The exact announcement format, delivery mechanism, persistence, and client/server APIs require a dedicated design; no TOFU or unauthenticated pin replacement is introduced by this direction.
- **Q5:** multi-instance servers and cluster management are deferred for separate design.

See [the scope review](scope-review-2026-11-08.md) for the Q1/Q3 discussion and remaining decisions. See [readiness](../readiness.md) for the historical CI results and their exact earlier-commit boundary.
