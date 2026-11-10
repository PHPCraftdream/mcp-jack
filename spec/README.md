# mcp-jack specification

**Status: draft v0.1; not frozen.** This main copy describes the existing HTTP request/response protocol, SDK behavior and current top-level fixtures. The earlier scope reduction of 2026-11-08 is reflected in the normative text and current generator/reference verifier. Checked-in files do not prove that tests or CI were run. This file does not establish broader Task57 acceptance, SDK support or release completion.

Selected D2/D3 owner directions and separately maintained candidate details are documented in [`candidate/README.md`](candidate/README.md), [`candidate/durable-nonces.md`](candidate/durable-nonces.md), [`candidate/server-key-rotation.md`](candidate/server-key-rotation.md), and [`../docs/protocol-transition.md`](../docs/protocol-transition.md). Candidate details are not normative v0.1, do not freeze wire behavior and do not authorize implementation, dependencies, version changes or release. Current protocol behavior remains the v0.1 spec and current top-level fixtures.

## Layout

| Path | Content |
|---|---|
| [01-authentication.md](01-authentication.md) | Current authentication: signatures and in-memory replay checks |
| [02-authorization.md](02-authorization.md) | Current registry, admin flag, dispatch and identity hand-off |
| [03-user-management.md](03-user-management.md) | Current native user/invite tools, user-key rotation and state file |
| `fixtures/` top level | The current v0.1 vector set plus two hand-maintained SDK tables |
| `fixtures/candidate/` | Task57 candidate source-preparation outputs; not current-v0.1 inputs |
| `tests/` top level | Current v0.1 runner contract and current top-level `CASES.md` |
| `tests/candidate/` | Separate candidate runner and candidate generated-index route |
| `tools/` top level | Established current generator and reference verifier |
| `tools/candidate/` | Independent candidate generator/checker and preparation machinery |

## Conventions

- Test vectors define the behavior they cover. Passing current top-level v0.1 cases is a conformance criterion, not evidence a runner was executed.
- **Current normative vector boundary:** exactly the eight generated files directly under top-level `fixtures/` form the current v0.1 protocol-vector set. The two hand-maintained top-level SDK tables are not protocol vectors; `fixtures/README.md` documents their scope/composition. Fixture keys are test-only.
- **Candidate fixture boundary:** nested `fixtures/candidate/` is separately routed Task57 future-profile source-preparation data. It is not current v0.1 loader/conformance input; stated expected values are declarations, not generated cryptographic proof.
- **Current/candidate case-index boundary:** top-level `tests/CASES.md` indexes current v0.1 cases only. Candidate runner tests and generated case index route separately through `tests/candidate/`; candidate results do not extend current conformance.
- **Current/candidate tooling boundary:** top-level `tools/gen-fixtures.mjs`/`tools/reference-verifier.mjs` cover current vectors. The independent `tools/candidate/` generator/checker and `.github/workflows/spec-fixtures.yml` entrypoint prepare candidate expectations only; they do not change or validate the current top-level set.

The commands below are maintainer examples for current top-level vectors only; they do not run candidate generation/checking/testing.

```text
node spec/tools/gen-fixtures.mjs          # regenerate current top-level vectors
node spec/tools/gen-fixtures.mjs --check  # check current top-level vectors
```

## Decisions in this draft

| # | Decision | Why |
|---|---|---|
| D1 | mcp-jack is a **transport wrapper** around unmodified MCP over HTTP: JSON-RPC bodies pass through untouched, with protection around them. The repository also contains a Go CLI gateway and stdio bridge; their presence does not establish broad MCP interoperability. WebSocket is not a protocol transport in v0.1. | The bounded executable profile is not general MCP conformance. |
| D2 | Ed25519 only, one protocol version, no negotiation. | Avoid downgrade surface and preserve consistent behavior. |
| D3 | A small custom signing format over raw bytes rather than RFC 9421 HTTP Message Signatures. | Newline-joined bytes are straightforward to reproduce and fixture-test across languages; the trade-off is a custom, nonstandard format. |
| D4 | Per-request signature with a nonce cache, no session. **Current nonce cache is in memory.** Durable authenticated nonce reservation before authorization/state mutation/dispatch is the selected future direction, not current v0.1 behavior. | Restart protection requires separate durable backend and acceptance work. |
| D5 | TLS provides confidentiality; signatures provide authentication, integrity, replay protection and an audit identity. | Signatures do not provide confidentiality. |
| D6 | No policy engine. Ordinary authenticated MCP passes through; consumers decide application authorization using verified `{kid, name, admin}` identity. `admin` gates only native administration tools. | Application authorization belongs to the protected service. |
| D7 | The `jack.` tool prefix is reserved for protocol-native tools handled by the protocol layer. | Native calls do not reach the wrapped handler. |
| D8 | No service-management profile. | Services define their own tools and access rules. |
| D9 | User administration and **user-key** rotation use native `jack.*` tools; the server receives public user keys only. | This is distinct from future server response-key rotation. |
| D10 | Enrollment is the exception to unknown-key rejection: a new key signs proof of possession and presents a single-use invite. | Invites are narrowly scoped bearer permissions. |
| D11 | One strict boolean `admin` per user, default false; protocol admin privilege gates native administration. | Keep protocol privilege simple and auditable. |
| D12 | Strict Ed25519 public-key admission and signature scalar rule (`S < L`). | Preserve the normative cryptographic contract; do not weaken it. |
| D13 | Duplicate JSON members in request bodies use last-occurrence-wins and are not merged; authentication still covers exact bytes. | Keep parser behavior explicit and narrowly scoped. |
| D14 | Server SDK hands a read-only verified identity snapshot to wrapped handlers. | Consumers can apply their own authorization. |

## Open questions and separately selected future directions

- **Q1.** Streaming responses remain future work; an authenticated encrypted session channel is a possible future direction.
- **Q2.** ~~Delegation~~ — closed: no delegation or `kind` protocol feature.
- **Q3.** **Server response-key rotation direction selected; contract and implementation remain candidate work.** Owner direction allows arbitrary multiple pending announcements, without a one-pending rule or cooldown; OLD remains in use until NEW takes over 48 hours after its announcement. The owner example is K1 announced Monday 10, K2 announced Monday 11: K1 remains usable until Wednesday 11 when K2 takes over. Candidate formal time/event representation and ordering/cutoff mechanics are technical defaults, not additional owner decisions. No server-key rotation is implemented or frozen in this spec.
- **Q4.** ~~Registry/policy distribution~~ — closed.
- **Q5.** Multi-instance/cluster nonce sharing remains deferred; current nonce storage is in memory. D2 selects durable authenticated reservation before native authorization/state mutation/dispatch, with unknown write outcome failing closed and no automatic retry. No timestamp-startup floor is selected. Design/backend qualification/implementation remain future work.
- **Q6.** Initial audience and server-key trust remain out of band. Rotation does not replace the initial independent pin.
- **Q7.** ~~RFC 9421 replacement~~ — closed; current signing format remains.
- **Q8.** ~~Protocol human-approval flow~~ — closed; not a protocol/SDK feature.
- **Q9.** ~~License~~ — MIT OR Apache-2.0; see repository license and contribution files.
- **Q10.** ~~Policy matching~~ — closed; ordinary MCP authorization belongs to SDK consumers.

This draft is not a wire freeze, release or promise of cross-SDK support. Static pins, user-key rotation, existing profiles and credentials remain unchanged absent a separately approved transition. Current normative text plus the eight top-level generated v0.1 vectors are the existing protocol baseline; nested candidate fixtures, tooling, runner/index and workflow are separately routed future-profile material and do not alter current conformance.
