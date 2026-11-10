# Release plan: v0.1.0 (historical plan; not release authorization)

**Current status: planning record, last updated 2026-11-10.** Preserve the historical 2026-11-09 statements and task IDs below as provenance, not as a current claim that all work remains unimplemented. The original plan is commit `777771fed0a53011898e55d959b6f8576675fd89`, atop main baseline `e681f07`. Its recommendations are explicitly superseded where noted. No wire freeze, version change, tag, publication, RC or release is approved.

PR #22 delivered the design baseline as `c098cf5678716b36d1bff5012f864e2e0d105286` after 32 successful checks on reviewed head `f00fc2e42e935f6632e48d224be3c76581aa6ec5`. All six post-merge workflows succeeded; main ancestry and source-preserving cleanup were verified. This establishes design delivery, not D2/D3 runtime implementation or candidate acceptance.

## 1. Where the project stands

### Historical 2026-11-09 baseline statement (preserved, not current)

The original plan stated that the following were done and verified in GitHub CI on main at `e681f07`:

- Specification v0.1 after the 2026-11-08 scope reduction: per-request Ed25519 signatures, nonce cache/time window, strict Ed25519 and canonical base64url, signed rejections, native `jack.*` tools, the single `admin` flag, verified caller identity hand-off, audit, and out-of-band first administrator.
- Go, Rust and TypeScript SDKs; normative generated fixtures and reference verifier; 3×3 cross-language request/response interop and credential-transfer matrices; coverage, bounded Go fuzzing, license and packaged-consumer checks.
- The plan recorded the repository as MIT OR Apache-2.0, with no open issues or pull requests, no tags and no npm/crates.io/Go proxy publication.

These are dated historical baseline claims, not current issue/PR counts or new test receipts. This release-plan document preserves that history. Other work in this same worktree supplies candidate generator/index and workflow changes; this documentation edit does not own or alter those paths.

### Current progress and open work

Parent reports PR16–21 as merged foundations, packaging and bounded Go CLI work; CLI source is present under `cmd/jack` and `internal/cli`. Do not infer all historical S3 acceptance receipts from source presence. PR22's parent-provided merge/check status is recorded above. The six post-merge workflows succeeded and Task52 cleanup completed. This document reconciles the listed public docs; separate Task57 work adds candidate generator/index and workflow artifacts.

The historical gap list below is retained for provenance, with current interpretation inline. This release-plan document is one part of broader Task57 work; this section does not describe other worker-owned candidate artifacts as absent.

| # | Historical gap (2026-11-09 wording) | Current reconciliation |
|---|---|---|
| G1 | Server key cannot be rotated; `docs/design/server-key-rotation.md` sr1 was a heavy, unimplemented proposal. | Rotation direction is selected: arbitrarily many pending announcements, and OLD remains in use until NEW takes over 48 hours after announcement. Candidate time anchor, ordering/cutoff details, implementation and acceptance remain future work. |
| G2 | Nonce cache is in memory and spec says nothing about restart. | Still a current source limitation. Selected remedy is durable authenticated nonce reservation before native authorization/state mutation/handler dispatch; unknown write outcome fails closed, without automatic retry. The historical `ts < server_start` recommendation is superseded. |
| G3 | No executables: no gateway, bridge or CLI. | Historical statement is stale: Go CLI/keygen/bootstrap/enroll/gateway/bridge source exists. This does not establish complete integration, exact CI receipts, broad MCP compatibility or release readiness. |
| G4 | Real MCP compatibility untested, including streams, `Accept`, protocol/session headers. | Compatibility design is source research and proposed future acceptance; do not label official MCP interoperability complete. It is distinct from current Jack 3×3 request/response and credential-transfer matrices. |
| G5 | Stale texts: fixtures/SDK migration pending; Q3 decision; SECURITY “policy checks”; old SDK README wording. | This document and the requested public docs are being reconciled; no claim is made about other historical G5 targets. Q3 direction is selected but not implemented/frozen. |
| G6 | No release engineering; versions/publication still need decisions. | No version changes are approved and any separately authorized RC is artifact-only/no registry publication. Release engineering/version bumps/publication remain unapproved. |
| G7 | Limited user/operator documentation. | This is not a complete operator guide or quickstart. Preserve the scope and tasks as future/historical planning, not delivered release artifacts. |
| G8 | Security assurance gaps: differential fuzzing, independent review, vulnerability scanning. | Candidate acceptance/security gates remain distinct from current workflows. No new audit, scan, or differential-fuzz result is claimed. |

## 2. Release scope: historical proposal and current decisions

The original release-plan recommendation was: “v0.1.0 contains a wire format frozen for the 0.x series; three SDKs; minimal server-key rotation; restart replay guard; Go CLI gateway/stdio bridge/key generation/bootstrap/admin commands; official MCP examples; documentation; signed release artifacts.” Its freeze, rotation/restart mechanism and release/artifact commitments are superseded. The spec is not frozen; no release is authorized.

The D-1/D-4/D-5 summaries in this plan are separate release scope, version, and artifact-only RC decisions; they do not approve D2/D3 protocol mechanics. D2/D3 express directions, while technical candidates remain defaults.

D2/D3 summaries here record protocol directions, not release approval. The D3 owner example is K1 announced Monday 10 and K2 announced Monday 11: K1 remains usable until Wednesday 11 when K2 takes over. The fixed next-announcement retirement is the owner direction. Separately, candidate `P_i`/`A_i` logical-time model, event anchor, ordinal tie ordering/empty intervals, strict client cutoff and delivery edges are technical defaults, not further owner decisions. See [versioning policy](versioning.md), [candidate index](../spec/candidate/README.md) and [protocol transition policy](protocol-transition.md).

Not selected/currently deferred or unchanged:

- Encrypted session channel/streaming remains future work.
- Multi-instance/cluster nonce sharing remains unsupported/deferred; current nonce storage is in memory. D2 design assumes durable authenticated reservation with a single accepting owner; implementation and backend qualification remain future work.
- Heavy sr1 generation/fork/quarantine proposal is not adopted as v0.1. The selected D3 direction is different and has no one-pending rule/cooldown.
- Per-user server keys, delegation, policy engine, ordinary MCP authorization and human-approval flows are not added by this work.
- Static server pins, profiles, credentials and user-key rotation remain unchanged unless the separately reviewed [protocol transition](protocol-transition.md) explicitly defines migration. No TOFU or silent `v1` reinterpretation.
- No publication/version bump, registry RC, stable release, tag, GitHub Release or public announcement is approved. Artifact-only RC policy is not RC authorization.

## 3. Decisions and superseded recommendations

The recommendations in these sections are historical, potentially broad or advice; they do not override the current decisions above.

| ID | Historical plan recommendation (2026-11-09) | Current decision/status |
|---|---|---|
| D-1 | Ship Go gateway/bridge/CLI, not SDKs only. | Candidate release-scope direction; Go source exists, but this is not release authorization. |
| D-2 | Reject `ts < server_start` as restart guard, retry with fresh `ts`. | **Superseded.** Durable authenticated nonce reservation before dispatch is selected. Unknown write outcome fails closed; never automatically retry. No timestamp startup floor. |
| D-3 | Read-only `jack.server.key`, refreshed automatically on connect and periodically; one pending rotation. | **Superseded.** Arbitrarily many pending announcements, without cooldown or one-pending restriction; OLD remains in use until NEW takes over 48 hours after announcement. Candidate time-anchor/order/cutoff details are technical defaults, not additional owner decisions. Automatic refresh is not selected; implementation remains future work. |
| D-4 | Set all component names/versions to 0.1.0 and verify registry name availability. | **Superseded.** No version changes yet; no name/tag/publication approval. Preserve checked-in values. |
| D-5 | Publish RCs to npm/crates.io and use Go prerelease tag. | **Superseded.** Any separately authorized RC is artifact-only, without registry publication. No tag or release is authorized here. |

## 4. Work plan and task-ID provenance

The original plan's task IDs are preserved as historical references, not evidence that each task is open, completed or accepted. Tasks that encode superseded mechanisms are called out; new candidate work is not silently folded into old acceptance.

### S1. Close specification and freeze the wire format — historical heading; freeze not approved

Depends historically on D-2/D-3. Current status: no freeze; this documentation change is not normative spec acceptance. Candidate details stay separate in [`spec/candidate/`](../spec/candidate/) and [`docs/protocol-transition.md`](protocol-transition.md).

| Task | Historical content / current interpretation | Acceptance status |
|---|---|---|
| S1.1 | Historical minimal one-pending server-key rotation and `switch_at`. Superseded by selected multi-pending announcement direction; technical candidate default. | Candidate contract review and later normative spec/fixtures remain future gates. |
| S1.2 | Historical `ts < server_start` restart guard. Superseded by D2 durable authenticated nonce reservation. | Durable backend/SDK contract and evidence remain future gates; no timestamp-floor case is selected. |
| S1.3 | Historical generator/reference rotation and restart vectors in current `CASES.md`. | This documentation edit leaves the current generated case index untouched. Other Task57 work supplies a candidate generated case index and workflow in separate paths; these remain separate from the current generated assets. |
| S1.4 | Fix stale public documentation. | This documentation edit covers the seven requested public documentation files. Other Task57 work has separate ownership. |
| S1.5 | Versioning policy and “wire v1 frozen for 0.x.” | Versioning policy says no freeze. Freeze approval and exact contract baseline remain future gates. |

### S2. Rotation and restart guard in SDKs — direction selected; implementation/acceptance pending

Historical S2.1–S2.4 specified a single rotation tool/window, one-pending semantics and startup guard. Those mechanisms are superseded. Future SDK work must implement a separately approved normative D2/D3 contract and add candidate fixtures/interop. Do not claim Go/Rust/TypeScript support for D2/D3 from current in-memory nonce stores/static pins. Existing Jack 3×3 request/response and credential-transfer matrices are separate.

| Task ID | Preserved workstream | Current status |
|---|---|---|
| S2.1 | Go server/client restart and rotation work. | Future candidate implementation; no durable nonce backend or server-key rotation client/server contract in the SDK. |
| S2.2 | Rust equivalent. | Future candidate implementation; Rust manifest is at MSRV 1.88. |
| S2.3 | TypeScript equivalent. | Future candidate implementation; package remains private. |
| S2.4 | Cross-language interop. | Existing Jack request/response and credential-transfer matrices are separate from future D2/D3 candidate and official MCP coverage. |

### S3. Executables (Go) — source exists; historical receipts remain distinct

The historical plan treated executable work as future. Current `internal/cli` source has keygen, bootstrap, enroll, gateway and bridge. Parent reports PR16–21 foundation/packaging/bounded CLI work and PR22 status above. This is not proof of every S3 acceptance item or release readiness. The gateway still uses in-memory nonce storage; its bounded legacy MCP profile is not general MCP compatibility.

| Task ID | Historical content | Current status / gate |
|---|---|---|
| S3.1 | CLI skeleton/keygen/bootstrap/enroll/config. | Source exists; do not infer a per-task CI receipt beyond parent-provided status. |
| S3.2 | Gateway and trusted-hop identity forwarding. | Source exists; deployment must protect upstream socket/hop. E2E/security acceptance requires exact receipts. |
| S3.3 | Stdio-to-HTTP bridge. | Source exists; framing/lifecycle source is not full MCP compatibility acceptance. |
| S3.4 | Historical `user ...` and `server-key announce/status` CLI commands. | Current `internal/cli/run.go` has no admin or rotation CLI subcommands. Server SDK native user-administration and user-key tools are separate. No server response-key rotation command exists. |
| S3.5 | Cross-platform builds. | Check actual artifact receipts for a specific SHA before claiming; no build was run for this documentation work. |

### S4. MCP ecosystem compatibility and examples — future acceptance

`docs/design/mcp-compatibility.md` records upstream source observations and proposed tests; it does not claim execution or compatibility. Separate official MCP client/bridge/gateway/server coverage from existing SDK 3×3 request/response and credential-transfer matrices. Legacy and modern MCP profiles are not interchangeable; do not claim broad MCP support.

| Task ID | Historical content | Current status |
|---|---|---|
| S4.1 | Official SDK examples. | Future work unless separate source/CI evidence says otherwise. |
| S4.2 | Official client → bridge → gateway → server E2E. | Candidate future acceptance; not represented by current Jack interop matrices. |
| S4.3 | Fix compatibility findings before freeze. | Freeze is not approved; resolve under a reviewed profile and future acceptance. |

### S5. Security assurance — open gates, not claims

The threat model distinguishes source observations from inferred risks and candidate checks; it is not an audit. Source/workflow configuration is not evidence that differential fuzzing, independent review or all advisory gates completed. Parent-provided D2/D3 directions and PR22 status are not candidate acceptance; the six post-merge workflows and Task52 cleanup completed.

| Task ID | Historical content | Current status |
|---|---|---|
| S5.1 | Threat model. | Reconciled in this worktree; no runtime/security assessment claimed. |
| S5.2 | Rust fuzz targets and TS property tests. | Historical task; do not claim completion absent receipts. |
| S5.3 | Differential fuzzing across SDKs. | Future acceptance; no differential-fuzz result claimed. |
| S5.4 | Independent review and fixes. | Separate review evidence required; no independent audit claim. |
| S5.5 | Supply-chain/advisory scanning. | Distinguish workflow wiring/parent receipts from a new scan; no scan run for this documentation work. |

### S6. Documentation — historical backlog, documentation portion scoped

This documentation portion does not add a full quickstart/operator guide. It follows the source, candidate and workflow work in broader Task57.

| Task ID | Historical content | Current status |
|---|---|---|
| S6.1 | User README and quickstart. | Not delivered by this documentation portion. |
| S6.2 | Operator guide. | Historical future work; no new guide claimed. |
| S6.3 | API docs. | Historical future work; no SDK API changes here. |
| S6.4 | Clean docs/status/index. | This documentation portion only; historical release-plan facts and task IDs are preserved; unsafe recommendations are superseded inline. |

### S7. Release engineering — no version/publication approval

| Task ID | Historical content | Current status |
|---|---|---|
| S7.1 | Set package metadata to release version and remove publication restrictions in release PR. | Not authorized; preserve current manifests and flags. |
| S7.2 | Changelog and release notes. | Existing files may be present; no version/release approval follows. |
| S7.3 | Publish artifacts/packages on tag. | Not authorized. Future artifact-only RC needs exact artifact/checksum/attestation receipts. |
| S7.4 | Repository settings/publishing credentials. | No new authorization or account configuration implied. |
| S7.5 | Recheck package names. | No package-name or publication decision made. |

### S8. Release candidate and release — not authorized

An RC, if separately authorized, is artifact-only with no registry publication. This supersedes historical S8.1's registry-published `v0.1.0-rc.1`/tag/install proposal. S8.2's repeat-RC step and S8.3's stable tag/publication/GitHub Release/announcement are not authorized. Future RC/stable actions require separate approvals and exact receipts.

## 5. Order and critical path — historical diagram, not current commitment

The original graph and “S1 → S2 → S4 → S8” critical path describe former one-pending/startup-floor/freeze/published-RC recommendations. They are not current estimates or approvals. Current sequencing is gated by review of D2/D3 directions and candidate technical details, normative contract decisions, implementation, separate candidate CI evidence, integration/security review and explicit release decision. No task completion is inferred from the historical graph.

## 6. Working rules

Preserve the historical process with current boundaries:

- Keep worktree/PR boundaries and tie CI receipts to exact full SHA; do not represent parent-provided status as local execution.
- The documentation portion does not rewrite current generated files. Separate Task57 work owns the candidate case generator/index and workflow.
- Future approved wire changes require normative spec, generator/reference model, fixtures and applicable SDKs together.
- No versions, tags, pushes, publication, RC or release without separate explicit approval; an artifact-only RC does not publish to registries.
- No executable commands, tests, scripts, scans, probes or builds were run for this documentation portion under the owner's prohibition.
