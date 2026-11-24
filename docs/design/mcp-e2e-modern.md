# Modern official-SDK E2E design (backlog #193)

## Purpose and boundaries

**Proposal, not an implementation or test result:** add an official-MCP-SDK E2E matrix for the `2026-07-28` modern profile, exercising the merged Go CLI `jack bridge` and `jack gateway`. Keep `tools/mcp-e2e` and its legacy matrix independently runnable and unchanged by modern fixture work.

Cover official SDK client/server interoperation for features both endpoints expose: modern requests and metadata, tool calls, signed progress streams, cancellation, and `subscriptions/listen` where supported. Compare direct SDK-to-SDK controls with Jack paths. Exclude SEP-3415 Events, Events-specific APIs/semantics, SDK-unsupported behavior, and full conformance. Claims about Events status and SDK coverage are **to confirm in CI**; custom handlers, Inspector, or conformance implementations do not count as official-SDK coverage.

In this document:
- **Observed** means repository evidence supplied by source review; it is not execution evidence.
- **Proposed** means future design or expected assertion.
- All SDK/version-dependent or runtime behavior not established by that review is marked **to confirm in CI**.

## Baseline and constraints

The existing `tools/mcp-e2e` suite targets the `2025-11-25` legacy profile. Its README lists Go SDK v1.8.0, TypeScript client/server 2.4.0 and node 2.1.2, and Rust `rmcp` 3.9.0; their modern-profile suitability is **to confirm in CI**. Existing modern support, stream APIs, and cancellation APIs for these versions are **to confirm in CI**.

Observed CI baseline: `.github/workflows/ci.yml` job `mcp-compat-e2e`, display name `mcp compat e2e (official clients x official servers)`, has a 45-minute timeout, Go 1.25, Node 22, stable Rust, and requires fixture lockfiles. The tracked locks are `tools/mcp-e2e/go/go.sum`, `tools/mcp-e2e/ts/package-lock.json`, and `tools/mcp-e2e/rust/Cargo.lock`. The README's claim that those locks are absent is stale and should be corrected in its own leaf task. Current cell code permits a TypeScript-server skip when either fixture artifact is unavailable as well as for the known limitation; tighten this so only the exact demonstrated TS-server issue can skip. Missing artifacts must fail. Verify that skip is narrow in CI.

Observed implementation constraints: bridge auto-era detection issues its own signed `server/discover` probe and verifies the modern response; modern bridge rejects `initialize`. A stream-capable bridge request opts in with `Jack-Accept: s1`. A modern/both gateway returns signed SSE when opted in. Gateway refuses `notifications/cancelled` POST upstream; modern HTTP cancellation is request/stream closure. The existing gateway integration test demonstrates a modern request without `Jack-Accept: s1` receiving verified `client.HTTPError` status 501, code `streaming_unsupported`. A modern request sent to a `legacy` gateway is rejected after legacy-profile inbound protocol-version header validation and before delegation to the handler (including authentication); do not describe it as a signed authenticated 501.

What the legacy runner asserts per cell (the inventory the modern runner must keep or replace; `tools/mcp-e2e/README.md` "What is asserted per cell"): hop captures between bridge and gateway (method, status, media type, body); exactly the sequence `initialize`, `initialized`, `tools/list`, `tools/call` with a matching echo result; the notification POST answered 202 with an empty body; the protocol version preserved in both directions; `Accept` carrying both `application/json` and `text/event-stream` and `Jack-Auth` present; bridge stdout purity (exact JSON-RPC frames, empty stderr, exit 0); one tamper cell per client x server pair (one flipped response byte at the proxy: upstream answers 200, the bridge exits 1 with zero stdout bytes and the fixed stderr line); recorded GET probes. Exit codes: 2 for harness errors, 1 for any failed cell, 0 only when every required cell ran.

Failure attribution for the modern runner: each cell records the hop captures and the bridge/gateway/fixture logs; a failure is attributed to the SDK when the same request through the direct (no-Jack) path fails the same way, to the fixture when the fixture's own readiness or echo check fails before any Jack hop, and to Jack otherwise; a cell outside the SDK's declared capability is a SKIP with API evidence, never a pass.

The existing proxy buffers a full response and does not cancel upstream on downstream disconnect. It is suitable for tamper-only buffered cases, not stream/cancellation. The modern stream/cancel harness must forward and capture incrementally, bound retained event/frame data, and abort the upstream request when the downstream disconnects.

## Matrix and paths

Run declared eligible official client × server pairs, with direct SDK controls and Jack paths. Record every cell and capability-based omission; SKIP is never PASS. Exact SDK versions and feature support are **to confirm in CI**.

| Path | Topology and purpose |
|---|---|
| Direct SDK control | Official client to official server over modern HTTP, without Jack. Isolates SDK interoperability; has no Jack signing oracle. |
| Bridge + modern gateway | Official stdio SDK client → `jack bridge` (`era: modern`) → incremental capture proxy → `jack gateway --profile modern` → official SDK server. Exercises Jack request/response verification and routing. |
| Bridge auto + both gateway | Same, with bridge `era: auto`, gateway `--profile both`, and a modern-capable server. Separately observe bridge's auto probe and subsequent SDK client traffic. |
| Scripted control | Minimal non-SDK endpoint only where needed for a deterministic protocol negative control, notably legacy-only/no-downgrade. It does not count as official-SDK coverage. |

### Scenarios and exact observations

1. **Auto detection and no initialize.** On the auto path, record the bridge-generated signed `server/discover` probe separately from official SDK client requests. Verify its signature and the modern response before era selection. Then assert the subsequent client modern POST count and sequence, and no `initialize`/`initialized`. Do not attribute a `server/discover` from the SDK itself to the bridge; whether an SDK issues one is **to confirm in CI**. Capture headers and per-hop identity. The client must receive the expected tool result.

2. **No silent downgrade.** Configure bridge era explicitly as `modern` and point it to a legacy-only or scripted legacy fixture. Require fail-closed behavior, no `initialize`, and no legacy retry; record client-visible failure and zero legacy fallback requests. Use a scripted non-SDK control if an official server cannot provide this behavior. Exact runtime failure shape is **to confirm in CI**. Do not infer this case from sending a modern request to a legacy gateway, which refuses before authentication.

3. **Plain tool call and metadata.** On direct and Jack paths, call a deterministic echo tool. Capture bridge/gateway request metadata and verify the signed response at the bridge; assert the client gets the expected result. Assert applicable mirrors only: protocol version, method, tool name for `tools/call`, and `Mcp-Param-*` only for parameters whose registered annotations define mirrors. Assert modern per-request `_meta` preservation where applicable. Do not require parameter mirrors for arbitrary arguments. Exact wire shape is **to confirm in CI**.

4. **Progress SSE with opt-in.** Run only a pair with verified stream capability. Keep the tool response open after emitting progress. The incremental proxy must expose the open response and first progress message before terminal response; assert request `Jack-Accept: s1`, signed status 200 event stream, frame signatures including terminal `end`, and bridge verification. The SDK client must observe progress followed by terminal result in order. Test tampering separately; never deliver unverified frames. SDK feature support and exact frame sequence are **to confirm in CI**.

5. **Missing-opt-in refusal oracle (separate from bridge success path).** For the bridge stream success case, bridge's stream layer automatically opts in; do not claim that case tests missing opt-in. Test the refusal through a modern/both gateway using an authenticated direct SDK HTTP control with modern request headers but no `Jack-Accept: s1`, or an isolated signing-boundary harness. The existing integration test is the oracle: require signature-verified status 501 and code `streaming_unsupported`. Use an official SDK transport only if it supports the required Jack auth hook; that capability is **to confirm in CI**. For the bridge side, a Jack-shaped 501 body carries no JSON-RPC version or matching id, so the modern bridge treats it as a protocol error (`server/internal/transport/response.go` about 539-544, `client/transport.go` about 319-356) and ends with a generic diagnostic: assert only a nonzero exit, zero stdout and no fabricated JSON-RPC result. Surfacing the exact verified status and body bytes through the bridge is NOT current behaviour; record it as a known gap, not an oracle. Do not test this by modern request against a legacy gateway.

6. **Cancellation while live.** Hold a `tools/call` stream open and wait until progress is observed. Two different things are tested and must not be conflated. (a) Bridge cleanup: the test driver closes the bridge's stdin (only where the driver owns that handle; for stdio SDK clients whose wrapper owns the child stdin this is not available) and observes upstream request context closure and no late frame; this proves the bridge, not the SDK. (b) SDK cancellation: only through the SDK's own abort API (an AbortSignal or context cancel on the in-flight call), where the SDK exposes one; for modern HTTP the cancellation signal is closing or aborting the live response stream, not finishing the request body and not an extra cancellation POST. Assert the incremental proxy aborts upstream on downstream disconnect. Test matching `notifications/cancelled` only where an official client can actually emit it; gateway must not send that notification upstream. If the official client cannot expose cancellation, report a capability SKIP with API evidence, not a simulated pass. Runtime semantics are **to confirm in CI**.

7. **`subscriptions/listen`.** Exercise only when both official SDK endpoints expose the method and stream lifecycle. Record delivered notification and clean end, opt-in, signed stream verification, and client-visible order. If either API is absent, report SKIP with evidence; never substitute a fake handler and label it official coverage. APIs are **to confirm in CI**.

8. **Tamper integrity.** A separate buffered tamper-only proxy case may alter a captured signed response and must prove fail-closed behavior: no success frame on stdout and no unverified result. Do not use the buffering proxy for stream or cancellation assertions. Exact error presentation is **to confirm in CI**.

For every cell record SDK names and immutable versions, path/profile, capability evidence, redacted bounded captures, client-visible outcome, signature oracle, and PASS/FAIL/SKIP reason. Never store credentials or signing secrets. Direct controls intentionally have no Jack signature oracle.

## Pins, lock bootstrap, fixtures

Do not hardcode an unverified SDK package version. A manually dispatched bootstrap workflow (not used by mandatory CI) should resolve the latest stable releases satisfying the `2026-07-28` profile and required feature gate, generate locks from fresh exact manifests with CI toolchains, and publish exact immutable package versions/commits plus lock artifacts and source references. Run API, stateless, stream, and cancellation capability probes. An owner reviews the evidence and commits the exact pins and lockfiles; mandatory CI then builds from committed locks with frozen/locked installs and never silently updates them. Bootstrap results are artifacts, not tracked files. Whether to use a separate workflow and the manifest format are owner decisions.

Candidate Go v1.7.0 is **to confirm in CI**. TypeScript, Python, and Rust modern-capable exact releases are **to confirm in CI**; resolve under the same rule, not by assumption. Existing legacy pins are baseline only. Whether Go stateless mode is required and how to configure it are **to confirm in CI**. No package-manager command is part of this design task.

Proposed scenario deadlines (all **to confirm in CI** after SDK profiles are established): client/server readiness 10s; direct ordinary tool 30s; bridge+gateway tool 45s; first stream event 10s; stream completion 30s; cancellation completion 10s; shutdown 5s. Measure the matrix, then set a 60–90 minute global job timeout. Fail on timeout with cell and phase recorded.

## Risks and controls

- SDK versions and APIs can drift; resolve immutable pins, commit lockfiles/artifact references, and build from those locks in mandatory CI. Exact supported versions and capabilities are **to confirm in CI**.
- Official servers may not emit progress/SSE or support stateless flags; probe each capability and report unsupported cells as SKIP, never PASS. These server/SDK capabilities are **to confirm in CI**.
- Whether Go stateless mode is required and how to enable it are **to confirm in CI**; probe before making it a fixture requirement.
- Cancellation APIs differ across SDKs; inspect/probe each client API and use transport closure where exposed. Exact APIs and semantics are **to confirm in CI**.
- The existing proxy buffers responses and does not cancel upstream when the downstream disconnects (`tools/mcp-e2e/lib/proxy.mjs`); use an incremental proxy that forwards streams and aborts upstream on disconnect for progress/cancellation cases.

## Disjoint leaf tasks and order

One task owns each listed file scope; no worker changes another scope. Parallel work is allowed only after stated interface dependencies.

A. **Pin/API audit and lock bootstrap.** Own only `tools/mcp-e2e-modern/pins/**` and, if approved, the new `.github/workflows/mcp-e2e-locks.yml`. Resolve exact immutable pins, source references, capability table, bootstrap artifact contract, and lock artifacts. Acceptance: reviewed versions and probes; no guessed capability. Depends on owner decision to include SDKs/bootstrap. Own the bootstrap workflow exclusively.

B1–B4. **Language fixtures.** Separate workers own respectively only `tools/mcp-e2e-modern/go/**`, `/ts/**`, `/python/**`, or `/rust/**`; no legacy fixture files. After pin audit and fixture protocol agreement, workers may run in parallel. Acceptance: builds from committed locks in CI, direct control for supported cases, and a capability manifest with evidence and explicit unsupported APIs.

C. **Driver, capture, and assertions.** Own only `tools/mcp-e2e-modern/run.mjs` and `tools/mcp-e2e-modern/lib/**`; no language fixture directories. Agree on fixture CLI/schema first, then parallelize with B. Acceptance: path/cell ledger, exact request observations, bounded incremental stream/frame capture, disconnect-to-upstream abort, live progress/cancellation oracles, signed refusal/tamper checks, redacted artifacts.

D. **Legacy documentation/skip correction.** Own only `tools/mcp-e2e/README.md` and `tools/mcp-e2e/lib/cell.mjs`; do not alter fixture or lock files. Parallel with modern work. Acceptance: README reflects the tracked locks; only the exact demonstrated TS-server limitation skips; missing artifacts fail. Verify in CI.

E. **Modern CI integration.** Own only the modern job stanza in `.github/workflows/ci.yml`; if bootstrap is approved, task A alone owns its separate workflow. Preserve the legacy job. Depends on pins and driver contract. Acceptance: isolated modern cache/job, locked builds, shipping CLI build, artifacts, measured timeout, and required-cell failures fail the job.

F. **Final review.** Reviewer owns no implementation files; review after A–E. Confirm no Events/custom-implementation claims, correct opt-in/refusal topology, signature verification before treating refusal as authentic, and cancellation by transport closure rather than upstream notification POST.

## Owner decisions

- Required official SDK set and minimum capability evidence for each cell?
- Approve manually dispatched latest-stable lock bootstrap, artifact review, and parent commit of exact pins/locks?
- Which cells are required versus capability-skippable?
- Modern job in `.github/workflows/ci.yml`; approve separate bootstrap workflow owned by A?
- Accept a minimal scripted legacy-only negative control if SDK servers cannot provide one?
- Confirm measured per-case deadlines and choose the global timeout within 60–90 minutes?
- Format of the pin manifest (one JSON file per language under `tools/mcp-e2e-modern/pins/` versus one shared file) and who approves a pin change?

## References

Repository locations relevant to implementation: `tools/mcp-e2e/README.md`, `tools/mcp-e2e/lib/cell.mjs`, `tools/mcp-e2e/lib/proxy.mjs`, `.github/workflows/ci.yml` (`mcp-compat-e2e`), `internal/cli/internal/bridge/bridge_modern.go`, `internal/cli/internal/gateway/gateway.go`, `internal/cli/internal/gateway/integration/gateway_profile_test.go`, `client/internal/stream/stream.go`, `spec/04-modern-profile.md`, and `spec/05-signed-streams.md`. Runtime behavior not explicitly backed by source review remains **to confirm in CI**.
