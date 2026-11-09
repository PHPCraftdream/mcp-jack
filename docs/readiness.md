# SDK coverage readiness review

## Current baseline contract and evidence boundary

Baseline `b13b972` migrates the Go, Rust, and TypeScript SDKs to admin-only protocol identity. Authenticated ordinary MCP requests are forwarded unchanged; the application authorizes from immutable verified identity `{kid, name, admin}`. `admin` gates only reserved `jack.admin.*` tools. Legacy user/state `kind` and `scopes` records are rejected without migration or rewrite. Q1 session-channel work is a future v0.2 direction; Q3 server-key rotation needs a separate exact design. This is a static documentation reconciliation, not runtime verification or a green-status report.

GitHub CI verified the integrated candidate `444c69b` for shared interop, packaged consumers, coverage, and fuzzing; exact evidence follows below. The current scenario source of truth is `interop/scenarios.json`.

## Current test-source inventory (static file inventory, not results)

- **Go:** root-level primitive, conformance and key tests (`base64_test.go`, `ed25519_test.go`, `header_test.go`, `spec/fixtures_test.go`); client transport/profile/signing tests under `client/`; verifier, identity, audit, state, native-tool and middleware tests under `server/`; key and transfer tests under `userkey/`.
- **Rust:** integration tests under `rust/tests/`, including `keys_conformance.rs`, `verify_conformance.rs`, `responses_conformance.rs`, `admin_conformance.rs`, `http_layer.rs`, `state_file.rs`, client transport/URL policy, and `user_key_transfer.rs`.
- **TypeScript:** tests under `ts/test/`, including auth/signing and verification vectors, `native.test.ts`, audit, nonce/state, Fetch and Node HTTP adapters, client transport/URL policy, and `user-key-transfer.test.ts`.
- **Shared contract data:** `spec/fixtures/` contains authentication, key, response, admin, state-file, URL-policy, and independent user-key-transfer fixtures. Fixture files are conformance sources; their presence does not establish a passing lane.
- **Interop and integration:** `interop/scenarios.json` is the current source of truth. The harness implements ordinary-handler verified-identity forwarding and malformed required-boolean admin-input controls. Matrix acceptance, package-consumer, coverage, and fuzz results for this baseline are recorded for `444c69b` in readiness evidence.

This inventory reports files and contract areas only. No local builds, tests, generators, harnesses, fuzz campaigns, or runtime probes were run for this review.

## Verified integration evidence — 2026-11-09

The reviewed integration commit is `444c69b1908277cd9a803726286ea90bd5ea2e12` in PR #14. All 28 checks completed successfully, including the temporary two-lane scoped Go workflow. Its narrower checks are now redundant with the passing standing full-module Go, Windows and race jobs; the temporary workflow is removed in the following delivery commit. These receipts apply to `444c69b`, not to an untested future commit, merge, release or publication.

- [Standing SDK, real request and credential-transfer 3×3 matrices, and standalone packaged consumers](https://github.com/PHPCraftdream/mcp-jack/actions/runs/42615582574).
- [Coverage and summarizer controls](https://github.com/PHPCraftdream/mcp-jack/actions/runs/42615582383).
- [Six bounded real Go fuzz targets and failure-source/discovery self-tests](https://github.com/PHPCraftdream/mcp-jack/actions/runs/42615582429).
- [Licence checks](https://github.com/PHPCraftdream/mcp-jack/actions/runs/42615582415).
- [Fixture generation](https://github.com/PHPCraftdream/mcp-jack/actions/runs/42615573302); fixture freshness also passed in standing CI.

| Product metric at `444c69b` only | Covered / measured | Result |
|---|---:|---:|
| Go statements | 1,910 / 2,194 | 87.06% |
| Rust LLVM lines | 7,014 / 7,427 | 94.44% |
| TypeScript V8 lines in loaded emitted JavaScript | 4,596 / 4,832 | 95.12% |

These are unlike metrics, not comprehensive branch/path coverage. Go helper and interop groups are separate; the Go unit-coverage interop group is 0/842 statements because separate interop processes are not covered by that profile. TypeScript records 58 loaded files and 3 unloaded files; its separately measured interop code is not part of the product percentage. Successful real matrices and packaged-consumer runs are separate execution evidence, not coverage instrumentation of those processes. No new registry publication, tag, release, dependency or MSRV change was made.

Each of the six real fuzz targets executed for at least 30 seconds, with minimization bounded at 10 seconds: request auth, response auth, body classification, profile load, envelope import and credential validation. Missing/duplicate/empty target discovery, tool failure, log loss, corpus scan/copy failure and run-all aggregation controls passed. Finite fuzzing does not establish absence of bugs.

## Historical CI evidence — exact earlier commit only

All links, measurements, and campaign results in this section belong exclusively to commit `deeb29fc5a18d5a876f0e2e6c3166dec0ee9b63e`. They are not new measurements and do not apply to baseline `b13b972`.

- [Native SDKs, race/MSRV/Node matrices, fixtures, interop matrices and independent consumers](https://github.com/PHPCraftdream/mcp-jack/actions/runs/42489931871)
- [Licence checks](https://github.com/PHPCraftdream/mcp-jack/actions/runs/42489931896)
- [Coverage reports and summarizer regression controls](https://github.com/PHPCraftdream/mcp-jack/actions/runs/42489931954)
- [Bounded Go fuzz campaign and controls](https://github.com/PHPCraftdream/mcp-jack/actions/runs/42489931886)

| Historical metric at `deeb29fc5a18d5a876f0e2e6c3166dec0ee9b63` only | Covered / measured | Earlier result |
|---|---:|---:|
| Go statements | 2,025 / 2,331 | 86.87% |
| Rust LLVM lines | 7,232 / 7,683 | 94.13% |
| TypeScript V8 lines in loaded emitted JavaScript | 4,830 / 5,080 | 95.08% |

Those unlike metrics do not measure comprehensive branch coverage. The earlier CI also reported a finite bounded Go fuzz campaign passing on that exact commit; a finite campaign is not proof that bugs are absent. Neither the percentages nor the fuzz result establish anything about `b13b972`.

## Limitations to keep in view

The old readiness snapshot noted that fuzzing was Go-only, Go statement coverage is not branch coverage, Rust stable coverage is line/region-based, and TypeScript coverage is measured on emitted JavaScript. Server byte caps bound bytes rather than time; Go and TypeScript client timeout behavior is largely delegated to caller transports. These are design constraints to consider when interpreting future reports, not claims that current-baseline checks have run.

No release, merge, publishing, or dependency decision follows from this review. npm `private: true`, Rust `publish = false`, versions, and MSRV are outside this documentation change.
