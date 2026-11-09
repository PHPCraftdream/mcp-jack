# Package metadata and artifact inventory

**Scope:** source-defined consumer-package metadata and workflow wiring at merged foundation baseline `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`. This is a source inventory, not an executed package receipt or actual archive extraction report. Parent-verified CI evidence for PR head `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` is recorded separately below; it does not prove post-merge success or validate packaging-metadata changes in this candidate. No local commands or checks were run for this inventory.

## Metadata intent and current boundaries

At merged foundation SHA `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`, the Rust manifest description was “Secure transport protocol wrapping MCP: authentication, authorization, audit (server SDK)”; it declared no `keywords`, `categories`, or explicit `readme` field. The crate packaging script requires and Cargo packages `rust/README.md`. The TypeScript manifest identified the `mcp-jack` ESM package and its root exports, without `description` or `keywords`; its package README describes the SDK. The protocol `admin` bit gates reserved administration; ordinary MCP authorization remains the integrating application's responsibility.

The unvalidated packaging candidate currently present in the source manifests proposes/applies a descriptive metadata bundle: Rust client-and-server description (“Client and server SDK for authenticated MCP over HTTP, with verified caller identity, protocol admin tools, and audit.”), keywords `mcp`, `authentication`, `ed25519`, `client`, `server`, categories `authentication`, `cryptography`, `network-programming`, and explicit `readme = "README.md"`; TypeScript description (“MCP HTTP client and server SDK for signed messages, verified caller identity, protocol admin tools, and audit.”) and the same keywords. Existing license and repository metadata are unchanged. These pending descriptive edits are not covered by foundation CI and are not validated by the historical receipts below.

At the merged foundation SHA, Rust crate `mcp-jack` was version `0.1.0`, edition 2021, MSRV 1.88, and `publish = false`; TypeScript `mcp-jack` was version `0.0.0`, `private: true`, Node `>=20`, with its existing ESM root exports. The candidate retains those package versions and publication restrictions. Go remains `github.com/PHPCraftdream/mcp-jack` with language directive 1.22. Rust `Cargo.lock` is tracked. This description does not authorize version, edition, dependency, or publication-flag changes.

At the merged foundation SHA, the Rust migration pinned optional `hickory-resolver`, `hickory-net`, and `hickory-proto` to exact 0.26.1 versions behind `client-http`; development `time` was exact 0.3.47, requiring `time-core` 0.1.8. Foundation CI's Rust MSRV and consumer lanes used 1.88. No claim here substitutes source inspection for build, package, or scanner evidence.

## Source-defined consumer artifacts

The workflow definitions and package/verification scripts define these outputs. Inventories are generated in CI scratch space; they are not committed archive receipts.

| CI upload name | Artifact filename and inventory | Source of member list | Consumer wiring |
|---|---|---|---|
| `consumer-go-artifact` | `go-module-snapshot.tgz` and `inventory.json` | `{ module, goVersion, files, snapshot }`; tracked paths matching module scope | `package-go.mjs` stages `module/`, then CI tars that directory. **`verify-go.mjs` consumes the staged directory, not the uploaded tarball**: consumer `replace` points to `../module`. The archive is an uploaded inspection artifact, not the bytes used by this consumer verification. |
| `consumer-rust-artifact` | `mcp-jack-0.1.0.crate` and `inventory.json` | `{ artifact, members, version, publish }`; `members` comes from sorted `cargo package --list`, not archive extraction | `verify-rust.mjs` extracts the `.crate`, compares extracted names to the saved list, and consumes the extracted crate in a fresh standalone consumer on Rust 1.88, without copying the product lockfile. |
| `consumer-ts-node20-artifact`, `consumer-ts-node22-artifact` | Each uploads `mcp-jack-0.0.0.tgz` and `inventory.json` | `{ name, version, private, artifact, members }`; actual `npm pack --json` file list, normalized and sorted | `verify-ts.mjs` installs the staged tarball, checks installed members against the inventory, and runs consumer checks against that installed package. The package remains private. |

The Go snapshot excludes root README/CHANGELOG, `docs/`, `cmd/`, `internal/`, Rust, TypeScript, tooling, and interop; it includes all tracked `spec/**`, including documentation, fixtures, tools, and tests. Rust packages its crate README, not repository-level documentation. The TypeScript tarball includes its package README; its allowlist contains no CHANGELOG or docs tree. These lanes do not deliver CLI, gateway, or bridge binaries.

### Source-defined member checks (not extraction receipts)

Optional allowed members below are not guaranteed to appear in an artifact.

- **Go:** allowed scope is root `*.go`, `go.mod`, both root license files, `client/*.go`, `server/*.go`, `userkey/*.go`, and all tracked `spec/**`. Required members include `go.mod`, `spec/spec.go`, both licenses, and every root-level Go file. Staging checks module identity and `go 1.22`, exact license bytes, and excludes `go.sum`. Verification checks scope/required members, byte-compares staged `go.mod` to the repository manifest, rejects `go.sum`, and uses `replace github.com/PHPCraftdream/mcp-jack => ../module`. The standalone smoke covers credentials and signed loopback client/server flow, including wrong-server-pin and tampered-request rejection. It does not compare the complete staged snapshot byte-for-byte to source or consume the uploaded tarball.
- **Rust:** required members are `Cargo.toml`, `src/lib.rs`, `README.md`, both licenses, and every `.rs` under `src/**`. Allowlist: `Cargo.toml`, `Cargo.lock`, `Cargo.toml.orig`, `deny.toml`, `.gitignore`, `.cargo_vcs_info.json`, README, both licenses, `src/**`, and `tests/**`. Verification extracts the crate and compares extracted names with `cargo package --list`, byte-compares packaged `.gitignore` and licenses, and checks `publish = false`, version `0.1.0`, MSRV `1.88`, license expression, and `default`, `http`, `client-http`, and `interop` features. The fresh standalone consumer resolves from the extracted crate without the product lockfile and exercises default, `client-http`, and `server-http` configurations; `server-http` maps the SDK `http` feature. Its generated consumer lockfile must differ byte-wise from the tracked product lockfile.
- **TypeScript:** required members: `package.json`, `README.md`, both licenses, `dist/index.js`, and `dist/index.d.ts`. Allowlist: these root files, root `dist/*.{js,d.ts}`, and direct `dist/client/*` / `dist/server/*` JS and declaration files; library build excludes `src/interop`. Staging retains `private: true` while removing `scripts` and `devDependencies`. Verification installs the tarball, requires installed member equality with npm-pack inventory, compares installed licenses byte-for-byte with repository copies, typechecks the public package-root import, and runs the loopback credentials/signed-message smoke including wrong-pin and tampered-request rejection.

At the merged foundation baseline, the package lanes used Go 1.22, Rust 1.88, and Node 20/22. The separately approved Go 1.26.10 security-scanning toolchain was not a consumer-package lane and did not change the Go 1.22 language floor; Go compatibility is not a deployment security endorsement. The candidate retains package versions and publication restrictions; its workflow/toolchain inventory must be checked against its exact SHA before reliance.

## Parent-verified CI evidence and boundary

The parent reports **all 32 PR checks SUCCESS** on exact tested PR head `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b`, including both 3×3 matrices, all six vulnerability scans, Rust 1.88 MSRV, and fresh consumer. **Historical evidence recorded 2026-11-09:** workflow run IDs:

| Workflow | Run ID | Result | Exact tested SHA |
|---|---:|---|---|
| Main CI | `42709461708` | SUCCESS | `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` |
| Vulnerabilities | `42709461656` | SUCCESS (all six scans) | `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` |
| Licenses | `42709462005` | SUCCESS | `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` |
| Coverage | `42709461764` | SUCCESS | `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` |
| Go fuzz | `42709461672` | SUCCESS | `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` |
| Fixtures | `42709452435` | SUCCESS | `8ee8858ec5d9802d02da1d9086e00be61e3e1d9b` |

Run attempts were not supplied. These successful receipts apply to the **PR head only**. PR #16 merged at `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`; the PR-head results do not demonstrate checks on that merge SHA. Post-merge success is recorded in the parent integration receipt below. The PR-head consumer checks do not constitute inspection receipts for downloaded archive members, do not validate packaging-metadata changes in this candidate, and do not establish Task #96 RC evidence or release acceptance.

## Evidence boundary and future gate

At the merged foundation source SHA, `.github/workflows/ci.yml` defined upload names/paths; `tools/consumer/package-{go,rust,ts}.mjs` defined staging and inventory creation; `tools/consumer/verify-{go,rust,ts}.mjs` defined consumer inputs and checks. Upload steps use `if: always()`, which does not establish package/verification success. This source inventory contains no generated inventory, downloaded artifact, extraction receipt, or per-artifact inspection evidence.

At the merged foundation baseline, the workflows provided the named consumer archives/snapshot and inventories, but no explicit project SHA-256 checksum file, release-candidate binary job, or artifact-attestation generation/verification job. A future Task **#96** candidate receipt must identify one exact full source SHA and workflow run/attempt, actual artifact IDs/names/filenames, platforms/toolchains, actual inventories and extracted members where applicable, independent per-file SHA-256, attestation subject/source verification if required, and evidence that required consumers used those exact produced bytes. Before relying on any foundation check inventory for required-check or RC decisions at a future Task #96 SHA, re-enumerate the actual workflow check contexts, matrix legs, and toolchains against that exact candidate SHA after any changes; do not assume the foundation inventory still applies. Do not substitute a checkout rebuild, registry package, or unrelated run. Artifact presence alone is insufficient.

Foundation PR #16 is merged. The foundation policy is delivered; Task **#54** post-merge verification and cleanup are complete. Future Task #96 production and verification receipts and repository-settings evidence are not prerequisites for foundation policy acceptance. Task #96 consolidates production receipts and verification/final disposition in one task; this document does not assert that it is complete. Artifact-only RC scope has no registry publication; registry publisher/trusted-publisher ownership is deferred and not an artifact-only RC prerequisite. Future version changes, tags, publication, and release decisions remain separately deferred. Repository settings are unverified. No release-readiness, dependency-vulnerability, license-audit, or security-review result is asserted by this inventory.

## Source references

- [Versioning and release policy](versioning.md) and [release plan](release-plan.md).
- [Threat model](threat-model.md) and [dependency-scanning policy](security-dependencies.md).
- [Release-foundations checkpoint](checkpoints/release-foundations-1109.md).
- [Consumer workflow](../.github/workflows/ci.yml); [Go package](../tools/consumer/package-go.mjs), [Go verify](../tools/consumer/verify-go.mjs); [Rust package](../tools/consumer/package-rust.mjs), [Rust verify](../tools/consumer/verify-rust.mjs); [TypeScript package](../tools/consumer/package-ts.mjs), [TypeScript verify](../tools/consumer/verify-ts.mjs).
- Package metadata and README sources: [Rust manifest](../rust/Cargo.toml), [Rust README](../rust/README.md), [TypeScript manifest](../ts/package.json), [TypeScript README](../ts/README.md).

## Parent integration receipt — 2026-11-09

After the worker handoff, parent verified all six post-merge workflows SUCCESS on exact merge SHA `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`: CI `42710339786`, vulnerabilities `42710340244`, licenses `42710339825`, coverage `42710340223`, Go fuzz `42710339895`, and fixtures `42710339912`. Primary main was fast-forwarded and ancestry verified. Six completed foundation worktrees and their local branches, plus the remote foundation branch, were removed after byte-verified preservation of source deltas. Task #54 is complete. These are foundation receipts, not evidence for this packaging candidate or any RC/settings acceptance.

PR #17 remains an unmerged CLI candidate. Its initial head `8c769b36bdb862dca9136b73ad331915d395f73b` failed the Linux raw-close test oracle; correction head `9b6778acaa474a162426cc918b9c1708d61acacc` is undergoing full CI. No CLI delivery acceptance is claimed. Repository settings remain UNVERIFIED and future RC receipt fields remain unfilled. These dated facts supersede earlier handoff timing only; recheck the exact future candidate before reliance.
