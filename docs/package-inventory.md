# Package metadata and artifact inventory

**Scope:** source-defined inventory of the packaging metadata and consumer lanes at the current main. This is a source inventory, not an executed package receipt or actual archive extraction report. Historical foundation CI receipts are recorded in git history and [`CHANGELOG.md`](../CHANGELOG.md). No local commands or checks were run for this inventory.

## Metadata intent and current boundaries

At merged foundation SHA `c98f7eb0dac9ad22f11f712a80a3fe9c537426ee`, the Rust manifest had no client-and-server description, keywords, categories, or explicit `readme` field, and the TypeScript manifest had no `description` or `keywords`. The current checked-in manifests carry that descriptive metadata: Rust description (“Client and server SDK for authenticated MCP over HTTP, with verified caller identity, protocol admin tools, and audit.”), keywords `mcp`, `authentication`, `ed25519`, `client`, `server`, categories `authentication`, `cryptography`, `network-programming`, and explicit `readme = "README.md"`; TypeScript description (“MCP HTTP client and server SDK for signed messages, verified caller identity, protocol admin tools, and audit.”) and the same keywords. Existing license and repository metadata are unchanged. The protocol `admin` bit gates reserved administration; ordinary MCP authorization remains the integrating application's responsibility.

At the merged foundation SHA, Rust crate `mcp-jack` was version `0.1.0`, edition 2021, MSRV 1.88, and `publish = false`; TypeScript `mcp-jack` was version `0.0.0`, `private: true`, Node `>=20`, with its existing ESM root exports. The current source sets both package versions to `0.1.0`; the `publish = false` / `private: true` guards were removed on the owner's order. Go remains `github.com/PHPCraftdream/mcp-jack` with `go.mod` declaring `go 1.25.0`. Rust `Cargo.lock` is tracked. The owner-ordered 0.1.0 package versions are recorded here; this description does not authorize edition, dependency, or publication changes.

At the merged foundation SHA, the Rust migration pinned optional `hickory-resolver`, `hickory-net`, and `hickory-proto` to exact 0.26.1 versions behind `client-http`; development `time` was exact 0.3.47, requiring `time-core` 0.1.8. Foundation CI's Rust MSRV and consumer lanes used 1.88. No claim here substitutes source inspection for build, package, or scanner evidence.

## Source-defined consumer artifacts

The workflow definitions and package/verification scripts define these outputs. Inventories are generated in CI scratch space; they are not committed archive receipts.

| CI upload name | Artifact filename and inventory | Source of member list | Consumer wiring |
|---|---|---|---|
| `consumer-go-artifact` | `go-module-snapshot.tgz` and `inventory.json` | `{ module, goVersion, files, snapshot }`; tracked paths matching module scope | `package-go.mjs` stages `module/`, then CI tars that directory. **`verify-go.mjs` consumes the staged directory, not the uploaded tarball**: consumer `replace` points to `../module`. The archive is an uploaded inspection artifact, not the bytes used by this consumer verification. |
| `consumer-rust-artifact` | `mcp-jack-0.1.0.crate` and `inventory.json` | `{ artifact, members, version }`; `members` comes from sorted `cargo package --list`, not archive extraction | `verify-rust.mjs` extracts the `.crate`, compares extracted names to the saved list, and consumes the extracted crate in a fresh standalone consumer on Rust 1.88, without copying the product lockfile. |
| `consumer-ts-node20-artifact`, `consumer-ts-node22-artifact` | Each uploads `mcp-jack-0.1.0.tgz` and `inventory.json` | `{ name, version, artifact, members }`; actual `npm pack --json` file list, normalized and sorted | `verify-ts.mjs` installs the staged tarball, checks installed members against the inventory, and runs consumer checks against that installed package. |

The Go snapshot excludes root README/CHANGELOG, `docs/`, `cmd/`, `internal/`, Rust, TypeScript, tooling, and interop; it includes all tracked `spec/**`, including documentation, fixtures, tools, and tests. Rust packages its crate README, not repository-level documentation. The TypeScript tarball includes its package README; its allowlist contains no CHANGELOG or docs tree. These lanes do not deliver CLI, gateway, or bridge binaries.

### Source-defined member checks (not extraction receipts)

Optional allowed members below are not guaranteed to appear in an artifact.

- **Go:** allowed scope is root `*.go`, `go.mod`, both root license files, every `*.go` under `client/`, `server/`, `rotation/`, `durable/` and `userkey/` (nested folders included), `internal/jacktest/*.go`, and all tracked `spec/**`. Required members include `go.mod`, `spec/spec.go`, both licenses, and every root-level Go file. Staging checks module identity and `go 1.25.0`, exact license bytes, and excludes `go.sum`. Verification checks scope/required members, byte-compares staged `go.mod` to the repository manifest, rejects `go.sum`, and uses `replace github.com/PHPCraftdream/mcp-jack => ../module`. The standalone smoke covers credentials and signed loopback client/server flow, including wrong-server-pin and tampered-request rejection. It does not compare the complete staged snapshot byte-for-byte to source or consume the uploaded tarball.
- **Rust:** required members are `Cargo.toml`, `src/lib.rs`, `README.md`, both licenses, and every `.rs` under the product crate's `src/**`. The Rust interop harness is a separate unpublished crate under `interop/rust/`, outside the packaged SDK crate; its binaries are not part of the product package, and the product crate has no `interop` feature. Allowlist: `Cargo.toml`, optional `Cargo.lock`, `Cargo.toml.orig`, `deny.toml`, `.gitignore`, `.cargo_vcs_info.json`, README, both licenses, `src/**`, and `tests/**`; the inventory does not assert whether Cargo includes `Cargo.lock`. Verification extracts the crate and compares extracted names with `cargo package --list`, byte-compares packaged `.gitignore` and licenses, and checks version `0.1.0`, MSRV `1.88`, license expression, and `default`, `http`, and `client-http` product features. The fresh standalone consumer resolves from the extracted crate without copying the product lockfile and compares its independently generated lockfile against the tracked product lockfile; it exercises default, `client-http`, and `server-http` configurations (`server-http` maps the SDK `http` feature).
- **TypeScript:** required members: `package.json`, `README.md`, both licenses, `dist/index.js`, and `dist/index.d.ts`. Allowlist: these root files, and every `dist/**` JS and declaration file (nested folders included); library build excludes `src/interop`. Staging removes `scripts` and `devDependencies`. Verification installs the tarball, requires installed member equality with npm-pack inventory, compares installed licenses byte-for-byte with repository copies, typechecks the public package-root import, and runs the loopback credentials/signed-message smoke including wrong-pin and tampered-request rejection.

The package lanes use Go 1.25.0 (the `consumer go 1.25` CI lane), Rust 1.88, and Node 20/22; the vulnerability-scan jobs run Go 1.26.11, which is not a consumer-package lane and does not change the Go language floor. Go compatibility is not a deployment security endorsement. Rust and TypeScript package versions are now `0.1.0`; the `publish = false` and `private: true` guards were removed on the owner's order. Publication happens only through the owner-dispatched manual workflows; tags and release decisions remain unauthorized.

## Historical CI evidence and boundary

Historical foundation CI receipts (PR-head and post-merge runs of 2026-11-09, covering the matrices, vulnerability scans, licence checks, coverage, Go fuzz, fixtures and consumer lanes) are recorded in git history and [`CHANGELOG.md`](../CHANGELOG.md). They apply only to their exact recorded SHAs and do not constitute inspection receipts for downloaded archive members or any release acceptance.

## Evidence boundary and future gate

At the merged foundation source SHA, `.github/workflows/ci.yml` defined upload names/paths; `tools/consumer/package-{go,rust,ts}.mjs` defined staging and inventory creation; `tools/consumer/verify-{go,rust,ts}.mjs` defined consumer inputs and checks. Upload steps use `if: always()`, which does not establish package/verification success. This source inventory contains no generated inventory, downloaded artifact, extraction receipt, or per-artifact inspection evidence.

At the merged foundation baseline, the workflows provided the named consumer archives/snapshot and inventories, but no explicit project SHA-256 checksum file, release-candidate binary job, or artifact-attestation generation/verification job. Any future artifact receipt must identify one exact full source SHA and workflow run/attempt, actual artifact IDs/names/filenames, platforms/toolchains, actual inventories and extracted members where applicable, independent per-file SHA-256, attestation subject/source verification if required, and evidence that required consumers used those exact produced bytes. Before relying on any historical check inventory for required-check or RC decisions, re-enumerate the actual workflow check contexts, matrix legs, and toolchains against that exact candidate SHA after any changes; do not assume the historical inventory still applies. Do not substitute a checkout rebuild, registry package, or unrelated run. Artifact presence alone is insufficient.

Historical task references (foundation PR #16, post-merge verification Task **#54**, receipt consolidation Task **#96**) are recorded history, not pending prerequisites. Artifact-only RC scope has no registry publication; registry publisher/trusted-publisher ownership is deferred and not an artifact-only RC prerequisite. Further version changes, tags, publication, and release decisions remain separately deferred. Repository settings are unverified. No release-readiness, dependency-vulnerability, license-audit, or security-review result is asserted by this inventory.

## Historical integration note

Foundation PR #16 post-merge verification and cleanup (Task **#54**) are complete and recorded in git history; PR #17 was a later CLI delivery candidate. These are dated historical facts only and imply nothing about current checks or acceptance.

## Source references

- [Versioning and release policy](versioning.md) and [release plan](release-plan.md).
- [Threat model](threat-model.md) and [dependency-scanning policy](security-dependencies.md).
- [Release-foundations checkpoint](checkpoints/release-foundations-1109.md).
- [Consumer workflow](../.github/workflows/ci.yml); [Go package](../tools/consumer/package-go.mjs), [Go verify](../tools/consumer/verify-go.mjs); [Rust package](../tools/consumer/package-rust.mjs), [Rust verify](../tools/consumer/verify-rust.mjs); [TypeScript package](../tools/consumer/package-ts.mjs), [TypeScript verify](../tools/consumer/verify-ts.mjs).
- Package metadata and README sources: [Rust manifest](../rust/Cargo.toml), [Rust README](../rust/README.md), [TypeScript manifest](../ts/package.json), [TypeScript README](../ts/README.md).
