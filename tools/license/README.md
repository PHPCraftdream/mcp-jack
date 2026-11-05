# Dependency licence checks

Policy and tooling behind the `license` GitHub workflow. The model is a
fail-closed allowlist: every dependency licence that is not explicitly allowed
fails CI, including licences that cannot be identified. The allowlists are
version controlled in this directory; the workflow runs on every push to main
and every pull request.

## What is checked

| Area | Tool (pinned) | Scope |
|---|---|---|
| Go | go-licenses v2.0.1 (`go install github.com/google/go-licenses/v2@v2.0.1`) | The module and all dependencies, including test-only imports (`--include_tests`). The Go module currently has no third-party dependencies; the job is the guard for future additions and validates the module's own dual licence. go-licenses evaluates no SPDX expressions: every licence file it detects must be on the allowlist (see OR and AND semantics). |
| Rust | cargo-deny 0.20.2 (pinned binary via `taiki-e/install-action@v2`, SHA256 verified) | The entire `Cargo.lock` graph: transitive and optional dependencies (`http`, `interop` features), dev-dependencies (`include-dev = true`), build-dependencies (on by default), and target-specific dependencies for every platform present in the lock (no target filtering). Policy: `rust/deny.toml`. Expression handling is proven by CI-only fixtures (`testdata/cargo-*`). |
| TypeScript | license-checker-rseidelsohn 5.0.1 (metadata only, exact version via `npx`) + SPDX evaluator (tooling/package-lock.json: spdx-satisfies 6.0.0, spdx-expression-parse 5.0.0, spdx-license-ids 3.0.24) | The installed tree after `npm ci`, dev dependencies included (the package itself has no runtime dependencies). Needs Node >= 24 (upstream `engines`). The checker only collects metadata; the policy decision evaluates full SPDX expressions (`tooling/eval.mjs`, installed by `npm ci` in `tools/license/tooling` from the committed lockfile; the JSON import attribute in `eval.mjs` requires Node >= 22, and the job pins 24). No packages are excluded: the old `--excludePrivatePackages` invocation silently skipped ANY package marked private, including third-party published packages, which fails open; every installed package is now evaluated, including this repository's own private roots, whose manifests declare `MIT OR Apache-2.0`. The licence tooling tree itself (`tools/license/tooling`) is scanned separately with the tooling-only allowlist `npm-tooling-allowed-licenses.txt` so its data licences never enter the product allowlist. Allowlist: `npm-allowed-licenses.txt` via `check-ts-licenses.sh`. |
| This repository | `check-own-license.mjs` (Node, no dependencies) | `rust/Cargo.toml` and `ts/package.json` must declare exactly `MIT OR Apache-2.0`; the root must contain exactly `LICENSE-APACHE` and `LICENSE-MIT`; the README must link both. Go modules have no licence field by design; the root licence files cover the Go module. |

Holding two licence files is the correct shape for a dual licence: recipients
choose one of the two (OR); they are not required to comply with both (AND).
The manifest check enforces the two-file dual shape and flags a third licence
file as a likely accident.

## Allowed licence categories and rationale

| Licence | Why allowed | Obligations to remember |
|---|---|---|
| MIT | Permissive; dominant in the current graph. | Keep copyright and licence text with distributions. |
| Apache-2.0 | Permissive with an explicit patent grant. | Section 4 attribution; NOTICE-file obligations on redistribution. |
| BSD-2-Clause | Permissive. | Notice preservation. |
| BSD-3-Clause | Permissive; used by `subtle`. | Notice preservation; non-endorsement clause. |
| ISC | Functionally equivalent to MIT. | Notice preservation. |
| Unlicense | Public-domain dedication; used by `memchr` (as `Unlicense OR MIT`). | None. |
| Unicode-3.0 | Required by the AND term of `unicode-ident` (`(MIT OR Apache-2.0) AND Unicode-3.0`). | Notice preservation. |
| CC0-1.0 | Only in the CI-only licence tooling tree: `spdx-license-ids` is the SPDX identifier list dedicated to the public domain. | None; the data is not redistributed by this repository. |
| CC-BY-3.0 | Only in the CI-only licence tooling tree: `spdx-exceptions`, and the CC-BY-3.0 branch of `spdx-ranges` (`(MIT AND CC-BY-3.0)`). | Attribution is owed if the data is ever redistributed; CI-only use redistributes nothing. These are SPDX data lists, not MIT-licensed code — the tooling-only allowlist records the declared expressions instead of rebranding them. |

Everything else is denied, including unknown, unlicensed, or non-SPDX
declarations, and all copyleft families (GPL, LGPL, AGPL, MPL, ...). A copyleft
licence may only enter through the exception process below.

### Tooling-only policy

The checker tooling's own dependency tree is covered by
`npm-tooling-allowed-licenses.txt`, scanned with the same fail-closed
evaluator. Its entries (MIT, Apache-2.0, CC0-1.0, CC-BY-3.0) apply ONLY to
`tools/license/tooling` and never widen the product npm allowlist; the
CC-BY-3.0/CC0-1.0 packages are SPDX data used at CI time and not shipped.

## OR and AND semantics

SPDX `OR` is satisfied when at least one branch is allowed, so a permissive
dependency is not rejected merely because another OR branch is copyleft. SPDX
`AND` requires every term to be allowed. What each tool actually does:

- cargo-deny (Rust) evaluates full expressions. Proven in CI by the
  licence-expression fixtures: `GPL-3.0-only OR MIT` passes an MIT-only
  allowlist, the same branches joined by `AND` are refused naming the crate
  and `GPL-3.0-only`, and a crate without any licence is refused
  (`testdata/cargo-or`, `testdata/cargo-and`, `testdata/cargo-unlicensed`).
- license-checker-rseidelsohn (TypeScript) only collects metadata (`--json`); the
  policy decision evaluates full SPDX expressions with the pinned
  `spdx-satisfies`/`spdx-expression-parse` tooling (`tooling/eval.mjs`): OR is
  satisfied by one allowed branch, AND requires every branch, and nesting is
  handled by the evaluator, not by string matching. Proven by the fixtures:
  `(MIT AND GPL-3.0-only) OR Apache-2.0` passes the real allowlist and fails
  without Apache-2.0, `MIT AND GPL-3.0-only` fails it, `GPL-3.0-only OR MIT`
  passes an MIT-only list, and `NotMIT` (unknown identifier), undetermined
  licences, guessed asterisk declarations, and ambiguous array metadata fail
  closed (`testdata/npm-fixture/`).
- go-licenses (Go) evaluates no SPDX expressions. Its check loop (check.go in
  the pinned v2.0.1 source) requires every licence file it detects for a
  library to be on the allowlist, by exact name. A permissive Go dependency
  that also carries a copyleft OR branch is therefore refused even though an
  OR conclusion would be permissible: a documented, conservative limitation
  of the tool, not silent misbehaviour. If such a case appears, resolve it
  with a reviewed decision recorded in the pull request for that exact
  module; do not widen the global allowlist to make the refusal disappear.

## Exceptions

Default is deny everywhere.

- Rust: `[[licenses.exceptions]]` in `rust/deny.toml`, per crate and
  version-bounded via the package spec (`crate = "name@1.2"`; the old
  `name`/`version` table keys are deprecated by cargo-deny). Template in
  `rust/deny.toml`.
- TypeScript: no per-package exception mechanism exists. The allowlist is a
  set of single SPDX licence identifiers (entries that are not one valid
  identifier fail the run), every identifier of every package expression is
  checked against the SPDX list, and unknown, undetermined, guessed,
  array-valued, or invalid declarations fail closed. The tooling-only
  allowlist (`npm-tooling-allowed-licenses.txt`) is a separate policy file
  for a separate tree, not a per-package exception mechanism.
- Go: no per-package exception mechanism exists. The allowlist is a set of
  global licence names and `check-go.sh` ignores comments; a commented entry
  has no effect. A narrow exception therefore requires an explicit, reviewed
  change to `tools/license/check-go.sh` together with its policy file,
  naming the module, version and justification.

The pull request adding any exception must justify what the licence is, why it
is compatible with distributing this work as MIT OR Apache-2.0, and why the
dependency cannot be avoided. Never add a licence ID globally as a way to
wave through a single package.

## Rejection controls

Every ecosystem runs a positive path first; then cases that must fail, and a
failure only counts as a refusal when the captured output names the offending
package/crate and licence. A crash, network error or usage error never counts
as enforcement:

- Go: the fixture module (`testdata/go-license-fixture/`, its only dependency
  is Apache-2.0 `github.com/google/go-cmp`) must pass the real allowlist;
  then `testdata/go-license-allow-mit-only.txt` must refuse it with evidence
  naming `go-cmp` and `Apache-2.0` (`go-fixture-controls.sh`).
- Rust: the real workspace must pass `rust/deny.toml`; then
  `testdata/deny-mit-only.toml` must fail with diagnostics naming
  Apache-2.0-only and BSD-3-Clause crates (`sync_wrapper`, `subtle`); the
  expression fixtures must behave as described under OR and AND semantics
  (`cargo-expression-controls.sh`).
- TypeScript: the real tree must pass the real allowlist; then
  `testdata/npm-allow-apache-only.txt` must refuse with evidence naming
  `@types/node` and `MIT`; the SPDX fixtures must behave as described under
  OR and AND semantics, with temporary installed trees materialized from
  tracked JSON and removed after each case (`npm-expression-controls.sh`).
- This repository: the repository itself must pass `check-own-license.mjs`,
  while `testdata/own-license-bad/` must fail it.

## Tooling versions and links

- go-licenses v2.0.1 - https://github.com/google/go-licenses (installed
  through the Go module proxy; the checksum database verifies the download).
  The licence-only job pins a dedicated modern local toolchain
  (`go-version: 1.25.x`, `GOTOOLCHAIN: local`) because go-licenses v2.0.1
  requires go >= 1.23.0 to build, and under GOTOOLCHAIN=auto the mismatch
  between the toolchain that built go-licenses and the `go` used for package
  listing makes go-licenses miss stdlib packages ("does not have module
  info", upstream #302/#335/#193, PR #364 unfixed in v2.0.1).
- cargo-deny 0.20.2 - https://github.com/EmbarkStudios/cargo-deny,
  configuration docs https://embarkstudios.github.io/cargo-deny/ (installed by
  taiki-e/install-action with SHA256 checksum verification).
- license-checker-rseidelsohn 5.0.1 -
  https://github.com/RSeidelsohn/license-checker-rseidelsohn (exact version
  via npx; npm verifies tarball integrity against registry metadata).

Tool version bumps are ordinary, reviewed changes that update the pin and this
file together.

## What a green check does not mean

A passing run is not legal advice and not distribution compliance. It checks
the licence declarations of the resolved dependency graphs at CI time only. It
does not discharge notice and attribution obligations: MIT, BSD, ISC,
Apache-2.0 and Unicode-3.0 all require preserving copyright and licence text
when distributing, and Apache-2.0 additionally requires NOTICE attribution.
Producing those artifacts (go-licenses `save`, cargo-about, or similar) is
deliberately out of scope here. A green check also says nothing about licence
changes upstream after the run.

## Running locally (optional)

CI is the authority. To reproduce a job:

```sh
go install github.com/google/go-licenses/v2@v2.0.1
bash tools/license/check-go.sh . tools/license/go-allowed-licenses.txt
bash tools/license/go-fixture-controls.sh

cargo install --locked cargo-deny@0.20.2
(cd rust && cargo deny --locked --all-features --config deny.toml check licenses)
bash tools/license/cargo-expression-controls.sh

(cd ts && npm ci --no-audit --no-fund)
(cd tools/license/tooling && npm ci --no-audit --no-fund)
bash tools/license/check-ts-licenses.sh ts tools/license/npm-allowed-licenses.txt
bash tools/license/check-ts-licenses.sh tools/license/tooling tools/license/npm-tooling-allowed-licenses.txt
bash tools/license/npm-expression-controls.sh

node tools/license/check-own-license.mjs
```
