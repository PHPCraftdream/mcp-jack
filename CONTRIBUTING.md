# Contributing

Thanks for your interest. The project is an early draft: the specification (`spec/`) is the authority, and the Go, Rust and TypeScript SDKs follow it. When an SDK and the spec disagree, the spec wins and the SDK is fixed.

## Ground rules

- Everything in the repository is in English: code, comments, docs, commit messages.
- A behavior change starts in `spec/` and its fixtures (`spec/tools/gen-fixtures.mjs` regenerates them; CI checks that they are up to date). Then every SDK gets the same change.
- No private paths, secrets or personal data in commits.
- Keep comments short and explain why, not what.

## Checks

CI runs all of these; run what applies to your change before opening a pull request.

| Area | Commands |
|---|---|
| Go | `gofmt -l .`, `go vet ./...`, `go test -race ./...` |
| Rust (`rust/`) | `cargo fmt --check`, `cargo clippy --locked --all-targets --all-features -- -D warnings`, `cargo test --locked --all-features` |
| TypeScript (`ts/`) | `npm ci --no-audit --no-fund`, `npm run typecheck`, `npm test` |
| Fixtures | `node spec/tools/gen-fixtures.mjs --check` |
| Interop (3 x 3 matrix) | build the executables as in `interop/README.md`, then `node interop/run.mjs` |
| Licences | CI-only: the `license` workflow; policy and rationale in `tools/license/README.md` |

### Licence checks

The `license` workflow enforces dependency licence compatibility for all three SDKs against the allowlists in `tools/license/`: Go (module plus all dependencies, test imports included), Rust (the whole `Cargo.lock` graph, including optional `http`/`interop` features, dev, build and platform-specific crates), and TypeScript (installed tree, dev dependencies included). It also verifies that the repository itself consistently declares the dual licence. Unknown or unlisted licences fail the build; see `tools/license/README.md` for the policy, the allowed licence categories and the exception process.

## Licence

By contributing you agree that your contribution is dual licensed under MIT OR Apache-2.0, as described in the README, without additional terms.
