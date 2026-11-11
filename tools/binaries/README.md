# Development CLI binary qualification

This tool runs only in GitHub CI for the release work. It does not publish a
release, tag, registry package, or signed release candidate. No dependency or
product version is changed.

The `Go CLI portable artifact qualification` job builds `cmd/jack` for Linux,
Windows and Darwin, each on amd64 and arm64, with the explicitly approved CI
compiler and `CGO_ENABLED=0`. Each target is built twice from separate tracked
source extractions and separate fresh Go build caches. The verified Go module
cache is shared; this is a same-compiler/same-host two-build reproducibility
check, not an across-host or independent-toolchain certification. Build flags
remove source paths and implicit VCS stamping. Embedded Go build information is
checked for target, compiler, CGO, executable mode, trimpath and conservative CPU
baseline before inventory is accepted.

The output directory must be new. Successful qualification produces six binaries,
`inventory.json`, and `SHA256SUMS`. Inventory binds the actual checkout SHA (which
may be a GitHub PR merge checkout), the PR feature SHA, compiler/host, flags,
byte sizes and binary hashes. It records relative artifact names, not source,
cache, or machine-private paths. Both outputs must have identical bytes and size;
empty or mismatched artifacts fail. Failed/incomplete outputs are not uploaded.

Only a target matching the compiler host executes a bounded `jack help` smoke.
Its stdout must be empty and stderr must contain the CLI usage. All other targets
are explicitly `cross-compile-only-not-native-qualified`; successful compilation
does not prove native private-storage, signal, process, TLS, filesystem or restart
behavior. The host help smoke is not lifecycle acceptance either: the separate
mandatory shipping-binary job supplies that proof for the qualified Linux profile.
In particular, no Windows/macOS or Linux-arm64 durable-backend acceptance is
inferred from this artifact inventory.

Standard-library Python unit tests exercise target coverage, embedded metadata
rejection, exact hashes/sizes and mismatched/empty output refusal. Their synthetic
byte fixtures are never executed. The CI job invokes the tool with isolated
Python mode, an exact expected checkout SHA and a fresh runner-temporary output
directory. Do not execute downloaded artifact scripts or treat checksums as
release signing, provenance attestations, a MAC, or backup-rollback evidence.
