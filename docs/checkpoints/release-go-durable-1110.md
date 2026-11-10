# Go durable replay and rotation implementation — initial tranche

## Status

Task #57 is complete: PR #23 merged as bcfbc2565681be5a74fcc0c7d25a82a519afa5be after 33 successful exact-head checks and six successful post-merge workflows. Its task-owned worktree and local/remote branches were removed after source preservation and integration verification.

Task #59 is in progress, implemented directly by the parent at the owner's request; no replacement agent was launched. All feature changes remain in worktrees/release-go-durable-1110; primary main remains main. No local compiler, tests, generator, Node, formatter, installation or scanner has been run.

## Initial tranche

- Explicit candidate rotation package: strict record codec, both signature checks, retained-key continuity/reuse checks, bounded history, ordinal tie selection and strict final cutoff.
- Go tests read the committed independent candidate JSON corpus, compare all 19 negative outcomes, and reproduce new-key signatures with Go's standard Ed25519 implementation.
- The owner-approved whole-module Go floor is changed to 1.25.0 in the working branch, including consumer manifest/identity checks. Product versions and publication flags remain unchanged.
- A temporary branch-only source-preparation job in the existing materialization workflow formats rotation sources in CI, tests that package, and uploads exact formatted files for parent integration. It must be removed before final Task #59 delivery; no lint/test gate is weakened.

## Durable admission seam — second tranche

Head36cf789ea25290ce6b01cc2ae463eef004fff8c9 passed all34 PR checks after integrating formatted bytes. The next tranche adds an explicit DurableNonces profile (mutually exclusive with the legacy store), an atomic registry writer gate for MemoryState/FileState, exact receipt/intent identity validation, fresh post-ACK eligibility checks, and a serving lease carried until Result.Done/NewHandler completion. Invalid signatures never call storage. Receipt mismatch or post-ACK clock rollback fences without dispatch. Backend errors are sanitized; no database detail is exposed. Panic/normal paths release committed leases.

New pipeline regressions use a clearly test-only storage spy, not a purported durable adapter. They cover zero pre-auth storage calls, actual writer-gate ownership, exact receipt mismatch, unknown refusal/no handler effects, late ACK with consumed nonce but no authorization, post-ACK rollback, copied-result idempotent release, HTTP handler lifetime and panic cleanup. At source c81489ba259cdeea968551fa9658072e1ae42611, source-preparation run42843175106/job129923515952 passed go test ./rotation ./server on Go1.26.10. Artifact13775569518 (GitHub archive digest sha256:451187d33baba621740dbf76ef501d44973b995861a4bb976e08d404a089a923) was downloaded into a new isolated directory, its complete formatting diff reviewed, and all seven outputs integrated byte-for-byte with cmp. Rotation and middleware files were already identical. Only three materialization checks were initially visible; the full pull_request CI run42843426599 was queued, not green. A pr-check watcher exit0 alone must never be used as proof that missing jobs passed.

The temporary preparation job now formats and tests rotation plus changed server files, and uploads go-sdk-formatted-sources with rotation/ and server/ paths. Integrate its actual artifact after review; do not invoke a local formatter. No bbolt dependency has been added yet.

## Opaque record signing — third tranche

While full CI for formatted admission head77d99c2 was queued/running, the parent implemented CreateRecord using opaque old/next Signer interfaces. It constructs exact B/R bytes, checks the new proof before invoking the old authorizer, validates both returned signatures without retry, and does not publish or mutate trust. New tests compare the complete Go-produced records with both independent overlap/tie chains and assert zero signer side effects on invalid input and zero old authorization after failed/altered new proof. Two additional bounds regressions cover the implicit checkpoint's history slot and an out-of-domain ordinal. Execution is pending CI. Before committing this tranche, the parent verified head77d99c2b0a9c9e623fe74c9ba287c930bdfc959f has all34 checks SUCCESS; the prior admission/freshness/lifecycle tranche is therefore fully green, but remains partial Task #59 work.

The completed old full CI run42843426599 at c81489b failed only the unchanged gofmt checks for admission.go, admission_test.go and verify.go; its failed log was inspected. The correction had already been pushed as77d99c2 from the reviewed formatted artifact. Do not call either old failure or queued current checks successful.

## Remaining implementation

This initial tranche is not Task #59 completion or runtime support. Durable nonce/backend ownership, high-water, intent/final receipts, dirty startup and unknown-outcome recovery; coordinated registry/key/enrollment gates; bbolt dependency/advisory/license/platform qualification and checksum generation; server publication/signer lifecycle/native tool; client ClockGuard/full-snapshot CAS/manual refresh; production integration and fault/concurrency tests remain unfinished.

The current gateway still uses volatile nonce state and static response signing. No durable claim, migration, protocol freeze or release follows from the codec package or the Go-floor edit. Go package consumer staging must include the new package and later the exact dependency lock/graph once generated in CI. Existing consumer no-dependency assertions have not yet been migrated because no dependency has been added in this tranche.

## Next steps

Initial tranche 5d1ff4d5836ed1c46af0680b70094b3654088bef is in draft PR #24. CI run42839252662/job129909708121 passed go test ./rotation on Go1.26.10. Both main Go lanes failed the unchanged gofmt gate. Artifact13774328831 (go-rotation-formatted-sources; GitHub-reported archive digest sha256:51083c597dd717e0f90f81950ba154744d092f2f318eca37e7965bb3a0180a4b) was downloaded into a new isolated directory after one recoverable TLS timeout. The parent reviewed the formatting-only diff and integrated all three files byte-for-byte with cmp confirmation. Push this correction, start a fresh background watcher, then continue implementation directly; do not merge partial Task #59 work. Tests/builds/formatting/dependency lock generation stay in GitHub CI.

Preserve the original release-plan worktree, all historical checkpoints and the unknown untracked nested directory in main. No publication is authorized.
