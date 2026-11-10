# Rust and TypeScript SDK group — candidate implementation

## Scope and ownership

Group60 is in progress in worktrees/release-sdk-rust-ts-1110, branch release-sdk-rust-ts-1110, based on delivered candidate spec/fixtures merge bcfbc2565681be5a74fcc0c7d25a82a519afa5be. The parent works directly; no agent was launched. This is independent of group59's Go worktree and preserves its acceptance/merge dependency gates. Primary checkout stays main; original plan worktree, unknown nested directory, historical checkpoints and local checkpoint commit4c5749d remain untouched.

## Initial TypeScript tranche

- Additive namespace rotation exports candidate codec/chain primitives; existing auth, client/server trust, static credentials and private-export boundaries are unchanged.
- Strict bounded ASCII12-line records, canonical decimals/base64url, exact scalar UTF-8 endpoint/audience binding, canonical admitted public keys/key IDs, checked172800 activation, both Ed25519 proofs and full-record hash.
- Contiguous extension from independently trusted checkpoint, previous full-record hash/adjacent signer/publication order/retained-key reuse and bounded1153-key history including implicit checkpoint.
- Frozen records and arrays contain only immutable scalar values, not mutable key/proof buffers. No input buffers are retained.
- Greatest eligible ordinal on equal activation; assignment lower bound and strict known cutoff checked against both signed timestamp and final raw sample.
- Tests execute all19 independently committed negative fixtures and both positive overlap/tie chains, compare exact wire bytes/full hashes, and check unknown-authorizer refusal, buffer ownership, malformed Unicode, numeric boundaries and retained-key reuse.

These are primitives only: no automatic refresh, pagination, persistence ACK, durable server profile, rotation trust/controller, native publication or runtime delivery is claimed. Endpoint BOM bytes are preserved by fatal UTF-8 decoding with ignoreBOM=true; unpaired JavaScript surrogates are rejected by an exact scalar round trip.

## Verification and remaining work

No local Node/compiler/build/tests/fuzz/install/formatter/scanner was run. No new dependency, version, MSRV or publication flag changed. Existing SDK crypto/base64url modules are reused; expected crypto bytes/checksums are not fabricated. New implementation/tests await actual GitHub CI; no green receipt exists yet.

Rust code has not been touched. Before Rust implementation, load rust-intel and inspect exact Cargo.lock/API/MSRV1.88 baseline. Group60 still requires full Rust implementation, TS server/client/durable ACK/failure/controller integration, bounded actual Rust fuzz campaigns and TS property/mutation controls, independent oracles, full consumers/feature isolation/security gates. New tooling dependencies require verification/approval. Node20/22, TS7 and downstream declarations TS5.9 remain existing acceptance lanes. Both SDKs must meet their own gates before group60 completes; partial green is not merge readiness.

## Opaque signing tranche — pending CI

The first source5530ddf2184baaea5e7d561bfe008eb08ea65060 has actual TypeScript test evidence: ci42877540931/job130044753766 on LinuxNode20 passed325tests,0fail, including all four candidate rotation tests. LinuxNode22/job130044753860, WindowsNode22 and consumerNode22/job130044753968 also succeeded. Full acceptance was not yet complete; remaining queued security/interop checks cannot be called green.

The next tranche reuses only the publicKey/sign capabilities of the existing client Signer through a type-only Pick, with no private export, publication, persistence, retry or trust mutation. Binding/checkpoint/public/message/signature snapshots are owned before provider callbacks. Invalid inputs fail before signing; NEXT proof is verified before OLD is invoked, and provider errors are sanitized. Tests compare complete newly signed overlap/tie records with independent committed bytes, require zero signing on invalid inputs, reject altered NEXT messages before OLD, verify call ordering/no retry, preserve exact BOM binding and resist provider mutation of inputs/public/proof buffers. Shared scalar-binding validation remains internal to the package namespace. New signing code/tests await CI; no local execution occurred.

At4b1929b5f6fd908d27e2ab6b7ddbbb52e0dcdc5b, TS build:test/coverage failed before tests executed: test/rotation.test.ts(130,18) TS2345, next-altered not assignable to never. Completed Linuxjob130057863893 and coveragejob130057864058 logs were read. The Node assert.deepEqual(calls,[]) assertion narrowed the captured array to never[]; replace only that empty-array assertion with assert.equal(calls.length,0), which preserves the exact no-signing requirement without a type cast or production change. New signing tests still require successful CI execution; the earlier325-test receipt applies only to5530ddf.

## Verified signing baseline and bounded mutation controls

Exact46c572f34571b3a5a07679d3245bc126bb656f54 passed all33 PR checks; watcher bo71ygwu1 completed exit0 and full count/SHA were independently confirmed. Actual LinuxNode20 job130064163261/run42883072342 logs show all eight candidate codec/signing tests executed and total329tests/pass329/fail0. The prior TS2345 is therefore fixed and verified. This is not full group60 acceptance or permission to merge the partial draft.

The next test tranche flips one ASCII bit at every byte position of one independently signed valid record, with a fixed maximum1024-byte corpus and test timeout30seconds. Every changed wire must be rejected by the SDK; the untouched record must still pass. This oracle derives from exact signed-byte binding, not a duplicate parser. Separate bounded cases require lexical ordinal/timestamp errors for leading zeros, signs, fractions, exponents, whitespace, non-numbers and unsafe integers before signature verification. These new mutation controls await CI and were not run locally.

## Delivery constraints

Implementation/commit/push/green-merge/post-merge/source-preserving cleanup were authorized by the owner. No new agents after the stop/self-work instruction. All execution remains in GitHub CI; start background gh watch immediately after every push/PR-ready/rerun and consume terminal results. Inspect exact SHA and full expected check set, not only watcher exit0 or initially visible materialization jobs. Any failure must be diagnosed and fixed in the same cycle. Product versions/private/publish flags and publication remain unchanged; final publication requires new explicit owner permission.
