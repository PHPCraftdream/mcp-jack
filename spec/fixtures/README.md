# spec/fixtures

Hand-maintained files in this directory:

- `client-url-policy.json` — SDK client URL policy test table (see docs/design/interop.md section 9). Not a protocol vector; not produced by `spec/tools/gen-fixtures.mjs`; not covered by its `--check`.
- `user-key-transfer.json` — SDK test table for local user-key transfer documents: key envelopes and server-issued client transfer credentials (see docs/design/user-keys.md). Hand-assembled from `keys.json` strings and fixed canonical templates; not a protocol vector, not produced by the generator, not covered by `--check`. Test runners compose the entries marked `compose` at test time and re-derive every key value themselves. The `context_cases` array carries structurally valid documents with expected trust outcomes, kept separate from the positive/negative classification; language lanes must also pass the fixture self-consistency checks defined in docs/design/user-keys.md section 11; these invariants apply to positives and structurally-valid context cases, while negatives retain deliberate mutations and assert their intended first failure.

Every other file here is a generated, normative protocol vector per [../README.md](../README.md).
