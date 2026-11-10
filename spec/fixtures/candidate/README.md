Candidate JSON fixtures are generated artifacts and are not committed here. The checked-in `spec/tests/candidate/CASES.md` is a source note, not the generated index; `spec/tools/candidate/fixture-build.mjs` owns that destination, and generation overwrites the note. The strict `--check` expects the generated index there, so it reports stale until generation has materialized it.

The candidate generator is the source-preparation authority. It writes these files when explicitly run by the candidate fixture workflow (not locally in this work item):

| Generated output | Purpose |
|---|---|
| `rotation-vectors.json` | Exact B/R records, signed positive and negative cases, and parser expectations |
| `nonce-vectors.json` | Durable admission/restart event inputs and hand-stated state/effect oracles |
| `rotation-state-vectors.json` | Signed response carriers, rotation snapshot inputs, state events, and hand-stated local outcomes |
| `../../tests/candidate/CASES.md` | Human-readable index rendered from the same source expectations |

CI sequence: `node spec/tools/candidate/gen-fixtures.mjs` → `node spec/tools/candidate/gen-fixtures.mjs --check` → `node spec/tools/candidate/verify-fixtures.mjs` → `node --test spec/tests/candidate/*.test.mjs` → upload `spec/fixtures/candidate/{rotation-vectors,nonce-vectors,rotation-state-vectors}.json` and generated `spec/tests/candidate/CASES.md`. The ordered receipt is pending; no commands were run in this work item. Until the owning Task 57 integration and CI run are complete, treat all candidate artifacts as source-only. The outputs are not in the worktree and no verifier/test receipt has been generated or claimed.

Client-side rotation failures such as `rotation_result_invalid`, `rotation_record_invalid`, `rotation_conflict`, `rotation_gap`, `rotation_bridge_expired`, `rotation_state_changed`, `rotation_state_unknown`, `rotation_key_interval`, `rotation_clock_unsafe`, and `rotation_clock_unavailable` are local errors, not HTTP responses. Only the candidate server-native tool error mapping is HTTP status-bearing.
