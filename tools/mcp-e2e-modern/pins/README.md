# Modern E2E SDK pins

Bootstrap artifacts are review input only; the owner approves and commits pins and locks.

## Placeholder schema

- `sdk`, `language`, `status`: identity, language, and resolution state (`unresolved` means unpinned).
- `packages`: split TypeScript entries, each with `name`, `role` (`client`, `server`, `tooling`), `version`, and `commit` (unresolved values are `null`).
- `umbrella`: informational `@modelcontextprotocol/sdk` entry with `informational: true` and nullable `version`; it is not a lock dependency.
- `module` (Go): module path. Go `version`, `commit`, and `release_url` are nullable placeholders.
- `protocol_version`: target `2026-07-28`; `protocol_supported` and all eight `capabilities` remain `null` until owner review; `no_probe` means the SDK behavior was not safely probed.
- `lockfiles`: manifest/lockfile names; `resolved_by` and `resolved_at` are nullable metadata.

## Bootstrap evidence and review

The resolver records latest and selected versions separately. It walks stable Go releases and npm versions newest-first within a bounded candidate list; when no candidate supports `2026-07-28`, it selects latest and still publishes locks with a note.

Evidence kinds are `probe`, `declared` (an SDK-declared protocol list), `source_match`, and `unknown` (reason `no_probe`, `no_evidence`, `probe_failed`, `download_failed`, or `source_search_error`), or `absent` only for a clean declared-list miss. TypeScript `latest` and `selected` each retain independent status/evidence; selected provenance is verified only when registry `gitHead`, the dereferenced GitHub tag commit, and an existing release tag agree.

The job fails on release-resolution, lock-generation, or report-write failure. Unknown/absent capabilities are recorded and do not fail the job. Dispatch `.github/workflows/mcp-e2e-locks.yml`; review the `mcp-e2e-pins-bootstrap` artifact, then the owner commits approved exact pins and locks. The workflow commits and pushes nothing.
