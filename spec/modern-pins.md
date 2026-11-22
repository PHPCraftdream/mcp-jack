# Pinned upstream revisions for the modern profile

The modern-profile specs ([04](04-modern-profile.md), [05](05-signed-streams.md), [06](06-webhooks.md)) and their vectors were written against these upstream texts, read on 2026-11-22. Any later change upstream is a new profile decision, not a silent update.

| Source | Revision | Note |
|---|---|---|
| MCP specification | `2026-07-28` ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog), [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)) | Replaces the `2025-11-25` handshake and sessions; the legacy profile stays supported. |
| MCP Events extension (`io.modelcontextprotocol/events`, SEP-3415) | [ext-events](https://github.com/modelcontextprotocol/ext-events) `c77b84395eff0ae32f53b0516c2214fe276ed050` (2026-11-20), `specification/beta/events/events.mdx` | Beta extension. |
| MCP Server Card extension (SEP-2127) | [experimental-ext-server-card](https://github.com/modelcontextprotocol/experimental-ext-server-card) `28db12c9b4a379489d46e49bf1bd4a991f05c9b7` (2026-11-19) | `Remote.extensionsInfo` (PR 55) is merged here. |
| Standard Webhooks | [standard-webhooks](https://github.com/standard-webhooks/standard-webhooks) `3d65b1824b6697f05a5a4584e7062bd23512fc8e` (2026-11-18) | `v1a` is deprecated there in favour of `v2a`; MCP Events still names `v1a`, so both are verified. |

Fixtures are generated only by the `spec fixtures` workflow (`modern-generate` job) from `tools/modern/gen-modern.mjs`; never edit `fixtures/modern/` or `tests/modern/CASES.md` by hand.
