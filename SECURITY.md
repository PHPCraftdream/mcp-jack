# Security policy

The protocol remains draft v0.1 and is **not frozen or independently audited**. Source includes Go, Rust and TypeScript SDKs plus a bounded Go CLI/gateway/stdio bridge. Neither their presence nor this documentation edit establishes full MCP compatibility, broader Task57 completion or release readiness. Current SDK nonce stores are in memory; server response-key rotation is not implemented. See the [threat model](docs/threat-model.md), [versioning and release policy](docs/versioning.md), and [candidate documents](spec/candidate/README.md).

Owner-selected future directions require separate technical design, implementation and acceptance: durable authenticated nonce reservation before native authorization/state mutation/handler dispatch, and multi-key server response rotation. The proposed details are not current protections. For D2, an unknown durable write outcome fails closed and is never automatically retried; a timestamp-startup floor is not selected. For D3, the selected direction permits arbitrary multiple pending announcements without a one-pending rule/cooldown, with OLD remaining in use until NEW takes over 48 hours after announcement. Candidate time anchors and ordering/cutoff details are technical defaults, not additional owner decisions. Neither direction establishes backend or SDK support.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Include the affected component (specification section, Go, Rust or TypeScript SDK, CLI), a description, and a reproduction if you have one.

You can expect an acknowledgement within a few days. Fixes are developed privately and disclosed together with the advisory.

## Scope

In scope: authentication and signature validation; nonce, freshness and replay behavior (including restart and durable-backend design); server response-key rotation and client pin transitions; enrollment, user-key rotation and protocol-admin checks; parser or serialization differences across SDKs; the `Jack-Auth` header and canonical encoding rules; CLI/gateway/stdio bridge boundaries; and credential handling. Report suspected issues in ordinary MCP authorization too, but note that the protocol does not supply a policy engine: authorization for ordinary MCP operations is application-owned. The protocol's `admin` privilege gates only native administrative tools.

Out of scope as secrets: the deterministic test keys in `spec/fixtures/keys.json`, public keys/vectors, and sample state documents under `spec/fixtures/`. They are public test material and must never be used outside tests. Findings involving their test-only status are not production credential compromise.

No test, build, runtime probe, scan or audit is claimed for this documentation edit. Local execution was skipped under the no-executable-commands restriction.
