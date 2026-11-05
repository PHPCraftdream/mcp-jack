# Security policy

mcp-jack is a security protocol, so reports about its specification or its SDKs are taken seriously. The project is an early draft (see the status line in the README); no release has been audited.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Include the affected component (specification section, Go, Rust or TypeScript SDK), a description, and a reproduction if you have one.

You can expect an acknowledgement within a few days. Fixes are developed privately and disclosed together with the advisory.

## Scope

In scope: signature, nonce, time-window and policy checks; enrollment and key rotation; parsing differences between the SDKs that let a request pass in one implementation and fail in another; the `Jack-Auth` header and canonical encoding rules.

Out of scope: the test keys in `spec/fixtures/keys.json` and the state files under `spec/fixtures/`. They are public test material and must never be used outside tests.
