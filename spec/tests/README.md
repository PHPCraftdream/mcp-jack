# Conformance tests

An implementation (Go, Rust, JS) conforms to spec v0.1 when its test runner passes every case in:

- `fixtures/request-vectors.json`: server-side request verification and authorization;
- `fixtures/response-vectors.json`: client-side response verification;
- the key checks below.

[CASES.md](CASES.md) is the generated index of all cases.

## Request vectors

File shape: `{ "registry": "registry.json", "cases": [ ... ] }`. Each case:

| Field | Meaning |
|---|---|
| `id`, `description` | Stable identifier and a human description. |
| `state` | `now` (Unix s), `window_seconds`, `aud`, and `nonce_cache`: entries `{kid, nonce, retain_until}` already present. |
| `request` | `method`, `target`, `headers` (list of `[name, value]` pairs, names case-insensitive), `body_b64u` (exact body bytes, unpadded base64url). `body_text` is informative only. |
| `expect` | `result`: `accept` or `reject`. On accept: `kid`. On reject: `http_status` and `code`. Always `nonce_recorded`. |
| `debug` | Informative: the signing string the generator signed, line by line. In tamper cases it differs from what a verifier recomputes; that is the point of the case. |

Runner contract:

1. Load the registry named by the file and treat `state.now` as the current time (inject the clock; never read the wall clock).
2. Preload `state.nonce_cache`, run the verification-and-authorization path with `request`, and compare.
3. `http_status` and `code` MUST match exactly. `nonce_recorded` is `true` when this request caused a new `(kid, nonce)` entry to be stored. That is when authentication succeeded, including requests rejected only at the authorization step. It is `false` for earlier failures and for replays.
4. Cases are independent: reset state for each.

## Response vectors

Each case has `state` (`now`, `window_seconds`, `pinned_server_kid`, `pinned_server_public_key`, `request_sig`), `response` (`status`, `headers`, `body_b64u`) and `expect` (`accept`, or `reject` with `code`). `request_sig` is the `sig` of the request being answered.

## Key checks

`fixtures/keys.json` lists test keys. A runner MUST confirm for every key that:

- the Ed25519 public key derived from `seed_hex` equals `public_key`;
- `kid` equals `base64url(SHA-256(public_key))`.

Ed25519 signatures are deterministic (RFC 8032), so a runner SHOULD also re-sign `debug.signing_string_lines` (joined with LF) of every `accept-*` case with the key named by the header `kid` and compare with the `sig` in the header. Byte-identical signatures across Go, Rust and JS are the strongest interoperability check.

## Adding a case

Add it to `tools/gen-fixtures.mjs` with the expected outcome. The generator refuses to write fixtures when the reference verifier disagrees with the stated expectation, then regenerate and commit all generated files together.
