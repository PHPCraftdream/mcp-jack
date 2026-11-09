# Design: cross-language interoperability tests

Status: Go, Rust and TypeScript SDKs implement the reduced admin-only identity contract in baseline `b13b972`; shared interop matrix acceptance was verified in GitHub CI on `444c69b` (see readiness evidence). The scenario source of truth is [`interop/scenarios.json`](../../interop/scenarios.json). The harness exercises verified-identity forwarding through ordinary handlers and malformed required-boolean admin-input controls. The integrated harness passed on `444c69b`; see readiness for exact runs.

## Contract and boundaries

CI builds the client and server executables for each language; the harness runs cross-language pairs. Current SDK behavior is ordinary MCP pass-through after authentication, immutable verified identity `{kid, name, admin}` at the wrapped handler, and protocol `admin` gating only reserved `jack.admin.*` tools. Application authorization is independent. Legacy user/state `kind` or `scopes` data is rejected without migration or rewrite; no policy engine participates.

Preserve these cross-language properties in the matrix:

- Exact request body bytes are signed; deterministic signing vectors pin signing-string and header bytes.
- Request authentication includes strict key/signature validation, freshness and replay defense. Verification-only signing controls use fixed time and nonce inputs and therefore do not substitute for live checks.
- Response signatures are mandatory for authenticated responses, including application errors. Only protocol-defined authentication-failure 401 responses may be unsigned.
- Clients trust a separately pinned server identity; no TOFU or silent pin replacement.
- Administrative state changes retain last-active-admin protection.
- The test server's ordinary-MCP application decision must use the verified handler identity, not a protocol policy or request-supplied identity.

The current server CLI is `interop-server --aud <aud> --state <file> --server-seed-hex <64 hex>` with optional `--bootstrap-ttl <seconds>` or `--verify-only`; it takes no policy-file input. `--verify-only` checks fixed signing cases while omitting time-window and nonce validation. Client CLI and current case details are documented in [the harness README](../../interop/README.md); that document uses the scenario source as the source of truth.

## Layout and independent transfer contract

Language harness sources are `interop/go/{server,client,transfer}/`, `rust/src/bin/interop*.rs`, and `ts/src/interop/`. They are outside the public SDK APIs. `interop/run.mjs` coordinates request scenarios and signing controls; `interop/transfer.mjs` separately coordinates user-key transfer. The latter's envelope, strict import, independent trust tuple, and role-isolated key surfaces remain governed by [user-keys.md](user-keys.md) and its fixtures. Do not conflate its envelope `type` discriminator with the removed user `kind` field.

Shared harness matrix acceptance, packaged-consumer checks, and coverage/fuzz evidence for baseline `b13b972` were verified in GitHub CI on `444c69b` (see readiness evidence). Q1 session-channel work is future v0.2 design, not implemented. Q3 server-key rotation requires a separate exact design and is not implemented.

## 9. Client URL policy

Spec 01 section 1 requires HTTPS for every non-loopback connection. The Go, Rust and TypeScript client SDKs enforce one conservative, literal-only policy on the destination URL, pinned by `spec/fixtures/client-url-policy.json` (a table of `{name, url, allow}` cases, with an optional `parse_reject` field, that all three SDK test suites run). The table is the normative test oracle for the SDK URL policy, but it is hand-maintained: it is not a generated protocol vector, is not produced by `spec/tools/gen-fixtures.mjs` and is not covered by its `--check`. This section is its prose.

The policy is a pure function of the raw URL string. For raw-string entry points it is applied before any URL-library parsing or normalisation and only accepts or refuses: it never rewrites the URL. APIs given an already-parsed URL or Request can only check that object's serialized URL; they cannot recover the original spelling, as detailed in 9.4.

1. Refuse if the string is empty, contains any byte `<= 0x20`, `0x7f` or `>= 0x80`, or contains a backslash anywhere.
2. The scheme must be `http` or `https` (ASCII case-insensitive), followed by `://`.
3. The authority is the text after `://` up to the first `/`, `?` or `#` (or the end). Refuse if it is empty, contains `@` (no userinfo, for any scheme) or contains `%` (no percent escapes in the authority; this also refuses zone IDs such as `[fe80::1%25eth0]`). Percent-encoded path or query bytes (e.g. `/a%20b?x=%2F`) are not affected.
4. Host and port. With a leading `[`: exactly one `]`, directly after a non-empty IPv6 literal made only of `[0-9A-Fa-f:.]`, followed by the end or `:` plus a port; no other `[` or `]`. Without a leading `[`: no `[` or `]`, at most one `:` (more means unbracketed IPv6), and a non-empty host made only of `[A-Za-z0-9._-]`. A port, if a `:` is present, is 1 to 5 ASCII digits with value 1..65535 (`host:`, `0` and `65536` are refused; leading zeros within 5 digits are fine).
5. `https` is accepted for any host passing 1-4, remote or loopback. The host is used literally; the policy performs no DNS.
6. `http` is accepted only for a literal loopback host: canonical dotted-decimal IPv4 (exactly four decimal octets 0..255, no leading zeros, first octet exactly 127), or bracketed IPv6 whose content is exactly `::1` (hex case irrelevant, no other spelling). Everything else over `http` is refused, including `localhost` and any `*.localhost`, `127.1`, `127.0.1`, `0x7f.0.0.1`, `2130706433`, `0177.0.0.1`, `127.000.000.001`, `0.0.0.0`, `[::]`, `[::ffff:127.0.0.1]`, `[0:0:0:0:0:0:0:1]`, `127.0.0.1.nip.io` and every userinfo trick (`evil.example#@127.0.0.1` has the authority `evil.example`, so it is a remote host).
7. Path, query and fragment are not inspected beyond rule 1 (so `@` and `%` after the authority are fine, a space is not). Their bytes are untouched and signed as before; the fragment is never signed.

### 9.1 Why literal-only

- No DNS and no alias list: `localhost` can resolve to anything, and a resolve-then-connect check would leave a time-of-check/time-of-use gap between the address checked and the address connected. Judging only the literal string leaves nothing to race.
- Userinfo, percent escapes in the authority, backslashes and zone IDs are refused, not normalised. Percent-encoded path and query bytes stay accepted and are signed exactly as given. Different URL parsers disagree on them (which host a backslash or `@` selects, whether `%31%32%37` is `127`), and a parser disagreement between the check and the transport is the classic downgrade vector. Refusing keeps one reading of the string.
- Refusal happens locally, before signing and before any injected transport, `fetch` or network call. A refused URL produces no signature and no packet.
- The signed target bytes are unaffected: the policy changes nothing about what is signed, it only decides whether signing and sending proceed. The standalone pure signing helpers, which take no destination URL, are unchanged and not subject to the policy.

### 9.2 Redirects and TLS

- SDK-owned sending clients never follow redirects. They refuse exactly the redirect statuses 301, 302, 303, 307 and 308 (the ones HTTP clients follow) locally as an error, before verification and without surfacing `Location`, in all three SDKs. Other 3xx statuses, notably 304 Not Modified, are not redirects: they go through normal signature verification like any other answer (a correctly signed 304 with an empty body is returned; unsigned or tampered ones fail verification).
- Redirect refusal is a no-follow/no-downgrade guard: a signed request is never replayed or verified against another origin. It is not TLS enforcement.
- TLS certificate validation stays with the platform transport and is never weakened; there is no insecure or skip-verify option.

### 9.3 Remaining boundary

A caller-injected transport (Rust `Transport` trait, TypeScript `fetchImpl`, Go `Config.HTTP` or a base `RoundTripper`) is outside the SDK's control. It must use TLS for `https` URLs, connect to exactly the URL it is given, and not follow redirects. The SDKs cannot police arbitrary custom transport behaviour. In Go, `Config.HTTP` is always wrapped by the SDK signing/verifying transport; the caller's transport remains responsible for TLS and not following redirects.

### 9.4 Fixture contract

Rows are `{name, url, allow}` plus the optional `parse_reject` (array of SDK ids; only `"go"` is used). `allow=true` means the security policy accepts the URL. `parse_reject: ["go"]` on an `allow=true` row (only `allow-https-percent-in-fragment`, `https://svc.example.test#%`) means the policy still accepts it (the fragment is never sent or signed and is not inspected), but that SDK's platform URL parser (Go `net/url` rejects the invalid escape `%` in the fragment) additionally rejects it at the public constructors and profile loaders with the generic "must be an absolute http/https URL" error, which is not a policy error, and `http.NewRequest` cannot build it. Every other `allow=true` row is accepted by every public constructor and profile loader in all three SDKs, with no exception.

Per row, each runner exercises three entry paths:

1. Policy function on the raw string: `allow=true` must pass; `allow=false` must be refused with the policy error.
2. Public constructors and profile loaders (Go `NewClient`/`LoadProfile`/`NewClientFromProfile`, Rust `Client::new`/`load_profile`/`from_profile`, TS `new Client`/`loadProfile`/`validateProfile`/`clientFromProfile`): `allow=false` must be refused with the policy error before any signing or transport call; `allow=true` must succeed, except rows listing that SDK in `parse_reject`, which must fail with a non-policy (generic parse) error.
3. Low-level signing transport (Go `Transport.RoundTrip`, Rust `SigningTransport::round_trip`, TS `createSigningFetch`): `allow=false` means zero signer uses and zero inner transport/fetch calls; `allow=true` reaches the inner spy exactly once.

Go limitation: `Transport` sees only the already-parsed `req.URL`, so rows the Go parser rejects (`http.NewRequest` fails) or normalises (percent-decoded host, dropped or escaped path or fragment bytes) cannot be presented to `RoundTrip` as the raw string. The Go runner classifies each row explicitly as parser-rejected, refused-at-transport or parser-normalised, and asserts that the pre-parser policy rejects the raw string in every `allow=false` case. TypeScript `createSigningFetch` checks URL and Request inputs on their WHATWG-normalised `href` (`Request.url` or `URL.href`); a string input is checked as given. In server-side pure Fetch handling, `Request.url` is normalized and cannot recover the original target spelling. The `node:http` adapter preserves the exact received origin-form target in the exported `RAW_TARGET_SYMBOL` through verification and copies it to the reconstructed request for forwarding. This adapter metadata is separate from SDK-private identity storage in the WeakMap, which remains unaffected; pure Fetch cannot recover the original target.

Fragments are never signed. In TS, the comparison of the response URL against the request URL ignores the fragment.
