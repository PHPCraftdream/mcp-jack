This crate is the Rust SDK for mcp-jack, the secure transport protocol wrapping MCP with authentication, the admin flag and audit: server verifier and tower layer (feature `http`), client and native tools, mirroring the Go SDK. It is checked against the same conformance vectors in spec/fixtures. Its fixture-loading tests read ../spec/fixtures in place rather than embedding copies.

## Tower HTTP adapter (feature `http`)

`JackLayer` (Go: `server.NewHandler`) wraps an existing tower `Service`, buffers each request body up to `max_body_bytes` (default 1 MiB), verifies it and answers protocol-native `jack.*` tools itself. The admin flag gates exactly the `jack.admin.*` tools (`403 admin_required`; an undefined `jack.` name is `403 operation_denied`); everything else is forwarded unchanged to the inner service for any authenticated caller (no `tools/list` filtering), and the inner response is buffered and signed, so `text/event-stream` responses are refused with 501 (v0.1 cannot sign streams). The inner response is buffered up to `max_response_bytes` (default 1 MiB, independent of `max_body_bytes`; exactly the limit passes). Beyond it the answer is a signed 502 `response_too_large`: upstream status, headers and partial body are discarded, and the answer is a fresh JSON response with its own `Content-Type` plus the `Jack-Auth` signature header (no upstream header survives); the inner body is dropped. Limits of the cap: it bounds bytes read, not time. A body that never yields a frame, or yields only empty frames, is not stopped by it (empty frames add no bytes and are not retained, but the adapter keeps awaiting). A deadline on the inner service covers only obtaining the response (headers + body handle), not the later body consumption, which happens in the adapter's future; a deadline covering body consumption must wrap the whole `JackService` produced by `JackLayer` (tower timeout or `tokio::time::timeout` around the call; the caller's responsibility, this crate has no timeout option). The inner service's own allocations before it returns its response are not bounded. Inner service errors propagate unchanged. The inner service must accept `http::Request<http_body_util::Full<bytes::Bytes>>` — wrap a hyper/axum-style service accordingly (this crate does not depend on axum).

**Verified caller identity (spec 02 section 3).** The tower layer inserts `mcp_jack::server::identity::VerifiedIdentity` — a `{kid, name, admin}` snapshot taken at verification time — as a typed request extension into every forwarded request (ordinary MCP POST and GET); handlers read it via `req.extensions().get::<VerifiedIdentity>()`. It has no public constructor or setter, and it is `Clone`, so a handler may retain its snapshot. Native `jack.*` calls never reach the wrapped handler and therefore carry no identity. Registry changes affect subsequent requests while an in-flight handler keeps its snapshot.

```rust,ignore
use bytes::Bytes;
use http_body_util::Full;
use mcp_jack::server::http::{HandlerConfig, JackLayer};
use tower::Layer as _;
use mcp_jack::server::verify::{Config, Verifier};
use std::sync::Arc;

let verifier = Verifier::new(Config {
    aud: "https://mcp.example/mcp".to_owned(),
    state: Arc::new(state_store),
    nonces: Arc::new(nonce_store),
    audit: None,
    native: Some(Arc::new(native_tools)),
    window_seconds: 0,
    now: Arc::new(|| unix_seconds()),
})?;
let layer = JackLayer::new(HandlerConfig {
    verifier: Arc::new(verifier),
    server_key,
    max_body_bytes: 0,
    max_response_bytes: 0,
});
let service = layer.layer(tower::service_fn(
    |req: http::Request<Full<Bytes>>| async move {
        Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(Bytes::new())))
    },
));
```

## Client (`mcp_jack::client`)

### Client URL policy

Spec 01 section 1 requires HTTPS for any non-loopback connection. `Client::new`, `load_profile`, `Client::from_profile` and `SigningTransport` (`round_trip` / `round_trip_as`) apply one literal-only policy to the raw destination URL string, locally, before signing and before the injected `Transport` is called (normative table: `spec/fixtures/client-url-policy.json`; prose: `docs/design/interop.md` section 9):

- `https` is accepted for any host with valid syntax (no DNS is done).
- `http` is accepted only for a literal canonical `127.x.y.z` (four decimal octets, no leading zeros) or `[::1]`. `localhost` and its aliases, `127.1`, hex/octal/integer IPv4, `[::ffff:127.0.0.1]` and every other spelling are refused over `http`.
- Userinfo (`@` in the authority), percent escapes in the authority (so no zone IDs), backslashes, spaces, control and non-ASCII bytes, bad ports (valid: 1..=65535) and other schemes are refused.
- Path, query and fragment are not inspected beyond the byte rule; percent-encoded path/query bytes are accepted and the signed target stays byte-for-byte as configured (e.g. `/a%20b?x=%2F`).
- Redirects are never followed: `SigningTransport` refuses exactly the statuses 301, 302, 303, 307 and 308 with an error and does not verify them against the old target. This is a no-follow guard (a signed request must not be verified against another target), not TLS enforcement. Other statuses, including 300 and a signed 304, are verified as usual.

Transport obligations: an implementation must use TLS with certificate validation for `https` URLs, connect to exactly the URL in `HttpRequest::url` (the wire URL must equal the signed one), not follow redirects (301/302/303/307/308: return them as is) and not downgrade or rewrite the URL. There is no insecure or skip-verify option. The SDK ships no HTTP implementation behind the default features and cannot police a custom `Transport`; it only refuses locally what it can see. The optional `client-http` feature ships a TLS-validating HTTP/1 implementation; a finite asynchronous deadline is applied, but exact wall-clock completion is not guaranteed because task cleanup can add bounded scheduling overhead. Custom transports remain possible and outside the SDK's control.

### Optional HTTP transport (feature `client-http`)

`client-http` enables `HttpTransport`, a blocking HTTP/HTTPS `Transport` implemented with Hyper's low-level HTTP/1 client, a current-thread Tokio runtime, rustls with the ring provider, and Hickory DNS. Each round trip runs on its own joined standard thread; its registered DNS and HTTP-driver tasks are closed, aborted, and awaited before return. The builder snapshots system DNS configuration, hosts, and certificate roots during `build()`, outside the round-trip deadline. Those local file/registry reads are not interruptible and construction can fail because of the environment; `HttpTransport::new()` returns a `Result`, and `Default` currently panics if construction fails. The default deadline is 15 seconds. The runtime deadline bounds asynchronous round-trip work, not exact wall-clock return. No claim is made that all runtime properties have been verified.

Pass the RAW transport to `Config.transport: Arc<dyn Transport>`; `Client` wraps it in `SigningTransport` exactly once. For standalone signing use, wrap it in `SigningTransport` yourself. Caller headers (including repeated `Jack-Auth` values) are sent as given. CONNECT, caller framing headers (`Content-Length`/`Transfer-Encoding`), duplicate `Host`, non-UTF-8 `Host`/`Authorization`, and nonempty bodies on methods other than POST/PUT/PATCH are refused locally. Any valid HTTP token method (e.g. `PROPFIND`) is transmitted byte-exactly.

```rust,ignore
use std::sync::Arc;
use std::time::Duration;
use mcp_jack::client::http_transport::HttpTransport;
use mcp_jack::client::transport::{HttpRequest, SigningTransport, Transport as _};

let transport = HttpTransport::builder()
    .timeout(Duration::from_secs(15))
    .trusted_certificates_der(Vec::new()) // empty: default WebPKI roots
    .build()?;
let signing = SigningTransport {
    transport,
    aud: "https://svc.example.test".to_owned(),
    signer: Arc::new(signer),
    server_key,
    now: Arc::new(|| unix_seconds()),
    nonce: Arc::new(|| mcp_jack::client::random_nonce().map(|n| n.to_vec())),
    window_seconds: 0,
};
let resp = signing.round_trip(HttpRequest {
    method: "POST".to_owned(),
    url: "https://svc.example.test/mcp".to_owned(),
    headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
    body: body_bytes,
})?;
```

For the usual `Client` path, hand the raw transport to `Config.transport`:

```rust,ignore
use std::sync::Arc;
use mcp_jack::client::rpc::{Client, Config};
use mcp_jack::client::http_transport::HttpTransport;

let client = Client::new(Config {
    base_url: "https://mcp.example.test/mcp".to_owned(),
    aud: "https://svc.example.test".to_owned(),
    signer: Arc::new(signer),
    server_key,
    transport: Arc::new(HttpTransport::new()?),
    now: None,
    nonce: None,
    window_seconds: 0,
})?;
```

Status and guarantees: TLS certificate and hostname validation are enabled; `trusted_certificates_der` replaces the default roots (empty input selects WebPKI roots). URL policy is checked locally, fragments are stripped, and the HTTP/1 origin-form target remains byte-exact. Duplicate request header values are appended in order. Redirects are not followed; environment proxies are not used; there are no retries or connection pool/reuse/cache. No automatic `User-Agent`, `Accept`, or `Accept-Encoding` headers are added. `text/event-stream` is refused on response headers. Response bytes are streamed and capped at `MAX_BODY_BYTES + 1`; the raw transport returns those bytes and `SigningTransport` refuses an oversized response. Status and repeated response headers are preserved; cross-header wire order is not.

The configured absolute deadline is an asynchronous round-trip budget covering DNS, connect, TLS, send, headers, and body; it is not an idle timeout reset on progress. Owned resolver and HTTP-driver tasks are closed, aborted, and awaited before return; cleanup and runtime scheduling can extend wall-clock return beyond the budget. Builder-time reads are outside that deadline and are not interruptible. The transport is blocking and HTTP/1 only; callers in async contexts must avoid blocking runtime workers. This describes implementation structure, not independently verified runtime behavior.

#### Dependency graph and licence impact

At the client-http transport integration (`f34e25d`), the product graph had 183 exact package/version pairs (182 third-party plus this crate), compared with the prior 104-pair client-http/ureq graph. This paragraph and the table below record that historical comparison, not the current dependency inventory; the current versions are in `Cargo.lock`. It retains every original third-party baseline pair unchanged, removes four ureq-only pairs (`ureq@3.4.3`, `ureq-proto@0.6.5`, `utf8-zero@0.8.1`, `base64@0.23.1`), and adds 83 pairs relative to the prior graph. The list below records the added pairs' published Cargo metadata license expression and declared `rust_version`; `UNKNOWN` means undeclared. It is all-target graph metadata, not platform activation or build proof.

| Package@version | License | MSRV |
|---|---|---|
| async-trait@0.1.92 | MIT OR Apache-2.0 | 1.71 |
| bitflags@2.13.2 | MIT OR Apache-2.0 | 1.56.0 |
| bumpalo@3.20.3 | MIT OR Apache-2.0 | 1.71.1 |
| critical-section@1.2.0 | MIT OR Apache-2.0 | UNKNOWN |
| crossbeam-channel@0.5.17 | MIT OR Apache-2.0 | 1.60 |
| crossbeam-epoch@0.9.21 | MIT OR Apache-2.0 | 1.61 |
| crossbeam-utils@0.8.23 | MIT OR Apache-2.0 | 1.60 |
| data-encoding@2.11.1 | MIT | 1.48 |
| displaydoc@0.2.7 | MIT OR Apache-2.0 | 1.71.0 |
| enum-as-inner@0.6.1 | MIT/Apache-2.0 | UNKNOWN |
| equivalent@1.0.3 | Apache-2.0 OR MIT | 1.6 |
| form_urlencoded@1.2.2 | MIT OR Apache-2.0 | 1.51 |
| futures-channel@0.3.34 | MIT OR Apache-2.0 | 1.71 |
| futures-io@0.3.34 | MIT OR Apache-2.0 | 1.36 |
| getrandom@0.3.4 | MIT OR Apache-2.0 | 1.63 |
| getrandom@0.4.3 | MIT OR Apache-2.0 | 1.85 |
| heck@0.5.0 | MIT OR Apache-2.0 | 1.56 |
| hickory-proto@0.25.2 | MIT OR Apache-2.0 | 1.71.1 |
| hickory-resolver@0.25.2 | MIT OR Apache-2.0 | 1.71.1 |
| icu_collections@2.1.1 | Unicode-3.0 | 1.83 |
| icu_locale_core@2.1.1 | Unicode-3.0 | 1.83 |
| icu_normalizer@2.1.1 | Unicode-3.0 | 1.83 |
| icu_normalizer_data@2.1.1 | Unicode-3.0 | 1.83 |
| icu_properties@2.1.2 | Unicode-3.0 | 1.83 |
| icu_properties_data@2.1.2 | Unicode-3.0 | 1.83 |
| icu_provider@2.1.1 | Unicode-3.0 | 1.83 |
| idna@1.1.0 | MIT OR Apache-2.0 | 1.57 |
| idna_adapter@1.2.1 | Apache-2.0 OR MIT | 1.82 |
| ipconfig@0.3.4 | MIT/Apache-2.0 | 1.71 |
| ipnet@2.12.2 | MIT OR Apache-2.0 | UNKNOWN |
| js-sys@0.3.107 | MIT OR Apache-2.0 | 1.81 |
| litemap@0.8.3 | Unicode-3.0 | 1.82 |
| lock_api@0.4.14 | MIT OR Apache-2.0 | 1.71.0 |
| moka@0.12.16 | (MIT OR Apache-2.0) AND Apache-2.0 | 1.71.1 |
| parking_lot@0.12.5 | MIT OR Apache-2.0 | 1.71 |
| parking_lot_core@0.9.12 | MIT OR Apache-2.0 | 1.71.0 |
| portable-atomic@1.15.0 | Apache-2.0 OR MIT | 1.34 |
| potential_utf@0.1.6 | Unicode-3.0 | 1.82 |
| ppv-lite86@0.2.21 | MIT OR Apache-2.0 | 1.61 |
| r-efi@5.3.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | 1.68 |
| r-efi@6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | 1.68 |
| rand@0.9.5 | MIT OR Apache-2.0 | 1.63 |
| rand_chacha@0.9.0 | MIT OR Apache-2.0 | 1.63 |
| rand_core@0.9.5 | MIT OR Apache-2.0 | 1.63 |
| redox_syscall@0.5.18 | MIT | UNKNOWN |
| resolv-conf@0.7.6 | MIT OR Apache-2.0 | 1.61 |
| rustversion@1.0.23 | MIT OR Apache-2.0 | 1.31 |
| scopeguard@1.2.0 | MIT OR Apache-2.0 | UNKNOWN |
| stable_deref_trait@1.2.1 | MIT OR Apache-2.0 | UNKNOWN |
| synstructure@0.14.0 | MIT | 1.71 |
| tagptr@0.2.0 | MIT/Apache-2.0 | UNKNOWN |
| thiserror@2.0.21 | MIT OR Apache-2.0 | 1.77 |
| thiserror-impl@2.0.21 | MIT OR Apache-2.0 | 1.77 |
| tinystr@0.8.5 | Unicode-3.0 | 1.82 |
| tinyvec@1.13.3 | Zlib OR Apache-2.0 OR MIT | UNKNOWN |
| tracing@0.1.44 | MIT | 1.65.0 |
| tracing-core@0.1.36 | MIT | 1.65.0 |
| try-lock@0.2.5 | MIT | UNKNOWN |
| url@2.5.8 | MIT OR Apache-2.0 | 1.63 |
| utf8_iter@1.1.0 | Apache-2.0 OR MIT | 1.83 |
| utf_types@1.0.0 | Apache-2.0 OR MIT | 1.83 |
| uuid@1.26.1 | Apache-2.0 OR MIT | 1.85.0 |
| want@0.3.2 | MIT | UNKNOWN |
| wasip2@1.0.1+wasi-0.2.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 1.82.0 |
| wasm-bindgen@0.2.130 | MIT OR Apache-2.0 | 1.81 |
| wasm-bindgen-macro@0.2.130 | MIT OR Apache-2.0 | 1.81 |
| wasm-bindgen-macro-support@0.2.130 | MIT OR Apache-2.0 | 1.81 |
| wasm-bindgen-shared@0.2.130 | MIT OR Apache-2.0 | 1.81 |
| widestring@1.2.1 | MIT OR Apache-2.0 | 1.58 |
| windows-registry@0.6.1 | MIT OR Apache-2.0 | 1.82 |
| windows-result@0.4.1 | MIT OR Apache-2.0 | 1.82 |
| windows-strings@0.5.1 | MIT OR Apache-2.0 | 1.82 |
| wit-bindgen@0.46.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 1.82.0 |
| writeable@0.6.4 | Unicode-3.0 | 1.82 |
| yoke@0.8.4 | Unicode-3.0 | 1.82 |
| yoke-derive@0.8.4 | Unicode-3.0 | 1.82 |
| zerocopy@0.8.63 | BSD-2-Clause OR Apache-2.0 OR MIT | 1.56.0 |
| zerocopy-derive@0.8.63 | BSD-2-Clause OR Apache-2.0 OR MIT | UNKNOWN |
| zerofrom@0.1.8 | Unicode-3.0 | 1.71.1 |
| zerofrom-derive@0.1.8 | Unicode-3.0 | 1.71.1 |
| zerotrie@0.2.5 | Unicode-3.0 | 1.82 |
| zerovec@0.11.9 | Unicode-3.0 | 1.83 |
| zerovec-derive@0.11.7 | Unicode-3.0 | 1.83 |

Retained optional TLS/core packages from the prior client-http graph: `rustls@0.23.46` (Apache-2.0 OR ISC OR MIT; 1.71), `rustls-pki-types@1.15.1` (MIT OR Apache-2.0; 1.60), `rustls-webpki@0.103.16` (ISC; 1.71), `webpki-roots@1.0.11` (CDLA-Permissive-2.0; 1.71), `ring@0.17.14` (Apache-2.0 AND ISC; 1.66), and `untrusted@0.9.0` (ISC; undeclared). The separately retained test dependency `tokio-rustls@0.26.6` is MIT OR Apache-2.0 (1.71); test-only `rcgen@0.13.2` declares no MSRV. New-package declared MSRVs are at most 1.85; undeclared values are UNKNOWN, and none of this metadata proves an actual Rust 1.85 build.

License-policy notes: the existing global allowlist is Apache-2.0, MIT, BSD-3-Clause, Unlicense, and Unicode-3.0. Expressions with OR alternatives are satisfied through their permitted MIT/Apache-2.0 or Unicode-3.0 branches; this is not a claim that BSD-2-Clause, LGPL, or Zlib is allowlisted. The four existing approved, version-bounded exceptions are unchanged: `ring@0.17.x` (ISC), `untrusted@0.9` (ISC), `rustls-webpki@0.103.x` (ISC), and `webpki-roots@1.0.x` (CDLA-Permissive-2.0). The CDLA-licensed WebPKI root data requires retaining its license text when redistributing bundled roots. No license-policy tool or advisory check was run; advisory status is UNKNOWN. This is metadata-based inventory, not legal advice or license-text audit. The existing TLS 1.2/1.3 feature configuration is unchanged.


## Interop executables (feature `interop`)

`cargo build --release --features interop` builds the harness executables `interop-server` and `interop-client` (`--features interop,http` also works, since `interop` enables `http`); the feature gates the optional HTTP dependencies (hyper/tokio) so the default library build is unaffected. The interop harness (`interop/targets.json`) expects the release paths below, with `.exe` appended automatically on Windows by the harness (interop/README.md section 2). Run `node interop/run.mjs` to drive them, or `node interop/run.mjs --clients rust --servers rust` for just the Rust pair (interop/README.md section 3); the `--verify-only` and `--bootstrap-ttl` contract lives in interop/README.md section 4.

```text
rust/target/release/interop-server
rust/target/release/interop-client
```

## User-key transfer (mcp_jack::user_key)

Role-specific transfer of Ed25519 client keys between the server (issuance) and the client (import). The full conformance table lives in `spec/fixtures/user-key-transfer.json` (shared with the Go and TypeScript lanes; see `docs/design/user-keys.md` sections 11 and 12.2) and is exercised by `tests/user_key_transfer.rs`.

### Server: issue a credential for delivery

```rust,ignore
use mcp_jack::user_key::{ConnectionData, server};

let connection = ConnectionData::new(
    "https://svc.example.test",            // validated URL (client URL policy)
    "https://svc.example.test",            // non-empty audience
    server_public_key_b64u,                // canonical unpadded base64url
    server_kid,
)?;
// Inject a CSPRNG byte source (production) — issue_user_key_os uses the OS.
let issued = server::issue_user_key_os(&connection)?;
let bytes: Vec<u8> = issued.credential_bytes(); // fresh copy per call
let public: mcp_jack::user_key::UserKeyPublic = issued.public_identity();
```

`IssuedUserKey` implements `Debug`/`Display` printing only the kid; the credential and the embedded private envelope are returned ONLY through the explicit `credential_bytes()` accessor. The credential and private envelope are UNENCRYPTED SECRET COPIES retained in plaintext with the issuer handle for its whole lifetime: there is no zeroization guarantee, every `credential_bytes()` call hands out a fresh sensitive copy, and the caller owns safe delivery and disposal. The SDK never persists them: no registry, profile or RPC surface of this crate carries credential or private-envelope bytes (those surfaces are public-data only). The secret types deliberately lack dangerous capabilities, and this is proven by compile-fail doc-test guards on the types themselves (`rust/src/user_key.rs`): `IssuedUserKey` cannot `sign` — neither through an inherent-shaped call nor through the real public `Signer` trait route (the guard's compile-fail doctest passes only while no such implementation exists — introducing a forbidden `Signer` impl would make the snippet compile and the doctest FAIL; a matched positive companion proves the trait route genuinely works for the client key the credential carries) — and has no seed accessor and no serde path in either direction; `ClientSigningKey` and `IssuedClientKey` are not serializable, not deserializable and not `Clone` (the client type additionally has no seed export); `ServerPublicKey` is not serializable or deserializable. Each guard has an adjacent positive example (the methods a consumer CAN use — `credential_bytes`/`public_identity`, `from_seed`/`generate`, `from_public_key`), so the guards bind the real API shape, not an accidental absence. These are compile-time capability proofs: a downstream crate that writes `serde_json::to_string(&client_signing_key)`, `serde_json::from_str::<ClientSigningKey>(text)`, or `key.clone()` on a secret type fails to compile.

### Server: validate a delivered credential against a configured identity

```rust,ignore
use mcp_jack::user_key::{ExpectedIdentity, server};

let configured = ExpectedIdentity { url, aud, server_public_key, server_kid };
server::validate_issued_credential(&bytes, &configured)?;
```

Validation runs the full document pipeline first (version, member set, encodings, URL policy, embedded client_key strict import, canonical bytes) and only then compares the identity: an invalid document keeps its pipeline class (`kid_mismatch`, `bad_url`, `wrong_field_type`, `invalid_public_key`, ...), while a valid document whose server identity differs refuses with exactly `server_identity_mismatch`.

### Client: import a credential with an independently trusted tuple

```rust,ignore
use std::sync::Arc;
use mcp_jack::user_key::{ExpectedIdentity, client};

// The tuple comes from the caller's own pinning — NEVER from the credential.
let expected = ExpectedIdentity { url, aud, server_public_key, server_kid };
let imported = client::import_credential(&bytes, &expected)?;
let signature = imported.signer.sign(b"payload"); // works like any signer
// The imported signer itself becomes the client's signer.
let config = imported.connection.client_config(Arc::new(imported.signer), transport_arc);
```

The expected tuple must match the credential's decoded url/aud/server key exactly, byte for byte; a mismatch (wrong server, wrong aud, wrong server public key, wrong server kid, incomplete or invalid tuple — including a malformed kid spelling) fails closed with `server_identity_mismatch` AFTER the document itself has validated, and no signer or configuration is returned (the API returns `Result::Err` and nothing else).

Context-free import remains exactly that: importing a raw seed (`ClientSigningKey::from_seed`) or a private envelope (`client::import_private_envelope`) is context-free key material handling — it pins no server, no audience and no URL, and is NOT ready-to-connect authentication. Only `import_credential` plus a caller-pinned `ExpectedIdentity` yields validated connection data usable with the client.

### Public-only flows

```rust,ignore
let envelope = client::export_public_envelope(&dyn_signer)?;   // canonical bytes
let identity = client::import_public_envelope(&envelope)?;     // verify-only
let server_record = server::import_public_envelope(&envelope)?; // strict public import
identity.sign(b"x").unwrap_err();                              // not_private
```

`client::export_public_envelope` works with ANY implementation of `mcp_jack::client::signer::Signer`, including non-extractable ones (OS key stores, ssh-agent): the trait exposes only `sign`, `public_key` and `kid`, so exporting a public envelope never requires — or enables — revealing a seed. Private-envelope import is `client::import_private_envelope` (client sink); feeding a private or credential document to a public sink is refused (`wrong_envelope_type`, server sink: `private_material_rejected`).

Documents are canonical JCS-style JSON capped at 4096 bytes; every error from the transfer API carries only a class, an optional member name and optional length pair (`UserKeyError::class/member/lengths`) — never input or secret bytes. The 66-case shared table (`user_key_transfer.rs`) is the executable specification of these rules.

## Packaged crate consumer (CI)

`publish = false` in rust/Cargo.toml means `cargo publish` is blocked, while `cargo package` still produces a distributable `.crate` artifact: packing is NOT publication — there is no registry upload, no tag and no release, and the version stays 0.1.0. The CI-only driver pair packages the crate into a stage and verifies it from a standalone consumer crate:

```
node tools/consumer/package-rust.mjs tools/consumer/.scratch/rust-consumer
node tools/consumer/verify-rust.mjs tools/consumer/.scratch/rust-consumer
```

The stage is a fresh direct child of `tools/consumer/.scratch/`; both drivers are restricted to GitHub Actions. The packaged `.crate` contains the crate sources (`src/`, including `src/bin/**`), the tests, this README, and byte-exact copies of `LICENSE-MIT` and `LICENSE-APACHE` committed under `rust/`; CI byte-compares the packaged licence files against the repository root copies, so licence-text drift fails the run.

The consumer is a standalone edition-2024, rust-version-1.85 crate whose SDK dependency is only the extracted `.crate` — never the checkout (the adapter-driving harness crates named below are optional, feature-gated supporting dependencies). It resolves its dependency graph FRESH on Rust 1.85: no product lockfile is copied in, and the consumer-generated `Cargo.lock` must exist and differ byte-wise from the product `rust/Cargo.lock`, proving independent resolution (Cargo ignores a path-dependency's own lockfile). The feature matrix: the default features build first; `client-http` runs a real signed loopback request over a socket, and an unsigned 401 from the server must surface as `Unauthenticated`; `server-http` drives the real packaged adapter — the consumer constructs `JackLayer` from `HandlerConfig`, wraps an in-process inner service, and drives it through the SDK client, with wrong-pin and tampered-body refusals running through the same adapter. The adapter-only supporting crates `ed25519-dalek`/`getrandom`/`http`/`bytes`/`http-body-util`/`tower`/`futures` are optional harness-only deps behind the consumer's own `server-http` feature; the SDK dependency itself remains only the extracted `.crate`. CI uploads the `.crate` and inventory.json as workflow artifacts for parent inspection. Coverage note: with the MSRV-aware v3 resolver, the crate's `rust-version = "1.85"` makes fresh dependency resolution honor each dependency's declared MSRV, so the consumer's fresh resolution on Rust 1.85 selects dependency versions compatible with the crate's MSRV where such metadata is declared.
