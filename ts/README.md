# mcp-jack (TypeScript SDK)

The `mcp-jack` npm package is the TypeScript SDK: it wraps an unmodified MCP endpoint with mcp-jack's authenticated, authorized and audited transport, mirroring the Go `jack` and `server` packages, and also ships the client as the namespaced `client` entry of the root export (mirroring the Go `client` package). It is ESM-only with zero runtime dependencies (only `node:crypto`, `node:fs`, `node:http`) and targets Node >= 20 under TypeScript's strictest settings; install with `npm ci` (the committed `package-lock.json` pins the dev dependencies; CI runs `npm ci --no-audit --no-fund`), build with `npm run build`, type-check with `npm run typecheck`. Conformance tests in `test/` load the normative fixtures from `spec/fixtures/` in place via `npm test` (`node --test`), so a fixture change breaks every SDK at once.

## Usage

Both adapters share one core: the verifier authenticates and authorizes every request, protocol-native `jack.*` tools are answered directly as MCP CallToolResults, and every other verified answer is signed with the server key (spec 01 sections 4 and 5). The aud check uses the configured audience, never the Host header (reverse-proxy safe); responses are buffered so they can be signed, which means `text/event-stream` is refused with 501 `streaming_unsupported` in v0.1, request bodies over `maxBodyBytes` (default 1 MiB) are answered with 413, and upstream response bodies over `maxResponseBytes` (default 1 MiB; 0 or unset means the default) are answered with a signed 502 `response_too_large` (the overflow answer discards the upstream status text and headers and carries a fresh `application/json` content-type, the mandatory `Jack-Auth` signature header and the `content-length` of its new body). The SSE 501 check takes precedence: it is decided on the declared media type before any body read. `maxResponseBytes` must be a positive safe integer, and `maxBodyBytes` must not be infinite or above `Number.MAX_SAFE_INTEGER`; otherwise `jackFetchHandler` throws at construction. The response cap bounds bytes pulled, not time. On overflow the adapter awaits `reader.cancel()` (inside try/catch, so errors cannot mask the 502), so an upstream whose cancellation promise never settles is outside the byte cap and can still delay the 502. A stream that only yields empty chunks, or never yields, is not stopped by the cap (empty chunks are not retained, so memory stays bounded, but the read continues forever), and the cap cannot bound what `next` buffers before returning its `Response`. A deadline on `next` covers only obtaining the `Response`, not the later body reads or the cancel; a deadline over the whole call including body consumption must wrap the returned handler (e.g. race/abort around the full `handle(req)` call) and is the caller's responsibility, since this SDK has no timeout option. The package exports both adapters from the root (`src/index.ts` re-exports `server/fetch.js` and `server/node.js`).

```ts
// Gateway: wrap the upstream MCP server with a verifier in front.
const verifier = new Verifier({
  aud: "https://svc.example.test",
  state,
  nonces: new NonceStore(),
  native: new Native(),
  now: () => Math.floor(Date.now() / 1000),
});
const next = async (req: Request): Promise<Response> => {
  const body = await req.arrayBuffer(); // the adapter buffered the body; restore the exact bytes
  return fetch(upstream, { method: req.method, headers: req.headers, ...(req.method === "GET" || body.byteLength === 0 ? {} : { body }) });
};
const handle = jackFetchHandler({ verifier, serverKey: seed, maxBodyBytes: 1 << 20, maxResponseBytes: 1 << 20 }, next);
```

The verified caller identity is handed to `next` as a frozen `{ kid, name, admin }` snapshot associated with the forwarded `Request` in SDK-private storage (a `WeakMap`, not an own property of the request) — so handler code can neither discover, replace, nor copy the association onto another `Request` — and reads it only through the exported accessor `jackIdentity(req)`. There is no exported storage symbol and no setter, so an identity can only come from a request that actually verified — request headers, body and query members cannot influence it. The snapshot is per-request: an in-flight handler retains the one it received, and registry changes (including a demotion through `jack.admin.user.set_admin`) affect only subsequent requests. The single `admin` boolean gates only the `jack.admin.*` tools (`403 admin_required`); ordinary MCP traffic is forwarded for every registered, active key, and legacy state files carrying `kind`/`scopes` members are rejected at load, never migrated.

```ts
// Node: serve the same handler from a real socket.
createServer(serveNode(handle)).listen(8080);
```

## Software user keys

Software user keys are role-opposite and root-level exported (module `src/user-key.ts`, zero new dependencies): on the client side, `ClientUserKey` and `generateClientUserKey()` import or generate the private Ed25519 key, `sign`, and expose only the public identity — `new ClientUserKey(seed)` accepts exactly a 32-byte `Uint8Array` and copies the seed bytes into the key object at construction without retaining the seed, `sign`/`publicKey` (a fresh copy per call) satisfy the client package's `Signer` interface structurally, and `ClientUserKey` has NO private export. On the server side, `ServerUserKey` imports ONLY a strictly validated public key: it must pass the SDK's existing `validatePublicKey` rules (exactly 32 bytes, canonical, on the curve, not the identity, in the prime-order subgroup — violations arrive as `JackError` with code `key_rejected`), and it exposes only `kid()` and `publicKey()` with no private access, no sign, and no recovery path from public to private. `issueUserKey()` is server-local issuance returning `{ server, handoff }`: the `server` object is the public-only identity to retain (e.g. as registry material; never any private key), and `handoff` (`UserKeyHandoff.exportSeed()`) is the ONLY explicit private export — a fresh plaintext copy of the 32-byte issued seed per call, NOT consumed by the call, for delivering the seed to the client out of band; the transport is the deployer's responsibility and the SDK performs no network issuance. Default serialization and inspection of the client, server and handoff objects reveal no secret. Portable serialization is implemented as additive named exports from the same root (module `src/user-key-transfer.ts`, re-exported by `src/index.ts`; design `docs/design/user-keys.md` sections 3, 4, 5, 7, 8 and 10). All document imports run one canonical strict pipeline: input over 4096 bytes is `oversized_envelope`; then strict UTF-8 decoding plus a narrow surrogate precheck on raw JSON string tokens (every `\uD800..DBFF` escape must be immediately followed by its `\uDC00..DFFF` low surrogate in the same token, escaped backslashes honored, lone surrogates and malformed escapes refused as `malformed_json`) run BEFORE platform parsing, so all platforms agree on the class; then the ordered semantic checks (version, type, exact member set, field types, canonical base64url encodings, strict public-key validity, seed-to-public and kid consistency) and finally the exact canonical-bytes gate — the input bytes must equal the canonical serialization of the parsed object, so duplicate members, alternate escape spellings, added whitespace and unknown members are never accepted and never repaired. Errors are a closed shared class set (`malformed_json`, `wrong_root_type`, `oversized_envelope`, `unknown_version`, `unknown_type`, `bad_member_set`, `wrong_field_type`, `bad_encoding`, `bad_url`, `invalid_public_key`, `seed_pub_mismatch`, `kid_mismatch`, `non_canonical_bytes`, `wrong_envelope_type`, `private_material_rejected`, `not_private`, `server_identity_mismatch`), delivered as the SDK's existing `JackError` with `httpStatus 0` (these codes never become HTTP responses), with diagnostics carrying only class, member name and observed lengths — never decoded values. `exportUserKeyPublicEnvelope(signer)` serializes any nonextractable `Signer`-shaped value (`publicKey()`/`kid()` only) into the canonical public envelope after validating the public key and that the supplied `kid` is the key id of those bytes. `importUserKeyPublicEnvelope(bytes)` returns the public-only data `{ pub32, kid }` with no sign method and no secret capability (secret operations on it would be `not_private`). `importServerUserKeyPublicEnvelope(bytes)` builds the existing public-only `ServerUserKey` and answers any private envelope or client credential with `private_material_rejected` (the security class wins over the wrong-kind class). `importClientUserKeyPrivateEnvelope(bytes)` imports a canonical private envelope into a software `ClientUserKey` (wrapping the existing from-seed constructor). `importClientUserKeyCredential(bytes, expected)` takes a canonical client credential plus a REQUIRED independently trusted expected tuple `{ url, aud, server_public_key, server_kid }` supplied out-of-band (section 8): trust checks run only after the whole document pipeline accepts — a structurally invalid credential fails its pipeline class, never `server_identity_mismatch` — comparison uses the exact decoded UTF-8 bytes of all four fields with no normalization or case folding, and a missing, incomplete, invalid or conflicting expected tuple is `server_identity_mismatch`; refusals return nothing and mutate no caller state, and the SDK performs no persistence or profile mutation. On success it returns `{ signer, connection }` where `signer` is the software client key and `connection` carries the decoded tuple plus `baseUrl`/`serverKey` (fresh copies), ready to feed the existing `client.Client`. `validateUserKeyCredentialForServer(bytes, expected)` runs the same pipeline and then the same comparison against the server's own configured identity (tooling and tests; not a network feature). `issueUserKeyCredential(config, randomSource?)` is local pure issuance with injected deterministic randomness (default `node:crypto.randomBytes`, overridable like the existing invite-code random pattern so tests can fix it): it validates the config tuple, derives the client key from 32 random bytes, and returns an `IssuedUserKeyCredential` whose `exportCredential()` returns a fresh independent copy of the canonical credential bytes on every call (no one-shot consumption state, no new error class for reuse), whose `publicIdentity()` is the public-only `ServerUserKey` for normal registration, and whose `String`/JSON/inspection form redacts by default; there is no sign method and no seed accessor; the result type validates its inputs at construction — a canonical credential whose ISSUED CLIENT key is exactly the supplied public identity (`publicIdentity()` is the issued user's public-only identity for registration, NEVER the credential's embedded server pin), with oversized input refused before any copy and mismatched identities refused `server_identity_mismatch` — while the factory `issueUserKeyCredential` remains the normal creation path. Security facts: the client and server surfaces never export private material, credentials never contain server private keys (the exact credential member set makes any such member `bad_member_set`), the module performs no persistence, profile or registry writes and no network issuance, no SDK surface prints or logs envelopes, credentials or seeds at any level, there is no TOFU, no silent pin replacement and no automatic rotation anywhere, and private envelopes and credentials are UNENCRYPTED plaintext secret copies whose safe delivery, backup and storage remain the caller's responsibility (no zeroization is guaranteed, and the secret lives with the issuer handle for its lifetime). This section documents the implemented public consumers, not disconnected helpers. The shared test table `spec/fixtures/user-key-transfer.json` is materialized in `test/user-key-transfer.test.ts` like the other fixture-driven tests (all 66 cases — 14 positives, 51 negatives, 1 context case — plus the 14-row acceptance table of section 12.3). The module is a raw, context-free foundation — no file IO, no serialization format, no versioning — and it is NOT ready-to-connect authentication: connection credentials (endpoint, audience, server public key and kid — never a server private key) come from the transfer contract above and must be validated against an independently trusted expected pin that is never silently replaced; a server key taken from an untrusted bundle is by itself not MITM protection, and there is no automatic rotation and no trust-on-first-use anywhere. As with all JavaScript secrets, `UserKeyHandoff.exportSeed()` output cannot be zeroized: the engine and GC keep uncontrolled copies and bytes stay readable until collected, so no hardened-storage claim is made and callers are responsible for their copies.

## Client

### Client URL policy

The client (`Client`, `clientFromProfile`/`loadProfile`/`validateProfile` and `createSigningFetch`) judges the destination as a raw string, before any URL parsing, locally and before signing or any `fetchImpl` call (spec 01 section 1; `docs/design/interop.md` section 9; table `spec/fixtures/client-url-policy.json`). `https` is accepted for any well-formed host. `http` is accepted only for a literal canonical `127.x.y.z` or `[::1]`. `localhost` and its aliases, non-canonical IPs (`127.1`, `0x7f.0.0.1`, `2130706433`, ...), userinfo, percent escapes in the authority (which also refuses zone IDs), backslashes, whitespace/control/non-ASCII bytes and bad ports are refused with `DestinationRefusedError`; percent-encoded path and query bytes stay accepted and are signed as given; there is no DNS and no insecure opt-out. `checkDestination(raw)` is exported. For `URL` and `Request` inputs of `createSigningFetch` the check runs on the serialised `.href` / `.url`.

Redirects are never followed: `redirect: "error"` is always passed to the fetch, and an answer from an injected fetch with status 301, 302, 303, 307 or 308, type `opaqueredirect`, `redirected` set, or a url that is non-empty and different (the fragment is ignored in this comparison) is refused with `RedirectRefusedError` and its body cancelled. Other 3xx statuses (300, 304) are not redirects and are verified normally. This is a no-follow guard so a signed request is never verified against another target; it is not TLS enforcement. A caller-supplied `fetchImpl` must use TLS for `https` URLs, connect to exactly the URL it is given and not follow redirects; the SDK cannot police an arbitrary custom fetch.

## Interop executables

`tsconfig.json` has `include: ["src"]` and `rootDir: "src"`, so `npm run build` compiles the two interop executables to `dist/interop/` alongside the library. Run the build in `ts/`, the executables from the repo root (that is where `interop/targets.json` resolves the paths):

```
npm run build
node ts/dist/interop/server.js --aud <aud> --state <file> --server-seed-hex <64 hex> [--bootstrap-ttl <seconds>] [--verify-only]
node ts/dist/interop/client.js --url <base-url> --seed-hex <64 hex> --server-public-key <b64u> --aud <aud> --scenario <name> [--seeds <file>] [--ts <n>] [--nonce <b64u>] [--arg k=v]...
```

## Standalone package consumer (CI)

The checkout remains `private: true` at version `0.0.0`; this task does not publish or make it publishable. The ordinary `npm run build` above is unchanged and continues to compile the interop executables for existing CI. The consumer artifact uses the separate library-only `npm run build:package` configuration, which excludes `src/interop/`.

From the repository root, prepare an npm tarball and its allowlisted member inventory, then verify it from an isolated consumer install:

```
node tools/consumer/package-ts.mjs tools/consumer/.scratch/ts-consumer
node tools/consumer/verify-ts.mjs tools/consumer/.scratch/ts-consumer
```

The preparation script is CI-only and requires `GITHUB_ACTIONS=true`; the stage must be a new direct child under `tools/consumer/.scratch/`. It builds into that stage, then stages only library `dist` JavaScript/declarations, this README, and byte-for-byte copies of the root `LICENSE-MIT` and `LICENSE-APACHE`; it runs `npm pack` with the private metadata retained. The stage contains the tarball, inventory, and intermediate `build/`, `package/`, and `npm-cache/` directories. `tools/consumer/.scratch/` is ignored by Git. The verification driver installs the tarball and the consumer fixture's own TypeScript tooling into a stage-local `consumer/` directory, checks the installed-file inventory and exact license bytes, type-checks `smoke.ts` using only the `mcp-jack` package-root import, then executes it against a bounded real loopback server. The smoke covers client-key public transfer, issuer credential import against a separately constructed trusted server tuple, a signed client/server round trip, wrong-server-pin refusal, and tampered-request refusal. No consumer lockfile is copied from the SDK.

CI runs the pair above as the consumer ts job (Node 20 and 22): the stage below `tools/consumer/.scratch/` is created fresh per run by the packaging driver, and the verification driver installs the tarball into a stage-local `consumer/` directory there; the tarball, inventory, and generated install/compiler files remain in that stage.

## Candidate rotation trust store

The additive `rotation` namespace exposes `RotationTrustStore` and the type
`RotationStoreOptions`. This is an explicit candidate-profile storage API; the
existing static `client.Client`, credentials, server adapters and authorization
rules do not opt into it automatically. It does not implement a rotating client,
refresh transport, native server tool, publication or recovery workflow.

Provision `binding`, immutable `window` (1–120 seconds) and `checkpoint` from an
independently trusted source, never from an unverified response or a store file
being adopted. `RotationTrustStore.initializeUnused(stateFile, options)` is a
separate, explicit operation for a proven unused profile and never overwrites an
existing file. Normal startup uses only `RotationTrustStore.open(stateFile,
options)`; missing, incompatible, dirty, unsafe or uncertain state is a refusal,
not an instruction to initialize, reset or retry.

The concrete profile is synchronous, single-process/cooperating-owner storage on
private Linux ext4/XFS/Btrfs directories. The immediate parent must belong to the
current UID with mode 0700; state and owner files use mode 0600. Symlink/hardlink,
unsafe-owner/mode and unsupported-platform/filesystem cases fail closed. An
exclusive random owner marker and a dirty logical epoch prevent accidental
concurrent/restart admission. Stale markers are never broken by PID checks or
removed automatically. Unknown write outcomes retain the startup gate and
artifacts; do not delete them to make startup succeed.

The protected bundle contains separate logical whole-snapshot and authoritative
ClockGuard records. `snapshot()` is a committed read, not a fresh clock sample,
readiness proof or ACK. `rawClock()` is preliminary; `advanceAndCheck()` and
`checkSnapshotClock(expected)` perform the authoritative monotone clock operation.
`compareAndSwap(expected, desired, clock)` requires the exact current snapshot and
captured guard, extends validated history and leaves logical guard bytes unchanged;
a copied snapshot tuple alone is not time authority. No method retries an unknown
operation or clears an unsafe rollback latch on catch-up. `close()` releases a
healthy, settled owner only; network callers need their own final authority and
response-lifetime gates. All synchronous callbacks and I/O must be bounded and
non-reentrant; this API cannot preempt an arbitrary stalled callback.

The local bundle limit is 16 MiB, distinct from the candidate refresh HTTP body
limit of 256 KiB. Checksums detect accidental corruption; they are not a MAC, backup rollback
oracle, physical-volume quota, power-loss certification or storage encryption.
Raw file ownership and wire-format helpers are not namespace exports. Full
candidate client/server controllers and independent release review remain separate
gates.
