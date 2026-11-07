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
  policy: parsePolicy(policyJson),
  native: new Native(),
  now: () => Math.floor(Date.now() / 1000),
});
const next = async (req: Request): Promise<Response> => {
  const body = await req.arrayBuffer(); // the adapter buffered the body; restore the exact bytes
  return fetch(upstream, { method: req.method, headers: req.headers, ...(req.method === "GET" || body.byteLength === 0 ? {} : { body }) });
};
const handle = jackFetchHandler({ verifier, serverKey: seed, maxBodyBytes: 1 << 20, maxResponseBytes: 1 << 20 }, next);
```

```ts
// Node: serve the same handler from a real socket.
createServer(serveNode(handle)).listen(8080);
```

## Software user keys

Software user keys are role-opposite and root-level exported (module `src/user-key.ts`, zero new dependencies): on the client side, `ClientUserKey` and `generateClientUserKey()` import or generate the private Ed25519 key, `sign`, and expose only the public identity — `new ClientUserKey(seed)` accepts exactly a 32-byte `Uint8Array` and copies the seed bytes into the key object at construction without retaining the seed, `sign`/`publicKey` (a fresh copy per call) satisfy the client package's `Signer` interface structurally, and `ClientUserKey` has NO private export. On the server side, `ServerUserKey` imports ONLY a strictly validated public key: it must pass the SDK's existing `validatePublicKey` rules (exactly 32 bytes, canonical, on the curve, not the identity, in the prime-order subgroup — violations arrive as `JackError` with code `key_rejected`), and it exposes only `kid()` and `publicKey()` with no private access, no sign, and no recovery path from public to private. `issueUserKey()` is server-local issuance returning `{ server, handoff }`: the `server` object is the public-only identity to retain (e.g. as registry material; never any private key), and `handoff` (`UserKeyHandoff.exportSeed()`) is the ONLY explicit private export — a fresh plaintext copy of the 32-byte issued seed per call, NOT consumed by the call, for delivering the seed to the client out of band; the transport is the deployer's responsibility and the SDK performs no network issuance. Default serialization and inspection of the client, server and handoff objects reveal no secret. The module is a raw, context-free foundation — no file IO, no serialization format, no versioning (portable serialization is a separate later contract) — and it is NOT ready-to-connect authentication: connection credentials (endpoint, audience, server public key and kid — never a server private key) come from a forthcoming contract and must be validated against an independently trusted expected pin that is never silently replaced; a server key taken from an untrusted bundle is by itself not MITM protection, and there is no automatic rotation and no trust-on-first-use anywhere. As with all JavaScript secrets, `UserKeyHandoff.exportSeed()` output cannot be zeroized: the engine and GC keep uncontrolled copies and bytes stay readable until collected, so no hardened-storage claim is made and callers are responsible for their copies.

## Client

### Client URL policy

The client (`Client`, `clientFromProfile`/`loadProfile`/`validateProfile` and `createSigningFetch`) judges the destination as a raw string, before any URL parsing, locally and before signing or any `fetchImpl` call (spec 01 section 1; `docs/design/interop.md` section 9; table `spec/fixtures/client-url-policy.json`). `https` is accepted for any well-formed host. `http` is accepted only for a literal canonical `127.x.y.z` or `[::1]`. `localhost` and its aliases, non-canonical IPs (`127.1`, `0x7f.0.0.1`, `2130706433`, ...), userinfo, percent escapes in the authority (which also refuses zone IDs), backslashes, whitespace/control/non-ASCII bytes and bad ports are refused with `DestinationRefusedError`; percent-encoded path and query bytes stay accepted and are signed as given; there is no DNS and no insecure opt-out. `checkDestination(raw)` is exported. For `URL` and `Request` inputs of `createSigningFetch` the check runs on the serialised `.href` / `.url`.

Redirects are never followed: `redirect: "error"` is always passed to the fetch, and an answer from an injected fetch with status 301, 302, 303, 307 or 308, type `opaqueredirect`, `redirected` set, or a url that is non-empty and different (the fragment is ignored in this comparison) is refused with `RedirectRefusedError` and its body cancelled. Other 3xx statuses (300, 304) are not redirects and are verified normally. This is a no-follow guard so a signed request is never verified against another target; it is not TLS enforcement. A caller-supplied `fetchImpl` must use TLS for `https` URLs, connect to exactly the URL it is given and not follow redirects; the SDK cannot police an arbitrary custom fetch.

## Interop executables

`tsconfig.json` has `include: ["src"]` and `rootDir: "src"`, so `npm run build` compiles the two interop executables to `dist/interop/` alongside the library. Run the build in `ts/`, the executables from the repo root (that is where `interop/targets.json` resolves the paths):

```
npm run build
node ts/dist/interop/server.js --aud <aud> --policy <file> --state <file> --server-seed-hex <64 hex> [--bootstrap-ttl <seconds>] [--verify-only]
node ts/dist/interop/client.js --url <base-url> --seed-hex <64 hex> --server-public-key <b64u> --aud <aud> --scenario <name> [--seeds <file>] [--ts <n>] [--nonce <b64u>] [--arg k=v]...
```
