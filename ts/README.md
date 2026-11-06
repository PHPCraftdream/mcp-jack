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

## Interop executables

`tsconfig.json` has `include: ["src"]` and `rootDir: "src"`, so `npm run build` compiles the two interop executables to `dist/interop/` alongside the library. Run the build in `ts/`, the executables from the repo root (that is where `interop/targets.json` resolves the paths):

```
npm run build
node ts/dist/interop/server.js --aud <aud> --policy <file> --state <file> --server-seed-hex <64 hex> [--bootstrap-ttl <seconds>] [--verify-only]
node ts/dist/interop/client.js --url <base-url> --seed-hex <64 hex> --server-public-key <b64u> --aud <aud> --scenario <name> [--seeds <file>] [--ts <n>] [--nonce <b64u>] [--arg k=v]...
```
