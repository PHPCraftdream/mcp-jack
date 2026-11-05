# mcp-jack (TypeScript SDK)

The `mcp-jack` npm package is the TypeScript SDK: it wraps an unmodified MCP endpoint with mcp-jack's authenticated, authorized and audited transport, mirroring the Go `jack` and `server` packages, and also ships the client as the namespaced `client` entry of the root export (mirroring the Go `client` package). It is ESM-only with zero runtime dependencies (only `node:crypto`, `node:fs`, `node:http`) and targets Node >= 20 under TypeScript's strictest settings; install with `npm ci` (the committed `package-lock.json` pins the dev dependencies; CI runs `npm ci --no-audit --no-fund`), build with `npm run build`, type-check with `npm run typecheck`. Conformance tests in `test/` load the normative fixtures from `spec/fixtures/` in place via `npm test` (`node --test`), so a fixture change breaks every SDK at once.

## Usage

Both adapters share one core: the verifier authenticates and authorizes every request, protocol-native `jack.*` tools are answered directly as MCP CallToolResults, and every other verified answer is signed with the server key (spec 01 sections 4 and 5). The aud check uses the configured audience, never the Host header (reverse-proxy safe); responses are buffered in full so they can be signed, which means `text/event-stream` is refused with 501 `streaming_unsupported` in v0.1, and bodies over `maxBodyBytes` (default 1 MiB) are answered with 413. The package exports both adapters from the root (`src/index.ts` re-exports `server/fetch.js` and `server/node.js`).

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
const handle = jackFetchHandler({ verifier, serverKey: seed, maxBodyBytes: 1 << 20 }, next);
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
