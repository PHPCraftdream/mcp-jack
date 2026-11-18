import assert from "node:assert/strict";
import { parseRequestAuth } from "../../../../src/core/auth-header.js";
import { signRequest, randomNonce, verifyResponse } from "../../../../src/client/signing/auth.js";
import { InMemorySigner } from "../../../../src/client/signing/signer.js";
import { MemoryAuditSink } from "../../../../src/server/audit.js";
import { Native } from "../../../../src/server/native.js";
import { NonceStore } from "../../../../src/server/registry/nonce.js";
import type { RegistryEntry as StateRegistryEntry } from "../../../../src/server/registry/state.js";
import { MemoryState } from "../../../../src/server/registry/state.js";
import { Verifier } from "../../../../src/server/verify.js";
import { jackFetchHandler } from "../../../../src/server/http/fetch.js";
import type { HandlerConfig } from "../../../../src/server/http/fetch.js";
import { loadKeys, loadRegistry, type RegistryEntry as FixtureRegistryEntry } from "../../../support/fixtures/index.js";
import { fixtureAud, fixtureNow, seedSignerByName } from "../../../support/client-harness.js";


export type Mutable<T> = { -readonly [K in keyof T]: T[K] };

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Fixture registry entry -> src registry entry; optional fields assigned only when defined (exactOptionalPropertyTypes). */
export function toStateEntry(e: FixtureRegistryEntry): StateRegistryEntry {
  const out: Mutable<StateRegistryEntry> = {
    kid: e.kid,
    publicKey: e.publicKey,
    name: e.name,
  };
  if (e.admin !== undefined) {
    out.admin = e.admin;
  }
  if (e.notBefore !== undefined) {
    out.notBefore = e.notBefore;
  }
  if (e.notAfter !== undefined) {
    out.notAfter = e.notAfter;
  }
  return out;
}

/** Fresh registry state seeded from the fixture (MemoryState is created empty). */
export function newRegistryState(): MemoryState {
  const st = new MemoryState();
  st.update((edit) => {
    for (const e of loadRegistry().keys) edit.putKey(toStateEntry(e));
  });
  return st;
}

/** Exactly the Go toolCallBody bytes. */
export function toolCallBody(name: string): Uint8Array {
  return utf8(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${name}","arguments":{}}}`);
}

/** The 32-byte seed of a keys.json entry and the kid derived from it. */
export function seedByName(name: string): { seed: Uint8Array; signer: InMemorySigner } {
  const key = loadKeys().keys.find((k) => k.name === name);
  assert.ok(key !== undefined, `keys.json has no key named ${name}`);
  const seed = Buffer.from(key.seedHex, "hex");
  assert.equal(seed.length, 32, `seed of ${name} is ${seed.length} bytes, want 32`);
  const signer = seedSignerByName(name);
  assert.equal(signer.kid(), key.kid, `derived kid of ${name} differs from keys.json`);
  return { seed: new Uint8Array(seed), signer };
}

export interface Harness {
  handle: (req: Request) => Promise<Response>;
  seen: { calls: number; body: Uint8Array | null };
  audit: MemoryAuditSink;
  serverPub: Uint8Array;
}

/** Wires the fixture registry verifier (with the REAL native tools) in front of a wrapped next. */
export function newHarness(
  maxBodyBytes: number | undefined,
  next: (req: Request) => Promise<Response>,
  maxResponseBytes?: number,
  registry?: MemoryState,
): Harness {
  const state = registry ?? newRegistryState();
  const audit = new MemoryAuditSink();
  const svc = seedByName("svc");
  const verifier = new Verifier({
    aud: fixtureAud,
    state,
    nonces: new NonceStore(),
    audit,
    native: new Native(),
    now: () => fixtureNow,
  });
  const seen: Harness["seen"] = { calls: 0, body: null };
  const wrapped = async (req: Request): Promise<Response> => {
    seen.calls += 1;
    seen.body = new Uint8Array(await req.arrayBuffer());
    return next(req);
  };
  const config: HandlerConfig = {
    verifier,
    serverKey: svc.seed,
    ...(maxBodyBytes !== undefined ? { maxBodyBytes } : {}),
    ...(maxResponseBytes !== undefined ? { maxResponseBytes } : {}),
  };
  return { handle: jackFetchHandler(config, wrapped), seen, audit, serverPub: svc.signer.publicKey() };
}

/** Builds a fresh-nonce signed Request plus its request signature (Go signedRequest). */
export function signedRequest(signer: InMemorySigner, method: string, target: string, body: Uint8Array): { request: Request; sig: string } {
  const nonce = randomNonce();
  const header = signRequest(signer, fixtureAud, method, target, body, nonce, fixtureNow);
  const sig = parseRequestAuth([header]).sig;
  const request = new Request("http://localhost" + target, {
    method,
    headers: { "jack-auth": header },
    ...(method === "POST" && body.length > 0 ? { body } : {}),
  });
  return { request, sig };
}

/** Verifies the response signature with the client-side verifier; throws (the assertion) on any failure. */
export async function assertSigned(response: Response, serverPub: Uint8Array, requestSig: string): Promise<Uint8Array> {
  const body = new Uint8Array(await response.arrayBuffer());
  const hv = response.headers.get("jack-auth");
  assert.ok(hv !== null, "response carries no jack-auth header");
  verifyResponse(serverPub, response.status, [hv], requestSig, body, fixtureNow, 30);
  return body;
}

/** The error code of a spec-4 rejection body. */
export function errorCode(body: Uint8Array): string {
  const parsed = JSON.parse(Buffer.from(body).toString("utf-8")) as { error?: { code?: string } };
  assert.ok(parsed.error !== undefined && typeof parsed.error.code === "string", `no error.code in ${Buffer.from(body).toString("utf-8")}`);
  return parsed.error.code;
}

export function aliceSigner(): InMemorySigner {
  return seedSignerByName("alice");
}

export function rootSigner(): InMemorySigner {
  return seedSignerByName("root");
}

/** tools/call body with explicit arguments JSON. */
export function toolCallBodyArgs(name: string, argsJson: string): Uint8Array {
  return utf8(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${name}","arguments":${argsJson}}}`);
}

export const forwardedAnswer = (): Response =>
  new Response('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}', { headers: { "content-type": "application/json" } });

/** Promise gate with guarded resolver closures, supported on Node 20. */
export function promiseGate(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolveGate: (() => void) | undefined;
  const promise = new Promise<void>((resolve) => {
    resolveGate = resolve;
  });
  return {
    promise,
    resolve: () => {
      assert.ok(resolveGate !== undefined, "gate resolver was initialized");
      resolveGate();
    },
  };
}

// ---- upstream response cap (maxResponseBytes) ----

export interface Probe {
  pulls: number;
  cancelled: boolean;
}

/** A source that yields one chunk per pull and never reads ahead (highWaterMark 0), so the counters are deterministic. */
export function probeStream(chunks: readonly Uint8Array[], probe: Probe): ReadableStream<Uint8Array> {
  let i = 0;
  return new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        probe.pulls += 1;
        const chunk = chunks[i];
        i += 1;
        if (chunk === undefined) {
          controller.close();
          return;
        }
        controller.enqueue(chunk);
      },
      cancel() {
        probe.cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
}

export const filled = (n: number): Uint8Array => new Uint8Array(n).fill(0x61);

export const UPSTREAM_HEADERS = { "content-type": "text/plain", "x-upstream": "yes", "set-cookie": "a=b" };

/** Runs one authorized GET through a handler whose upstream answers with the given Response. */
export async function answer(
  maxResponseBytes: number | undefined,
  upstream: () => Response,
  maxBodyBytes?: number,
): Promise<{ response: Response; harness: Harness; sig: string }> {
  const harness = newHarness(maxBodyBytes, async () => upstream(), maxResponseBytes);
  const { request, sig } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
  return { response: await harness.handle(request), harness, sig };
}

/** The signed response_too_large 502, bound to the ORIGINAL request signature and free of any upstream data. */
export async function assertOverflow(r: { response: Response; harness: Harness; sig: string }): Promise<void> {
  const { response, harness, sig } = r;
  assert.equal(response.status, 502);
  assert.equal(response.statusText, "");
  const hv = response.headers.get("jack-auth");
  assert.ok(hv !== null);
  const body = new Uint8Array(await response.arrayBuffer());
  verifyResponse(harness.serverPub, 502, [hv], sig, body, fixtureNow, 30);
  const other = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0)).sig;
  assert.notEqual(other, sig);
  assert.throws(() => verifyResponse(harness.serverPub, 502, [hv], other, body, fixtureNow, 30));
  assert.equal(
    Buffer.from(body).toString("utf-8"),
    '{"error":{"code":"response_too_large","message":"upstream response exceeds the configured limit"}}',
  );
  assert.equal(errorCode(body), "response_too_large");
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.equal(response.headers.get("x-upstream"), null);
  assert.equal(response.headers.get("set-cookie"), null);
}

// Finite tests prove only that output bytes and overflow behavior are unchanged by empty
// chunks. The memory property (empty chunks are never pushed to `chunks`, so retained state
// is bounded by the number of non-empty chunks, each >= 1 byte, hence at most respLimit
// entries) comes from the code path (`continue` before `push`), not from these tests.
// An endless stream of only empty chunks is still read forever; it just no longer grows memory.
export const empty = new Uint8Array(0);

export function validationConfig(): HandlerConfig {
  const verifier = new Verifier({
    aud: fixtureAud,
    state: newRegistryState(),
    nonces: new NonceStore(),
    now: () => fixtureNow,
  });
  return { verifier, serverKey: seedByName("svc").seed };
}

/** Nonstandard upstream: give a body-bearing Response a no-body status after construction. */
export function nonstandardNoBodyStatus(status: 204 | 205 | 304, withBody = true): { response: Response; upstreamBytes: Uint8Array } {
  const upstreamBytes = withBody ? utf8(`upstream-${status}`) : new Uint8Array(0);
  const response = new Response(withBody ? upstreamBytes : null, { headers: UPSTREAM_HEADERS });
  Object.defineProperty(response, "status", { value: status });
  return { response, upstreamBytes };
}
