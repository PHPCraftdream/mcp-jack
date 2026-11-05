/** Port of Go server/middleware_test.go against the Fetch adapter (ts/src/server/fetch.ts). */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseRequestAuth } from "../src/auth-header.js";
import { decodeBase64URLFixed } from "../src/encoding.js";
import { verify as verifyEd25519 } from "../src/ed25519.js";
import { requestSigningString } from "../src/signing.js";
import { signRequest, randomNonce, verifyResponse } from "../src/client/auth.js";
import { InMemorySigner } from "../src/client/signer.js";
import { MemoryAuditSink } from "../src/server/audit.js";
import { Native } from "../src/server/native.js";
import { NonceStore } from "../src/server/nonce.js";
import { parsePolicy } from "../src/server/policy.js";
import type { RegistryEntry as StateRegistryEntry } from "../src/server/state.js";
import { MemoryState } from "../src/server/state.js";
import { Verifier } from "../src/server/verify.js";
import type { VerifyResult } from "../src/server/verify.js";
import { jackFetchHandler } from "../src/server/fetch.js";
import type { HandlerConfig } from "../src/server/fetch.js";
import {
  loadDefaultPolicy,
  loadKeys,
  loadRegistry,
  loadWildcardPolicy,
  type RegistryEntry as FixtureRegistryEntry,
} from "./fixtures.js";
import { fixtureAud, fixtureNow, seedSignerByName } from "./client-harness.js";

type Mutable<T> = { -readonly [K in keyof T]: T[K] };

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Fixture registry entry -> src registry entry; optional fields assigned only when defined (exactOptionalPropertyTypes). */
function toStateEntry(e: FixtureRegistryEntry): StateRegistryEntry {
  const out: Mutable<StateRegistryEntry> = {
    kid: e.kid,
    publicKey: e.publicKey,
    name: e.name,
    scopes: e.scopes,
  };
  if (e.kind !== undefined) {
    out.kind = e.kind;
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
function newRegistryState(): MemoryState {
  const st = new MemoryState();
  st.update((edit) => {
    for (const e of loadRegistry().keys) edit.putKey(toStateEntry(e));
  });
  return st;
}

/** Exactly the Go toolCallBody bytes. */
function toolCallBody(name: string): Uint8Array {
  return utf8(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${name}","arguments":{}}}`);
}

/** The 32-byte seed of a keys.json entry and the kid derived from it. */
function seedByName(name: string): { seed: Uint8Array; signer: InMemorySigner } {
  const key = loadKeys().keys.find((k) => k.name === name);
  assert.ok(key !== undefined, `keys.json has no key named ${name}`);
  const seed = Buffer.from(key.seedHex, "hex");
  assert.equal(seed.length, 32, `seed of ${name} is ${seed.length} bytes, want 32`);
  const signer = seedSignerByName(name);
  assert.equal(signer.kid(), key.kid, `derived kid of ${name} differs from keys.json`);
  return { seed: new Uint8Array(seed), signer };
}

interface Harness {
  handle: (req: Request) => Promise<Response>;
  seen: { calls: number; body: Uint8Array | null };
  audit: MemoryAuditSink;
  serverPub: Uint8Array;
}

/** Wires the fixture registry/policy verifier (with the REAL native tools) in front of a wrapped next. */
function newHarness(maxBodyBytes: number | undefined, next: (req: Request) => Promise<Response>): Harness {
  const state = newRegistryState();
  const audit = new MemoryAuditSink();
  const svc = seedByName("svc");
  const verifier = new Verifier({
    aud: fixtureAud,
    state,
    nonces: new NonceStore(),
    policy: parsePolicy(JSON.stringify(loadDefaultPolicy())),
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
  };
  return { handle: jackFetchHandler(config, wrapped), seen, audit, serverPub: svc.signer.publicKey() };
}

/** Builds a fresh-nonce signed Request plus its request signature (Go signedRequest). */
function signedRequest(signer: InMemorySigner, method: string, target: string, body: Uint8Array): { request: Request; sig: string } {
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
async function assertSigned(response: Response, serverPub: Uint8Array, requestSig: string): Promise<Uint8Array> {
  const body = new Uint8Array(await response.arrayBuffer());
  const hv = response.headers.get("jack-auth");
  assert.ok(hv !== null, "response carries no jack-auth header");
  verifyResponse(serverPub, response.status, [hv], requestSig, body, fixtureNow, 30);
  return body;
}

/** The error code of a spec-4 rejection body. */
function errorCode(body: Uint8Array): string {
  const parsed = JSON.parse(Buffer.from(body).toString("utf-8")) as { error?: { code?: string } };
  assert.ok(parsed.error !== undefined && typeof parsed.error.code === "string", `no error.code in ${Buffer.from(body).toString("utf-8")}`);
  return parsed.error.code;
}

function aliceSigner(): InMemorySigner {
  return seedSignerByName("alice");
}

function rootSigner(): InMemorySigner {
  return seedSignerByName("root");
}

test("middleware forwards and signs", async () => {
  const alice = aliceSigner();
  const alicePub = alice.publicKey();
  const body = toolCallBody("svc.status");
  // Self-check before the handler: the exact header alice sends verifies against her registry key.
  const preHeader = signRequest(alice, fixtureAud, "POST", "/mcp?x=1", body, randomNonce(), fixtureNow);
  const pre = parseRequestAuth([preHeader]);
  const preSigning = requestSigningString("POST", "/mcp?x=1", fixtureAud, pre.kid, pre.ts, pre.nonce, body);
  assert.equal(verifyEd25519(alicePub, utf8(preSigning), decodeBase64URLFixed(pre.sig, 64)), true);

  const harness = newHarness(undefined, async () =>
    new Response('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}', { headers: { "content-type": "application/json" } }),
  );
  const { request, sig } = signedRequest(alice, "POST", "/mcp?x=1", body);
  const response = await harness.handle(request);

  assert.equal(response.status, 200);
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.equal(Buffer.from(out).toString("utf-8"), '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}');
  assert.equal(harness.seen.calls, 1);
  assert.ok(harness.seen.body !== null && Buffer.from(harness.seen.body).equals(Buffer.from(body)), "the wrapped handler must see the exact request body");
});

test("middleware rejects unauthenticated unsigned", async () => {
  const harness = newHarness(undefined, async () => new Response("nope"));
  const request = new Request("http://localhost/mcp", {
    method: "POST",
    ...(toolCallBody("svc.status").length > 0 ? { body: toolCallBody("svc.status") } : {}),
  });
  const response = await harness.handle(request);

  assert.equal(response.status, 401);
  assert.equal(response.headers.get("www-authenticate"), "Jack-Auth");
  assert.equal(response.headers.get("jack-auth"), null, "an authentication failure must not be signed");
  const out = new Uint8Array(await response.arrayBuffer());
  assert.equal(errorCode(out), "missing_auth");
  assert.equal(harness.seen.calls, 0);
});

test("middleware signs authorization rejection", async () => {
  const harness = newHarness(undefined, async () => new Response("nope"));
  const { request, sig } = signedRequest(aliceSigner(), "POST", "/mcp", toolCallBody("svc.restart"));
  const response = await harness.handle(request);

  assert.equal(response.status, 403);
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.equal(errorCode(out), "insufficient_scope");
  assert.equal(response.headers.get("www-authenticate"), null);
  assert.equal(harness.seen.calls, 0);
});

test("middleware refuses streams", async () => {
  const harness = newHarness(undefined, async () =>
    new Response("data: x\n\n", { headers: { "content-type": "text/event-stream" } }),
  );
  const { request, sig } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
  const response = await harness.handle(request);

  assert.equal(response.status, 501);
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.equal(errorCode(out), "streaming_unsupported");
});

test("middleware cancels an endless event stream", { timeout: 5000 }, async () => {
  let cancelled = false;
  const endless = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(utf8("data: x\n\n"));
    },
    async pull(controller) {
      // Yield to the event loop so a regression (buffering first) is cut off
      // by the test timeout instead of starving timers in a microtask loop.
      await new Promise<void>((resolve) => setTimeout(resolve, 1));
      controller.enqueue(utf8("data: x\n\n"));
    },
    cancel() {
      cancelled = true;
    },
  });
  // Pipeline: alice GET accepted -> next answers a NEVER-ENDING
  // text/event-stream body. The adapter must refuse on the HEADER, before
  // reading the body, answer the SIGNED 501 and cancel the refused stream;
  // buffering the body first would hang this test until its timeout.
  const harness = newHarness(undefined, async () => new Response(endless, { headers: { "content-type": "text/event-stream" } }));
  const { request, sig } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
  const response = await harness.handle(request);

  assert.equal(response.status, 501);
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.equal(errorCode(out), "streaming_unsupported");
  assert.equal(cancelled, true, "the refused stream must be cancelled");
});

test("middleware body limit", async () => {
  const harness = newHarness(64, async () => new Response("nope"));
  const big = utf8('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"' + "x".repeat(200) + '"}}');
  assert.equal(big.length, 260, "the padded body must exceed the 64-byte limit with margin");
  const { request } = signedRequest(aliceSigner(), "POST", "/mcp", big);
  const response = await harness.handle(request);

  assert.equal(response.status, 413);
  assert.equal(errorCode(new Uint8Array(await response.arrayBuffer())), "invalid_request");
  assert.equal(response.headers.get("jack-auth"), null, "the body cap answer is unsigned");
  assert.equal(harness.seen.calls, 0);
});

test("middleware method not allowed", async () => {
  const harness = newHarness(undefined, async () => new Response("nope"));
  const { request } = signedRequest(aliceSigner(), "PUT", "/mcp", toolCallBody("svc.status"));
  const response = await harness.handle(request);

  assert.equal(response.status, 405);
  assert.equal(errorCode(new Uint8Array(await response.arrayBuffer())), "method_not_allowed");
  assert.equal(response.headers.get("jack-auth"), null, "the 405 precedes authentication, so it is unsigned");
  assert.equal(harness.seen.calls, 0);
});

test("middleware answers native tools itself", async () => {
  const root = rootSigner();
  const rootKid = root.kid();
  const rootPublicKeyB64 = Buffer.from(root.publicKey()).toString("base64url");
  const fixtureRoot = loadRegistry().keys.find((k) => k.name === "root");
  assert.ok(fixtureRoot !== undefined);
  assert.equal(rootKid, fixtureRoot.kid);
  assert.equal(rootPublicKeyB64, fixtureRoot.publicKey);

  const harness = newHarness(undefined, async () => new Response("nope"));
  const { request, sig } = signedRequest(root, "POST", "/mcp", toolCallBody("jack.whoami"));
  const response = await harness.handle(request);

  assert.equal(response.status, 200);
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.equal(harness.seen.calls, 0, "whoami never reaches the wrapped handler");
  const parsed = JSON.parse(Buffer.from(out).toString("utf-8")) as {
    id: number;
    result: { isError: boolean; structuredContent: Record<string, unknown>; content: { type: string; text: string }[] };
  };
  assert.equal(parsed.id, 1);
  assert.equal(parsed.result.isError, false);
  // The field set is fixed by native.ts whoami() and spec 03 section 3 (the
  // request-vectors "native-whoami" case is titled "no public key"): exactly
  // kid, name, kind, scopes and the validity bounds.
  const structured = {
    kid: rootKid,
    name: "root",
    kind: "human",
    scopes: ["admin", "read", "lifecycle", "config:write"],
    not_before: null,
    not_after: null,
  };
  assert.deepEqual(parsed.result.structuredContent, structured);
  assert.deepEqual(parsed.result.content, [{ type: "text", text: JSON.stringify(parsed.result.structuredContent) }]);
  assert.equal(harness.audit.events().length, 0, "whoami is not an audited tool");
});

test("middleware answers a wrapped handler crash unsigned", async () => {
  const harness = newHarness(undefined, async () => {
    throw new Error("boom");
  });
  const { request } = signedRequest(aliceSigner(), "POST", "/mcp", toolCallBody("svc.status"));
  const response = await harness.handle(request);

  assert.equal(response.status, 500);
  assert.equal(errorCode(new Uint8Array(await response.arrayBuffer())), "internal_error");
  assert.equal(response.headers.get("jack-auth"), null, "the crash answer is never signed");
  assert.equal(harness.seen.calls, 1);
});

test("middleware keeps percent-encoded target bytes", async () => {
  const harness = newHarness(undefined, async () => new Response("{}", { headers: { "content-type": "application/json" } }));
  const { request, sig } = signedRequest(aliceSigner(), "POST", "/mcp?x=%7e&y=a%2Fb", toolCallBody("svc.status"));
  const response = await harness.handle(request);

  assert.equal(response.status, 200);
  await assertSigned(response, harness.serverPub, sig);
  assert.equal(harness.seen.calls, 1);
});

test("verifier denies native tools without an implementation", () => {
  const verifier = new Verifier({
    aud: fixtureAud,
    state: newRegistryState(),
    nonces: new NonceStore(),
    policy: parsePolicy(JSON.stringify(loadWildcardPolicy())),
    now: () => fixtureNow,
  });
  const body = toolCallBody("jack.whoami");
  const { request } = signedRequest(rootSigner(), "POST", "/mcp", body);
  const header = request.headers.get("jack-auth") as string;
  const res: VerifyResult = verifier.verify({ method: "POST", target: "/mcp", authValues: [header], body });
  assert.equal(res.accepted, false);
  assert.equal(res.httpStatus, 403);
  assert.equal(res.code, "operation_denied");
  assert.equal(res.nonceRecorded, true);
  assert.notEqual(res.requestSig, "");
});
