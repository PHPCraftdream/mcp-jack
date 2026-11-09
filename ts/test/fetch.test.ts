/** Port of Go server/middleware_test.go against the Fetch adapter (ts/src/server/fetch.ts). */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseRequestAuth } from "../src/auth-header.js";
import { decodeBase64URLFixed, encodeBase64URL } from "../src/encoding.js";
import { verify as verifyEd25519 } from "../src/ed25519.js";
import { requestSigningString } from "../src/signing.js";
import { signRequest, randomNonce, verifyResponse } from "../src/client/auth.js";
import { InMemorySigner } from "../src/client/signer.js";
import { MemoryAuditSink } from "../src/server/audit.js";
import { Native } from "../src/server/native.js";
import { NonceStore } from "../src/server/nonce.js";
import type { RegistryEntry as StateRegistryEntry } from "../src/server/state.js";
import { MemoryState } from "../src/server/state.js";
import { Verifier } from "../src/server/verify.js";
import type { VerifyResult } from "../src/server/verify.js";
import { jackFetchHandler, jackIdentity } from "../src/server/fetch.js";
import type { HandlerConfig } from "../src/server/fetch.js";
import type { JackIdentity } from "../src/server/verify.js";
import { loadKeys, loadRegistry, type RegistryEntry as FixtureRegistryEntry } from "./fixtures.js";
import { fixtureAud, fixtureNow, seedSignerByName } from "./client-harness.js";

type Mutable<T> = { -readonly [K in keyof T]: T[K] };

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Fixture registry entry -> src registry entry; optional fields assigned only when defined (exactOptionalPropertyTypes). */
function toStateEntry(e: FixtureRegistryEntry): StateRegistryEntry {
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

/** Wires the fixture registry verifier (with the REAL native tools) in front of a wrapped next. */
function newHarness(
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

test("middleware signs the admin-gate rejection", async () => {
  // Ordinary MCP is never gated, so the only authorization rejection left is
  // the jack.admin.* gate: alice (not an admin) calls an admin tool.
  const harness = newHarness(undefined, async () => new Response("nope"));
  const { request, sig } = signedRequest(aliceSigner(), "POST", "/mcp", toolCallBody("jack.admin.user.list"));
  const response = await harness.handle(request);

  assert.equal(response.status, 403);
  const out = await assertSigned(response, harness.serverPub, sig);
  assert.equal(errorCode(out), "admin_required");
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
  // The field set is fixed by native.ts whoami() and spec 03 section 3.1: exactly
  // kid, name, admin and the validity bounds.
  const structured = {
    kid: rootKid,
    name: "root",
    admin: true,
    not_before: null,
    not_after: null,
  };
  assert.deepEqual(parsed.result.structuredContent, structured);
  assert.deepEqual(parsed.result.content, [{ type: "text", text: JSON.stringify(parsed.result.structuredContent) }]);
  assert.equal(harness.audit.events().length, 0, "whoami is not an audited tool");
});

/** tools/call body with explicit arguments JSON. */
function toolCallBodyArgs(name: string, argsJson: string): Uint8Array {
  return utf8(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${name}","arguments":${argsJson}}}`);
}

const forwardedAnswer = (): Response =>
  new Response('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}', { headers: { "content-type": "application/json" } });

test("forward hands the wrapped handler a frozen identity snapshot", async () => {
  const aliceKid = aliceSigner().kid();
  let identity: JackIdentity | undefined;
  let frozen = false;
  let snapshotRef: JackIdentity | undefined;
  const harness = newHarness(undefined, async (req) => {
    const id = jackIdentity(req);
    identity = id === undefined ? undefined : { kid: id.kid, name: id.name, admin: id.admin };
    frozen = id !== undefined && Object.isFrozen(id);
    snapshotRef = id;
    return forwardedAnswer();
  });
  const { request } = signedRequest(aliceSigner(), "POST", "/mcp", toolCallBody("svc.status"));
  const response = await harness.handle(request);

  assert.equal(response.status, 200);
  assert.equal(harness.seen.calls, 1);
  assert.deepEqual(identity, { kid: aliceKid, name: "alice", admin: false });
  assert.equal(frozen, true, "the identity snapshot must be frozen");
  assert.ok(snapshotRef !== undefined && Object.isFrozen(snapshotRef));
});

test("forward hands the registry's admin entry admin true", async () => {
  const rootKid = rootSigner().kid();
  let identity: JackIdentity | undefined;
  const harness = newHarness(undefined, async (req) => {
    const id = jackIdentity(req);
    identity = id === undefined ? undefined : { kid: id.kid, name: id.name, admin: id.admin };
    return forwardedAnswer();
  });
  const { request } = signedRequest(rootSigner(), "POST", "/mcp", toolCallBody("svc.status"));
  const response = await harness.handle(request);

  assert.equal(response.status, 200);
  assert.deepEqual(identity, { kid: rootKid, name: "root", admin: true });
});

test("forged x-jack headers and query members cannot influence the identity", async () => {
  const aliceKid = aliceSigner().kid();
  const rootKid = rootSigner().kid();
  let seen: JackIdentity | undefined;
  const harness = newHarness(undefined, async (req) => {
    const id = jackIdentity(req);
    seen = id === undefined ? undefined : { kid: id.kid, name: id.name, admin: id.admin };
    return forwardedAnswer();
  });

  // Forged header kid.
  const forgedKid = signedRequest(aliceSigner(), "POST", "/mcp", toolCallBody("svc.status"));
  forgedKid.request.headers.set("x-jack-kid", rootKid);
  assert.equal((await harness.handle(forgedKid.request)).status, 200);
  assert.deepEqual(seen, { kid: aliceKid, name: "alice", admin: false }, "forged x-jack-kid must not change the identity");

  // Forged header admin flag.
  const forgedAdmin = signedRequest(aliceSigner(), "POST", "/mcp", toolCallBody("svc.status"));
  forgedAdmin.request.headers.set("x-jack-admin", "true");
  assert.equal((await harness.handle(forgedAdmin.request)).status, 200);
  assert.deepEqual(seen, { kid: aliceKid, name: "alice", admin: false }, "forged x-jack-admin must not change the identity");

  // Forged query members, signed as part of the target.
  const { request } = signedRequest(aliceSigner(), "POST", `/mcp?kid=${encodeURIComponent(rootKid)}&admin=1`, toolCallBody("svc.status"));
  assert.equal((await harness.handle(request)).status, 200);
  assert.deepEqual(seen, { kid: aliceKid, name: "alice", admin: false }, "forged query members must not change the identity");
});

test("a GET request carries the identity to the handler too", async () => {
  const aliceKid = aliceSigner().kid();
  let identity: JackIdentity | undefined;
  const harness = newHarness(undefined, async (req) => {
    const id = jackIdentity(req);
    identity = id === undefined ? undefined : { kid: id.kid, name: id.name, admin: id.admin };
    return forwardedAnswer();
  });
  const { request } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
  assert.equal((await harness.handle(request)).status, 200);
  assert.deepEqual(identity, { kid: aliceKid, name: "alice", admin: false });
});

test("jackIdentity is undefined without the SDK's forward path", () => {
  assert.equal(jackIdentity(new Request("http://localhost/mcp", { method: "GET" })), undefined);
});

test("a signed request's arguments cannot forge identity metadata", async () => {
  const aliceKid = aliceSigner().kid();
  const rootKid = rootSigner().kid();
  let seen: JackIdentity | undefined;
  const harness = newHarness(undefined, async (req) => {
    seen = jackIdentity(req);
    return forwardedAnswer();
  });
  const body = toolCallBodyArgs("svc.status", `{"kid":"${rootKid}","admin":true}`);
  const { request } = signedRequest(aliceSigner(), "POST", "/mcp", body);
  assert.equal((await harness.handle(request)).status, 200);
  assert.deepEqual(seen, { kid: aliceKid, name: "alice", admin: false });
});

/** Promise gate with guarded resolver closures, supported on Node 20. */
function promiseGate(): { readonly promise: Promise<void>; readonly resolve: () => void } {
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

test("an in-flight handler keeps the real SDK snapshot across an overlapping registry demotion", { timeout: 5000 }, async () => {
  const bob = seedSignerByName("bob");
  const bobKid = bob.kid();
  const rootKid = rootSigner().kid();
  // Two-admin registry: root and bob both admin:true.
  const state = new MemoryState();
  state.update((edit) => {
    edit.putKey({ kid: rootKid, publicKey: encodeBase64URL(rootSigner().publicKey()), name: "root", admin: true });
    edit.putKey({ kid: bobKid, publicKey: encodeBase64URL(bob.publicKey()), name: "bob", admin: true });
  });
  const release = promiseGate();
  const entered = promiseGate();
  const handlerRequests: Request[] = [];
  let inFlight: JackIdentity | undefined;
  let inHandlerSnapshotAfterDemotion: JackIdentity | undefined;
  let subsequent: JackIdentity | undefined;
  let handlerInvocations = 0;
  const harness = newHarness(undefined, async (req) => {
    handlerInvocations += 1;
    handlerRequests.push(req);
    if (handlerInvocations === 1) {
      const identity = jackIdentity(req);
      assert.ok(identity !== undefined, "parked handler received an identity");
      inFlight = identity;
      entered.resolve();
      await release.promise;
      // Re-read the ACTUAL SDK request after the overlapping mutation and
      // before this handler returns; the association must be the same object.
      inHandlerSnapshotAfterDemotion = jackIdentity(req);
      assert.equal(inHandlerSnapshotAfterDemotion, identity);
      assert.deepEqual(inHandlerSnapshotAfterDemotion, { kid: bobKid, name: "bob", admin: true });
      assert.ok(Object.isFrozen(inHandlerSnapshotAfterDemotion));
    } else {
      subsequent = jackIdentity(req);
    }
    return forwardedAnswer();
  }, undefined, state);

  // Request 1 from bob enters the handler and parks there.
  const first = signedRequest(bob, "POST", "/mcp", toolCallBody("svc.status"));
  const pendingFirst = harness.handle(first.request);
  let firstResponse: Response | undefined;
  try {
    await entered.promise;
    const identity = inFlight;
    assert.ok(identity !== undefined, "the parked handler received an identity");
    assert.equal(identity.admin, true, "bob was an admin at verification time");
    assert.ok(Object.isFrozen(identity), "the SDK snapshot is frozen");
    const actualRequest = handlerRequests[0];
    assert.ok(actualRequest !== undefined, "the actual restored handler request was captured");
    assert.equal(jackIdentity(actualRequest), identity, "the actual handler request resolves to the SDK snapshot");

    // OVERLAPPING mutation: while handler 1 is parked, root demotes bob through
    // the REAL native set_admin on the same adapter. jack.admin.* never reaches
    // next, so the demotion completes although handler 1 has not returned.
    const demote = signedRequest(
      rootSigner(),
      "POST",
      "/mcp",
      toolCallBodyArgs("jack.admin.user.set_admin", `{"kid":"${bobKid}","admin":false}`),
    );
    assert.equal((await harness.handle(demote.request)).status, 200);
    assert.equal(harness.seen.calls, 1, "the native demote must not reach the wrapped handler");

    // This outside-handler read uses the same actual Request captured above,
    // never the caller's original request or a copied identity.
    assert.equal(jackIdentity(actualRequest), identity);
    assert.ok(state.lookup(bobKid)?.admin !== true, "bob is no longer an admin in current state");
    assert.equal(identity.admin, true, "the in-flight snapshot is unchanged by the overlapping demotion");
    assert.ok(Object.isFrozen(identity), "still frozen after the registry changed");
  } finally {
    release.resolve();
    firstResponse = await pendingFirst;
  }
  assert.ok(firstResponse !== undefined);
  assert.equal(firstResponse.status, 200);
  assert.equal(inHandlerSnapshotAfterDemotion, inFlight, "the handler re-read the same SDK snapshot");

  // A subsequent request gets the NEW snapshot: a different frozen object.
  const second = signedRequest(bob, "POST", "/mcp", toolCallBody("svc.status"));
  assert.equal((await harness.handle(second.request)).status, 200);
  assert.equal(harness.seen.calls, 2);
  const actualSecondRequest = handlerRequests[1];
  assert.ok(actualSecondRequest !== undefined, "the second restored handler request was captured");
  assert.equal(jackIdentity(actualSecondRequest), subsequent, "the second handler request resolves to its own snapshot");
  assert.ok(subsequent !== undefined, "the second forwarded request carried an identity");
  assert.equal(subsequent.admin, false, "the later request sees the demotion");
  assert.ok(Object.isFrozen(subsequent));
  assert.ok(!Object.is(inFlight, subsequent), "each request gets its own snapshot object");
});

test("the identity association resists discovery, replacement and copying from handler code", async () => {
  const forged = { kid: rootSigner().kid(), name: "root", admin: true };
  const harness = newHarness(undefined, async (req) => {
    const real = jackIdentity(req);
    assert.ok(real !== undefined, "handler received an identity");
    const copied = new Request("http://localhost/copied", { method: "GET" });
    const clone = req.clone();
    const reconstructed = new Request(req);

    // Inspect own keys without invoking any accessors. Identity-shaped values
    // are identified only from own data descriptors on their own fields.
    let exposedIdentity = false;
    const accessorDescriptors = new Map<PropertyKey, PropertyDescriptor>();
    const identityDescriptors: Array<[PropertyKey, PropertyDescriptor]> = [];
    for (const key of Reflect.ownKeys(req)) {
      const descriptor = Object.getOwnPropertyDescriptor(req, key);
      assert.ok(descriptor !== undefined, "own key has a descriptor");
      if (!("value" in descriptor)) {
        accessorDescriptors.set(key, descriptor);
        continue;
      }
      const value: unknown = descriptor.value;
      let identityShaped = false;
      if (typeof value === "object" && value !== null) {
        const valueDescriptors = Object.getOwnPropertyDescriptors(value);
        identityShaped = ["kid", "name", "admin"].every((name) => {
          const member = valueDescriptors[name];
          return member !== undefined && "value" in member;
        });
      }
      if (value === real || identityShaped) {
        exposedIdentity = true;
        identityDescriptors.push([key, descriptor]);
        Reflect.set(req, key, forged);
      }
    }
    assert.equal(exposedIdentity, false, "no request own property exposes an identity");
    for (const [key, descriptor] of accessorDescriptors) {
      assert.deepEqual(Object.getOwnPropertyDescriptor(req, key), descriptor, "accessor descriptor remains unchanged");
    }
    for (const [key, descriptor] of identityDescriptors) {
      assert.notEqual(Object.getOwnPropertyDescriptor(req, key)?.value, forged, "an identity-shaped property was not replaced");
      assert.notEqual(descriptor.value, forged);
    }

    assert.equal(Reflect.set(real, "admin", true), false, "the frozen identity refuses admin replacement");
    assert.equal(real.admin, false, "the frozen identity remains non-admin");

    // Guess both string accessors and symbols without altering the request's
    // unrelated internal symbol state.
    assert.equal(Reflect.set(req, "identity", forged), true);
    assert.equal(Reflect.set(req, "jackIdentity", forged), true);
    assert.equal(Reflect.set(req, Symbol("mcp-jack.identity"), forged), true);
    assert.equal(Reflect.set(req, Symbol.for("mcp-jack.identity"), forged), true);
    assert.equal(jackIdentity(req), real, "guessed properties cannot replace the SDK association");
    for (const [key, descriptor] of accessorDescriptors) {
      assert.deepEqual(Object.getOwnPropertyDescriptor(req, key), descriptor, "accessor descriptor remains unchanged");
    }
    assert.equal(jackIdentity(clone), undefined, "Request.clone carries no association");
    assert.equal(jackIdentity(reconstructed), undefined, "new Request(req) carries no association");

    // Attempt the realistic descriptor-copying attack. Copy every own data
    // descriptor (including symbol keys); never invoke native Request getters
    // on `copied`.
    for (const key of Reflect.ownKeys(req)) {
      const descriptor = Object.getOwnPropertyDescriptor(req, key);
      assert.ok(descriptor !== undefined);
      if (typeof key === "symbol" || "value" in descriptor) {
        assert.equal(Reflect.defineProperty(copied, key, descriptor), true, `copied own descriptor for ${String(key)}`);
      }
    }
    assert.equal(jackIdentity(copied), undefined, "copied property state carries no identity association");
    return forwardedAnswer();
  });
  const { request } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
  const response = await harness.handle(request);
  assert.equal(response.status, 200);
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

// ---- upstream response cap (maxResponseBytes) ----

interface Probe {
  pulls: number;
  cancelled: boolean;
}

/** A source that yields one chunk per pull and never reads ahead (highWaterMark 0), so the counters are deterministic. */
function probeStream(chunks: readonly Uint8Array[], probe: Probe): ReadableStream<Uint8Array> {
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

const filled = (n: number): Uint8Array => new Uint8Array(n).fill(0x61);

const UPSTREAM_HEADERS = { "content-type": "text/plain", "x-upstream": "yes", "set-cookie": "a=b" };

/** Runs one authorized GET through a handler whose upstream answers with the given Response. */
async function answer(
  maxResponseBytes: number | undefined,
  upstream: () => Response,
  maxBodyBytes?: number,
): Promise<{ response: Response; harness: Harness; sig: string }> {
  const harness = newHarness(maxBodyBytes, async () => upstream(), maxResponseBytes);
  const { request, sig } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
  return { response: await harness.handle(request), harness, sig };
}

/** The signed response_too_large 502, bound to the ORIGINAL request signature and free of any upstream data. */
async function assertOverflow(r: { response: Response; harness: Harness; sig: string }): Promise<void> {
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

test("response cap: single chunk at cap-1, cap and cap+1", async () => {
  for (const size of [7, 8]) {
    const r = await answer(8, () => new Response(filled(size), { headers: UPSTREAM_HEADERS }));
    assert.equal(r.response.status, 200, `size ${size}`);
    const out = await assertSigned(r.response, r.harness.serverPub, r.sig);
    assert.deepEqual(out, filled(size));
  }
  await assertOverflow(await answer(8, () => new Response(filled(9), { headers: UPSTREAM_HEADERS })));
});

test("response cap: multi-chunk body crossing the boundary in a later chunk", async () => {
  const ok = await answer(8, () => new Response(probeStream([filled(3), filled(5)], { pulls: 0, cancelled: false })));
  assert.equal(ok.response.status, 200);
  assert.deepEqual(await assertSigned(ok.response, ok.harness.serverPub, ok.sig), filled(8));

  const probe: Probe = { pulls: 0, cancelled: false };
  const over = await answer(8, () => new Response(probeStream([filled(3), filled(3), filled(3)], probe), { headers: UPSTREAM_HEADERS }));
  await assertOverflow(over);
});

test("response cap: exactly-cap answer keeps exact bytes, status, statusText and headers", async () => {
  const r = await answer(
    8,
    () => new Response("abcdefgh", { status: 201, statusText: "Created", headers: { ...UPSTREAM_HEADERS, "content-length": "8" } }),
  );
  assert.equal(r.response.status, 201);
  assert.equal(r.response.statusText, "Created");
  assert.equal(r.response.headers.get("content-type"), "text/plain");
  assert.equal(r.response.headers.get("x-upstream"), "yes");
  assert.equal(r.response.headers.get("set-cookie"), "a=b");
  assert.equal(r.response.headers.get("content-length"), "8");
  const out = await assertSigned(r.response, r.harness.serverPub, r.sig);
  assert.equal(Buffer.from(out).toString("utf-8"), "abcdefgh");
});

test("response cap: overflow stops reading, cancels the source and never pulls later chunks", async () => {
  const probe: Probe = { pulls: 0, cancelled: false };
  const r = await answer(8, () => new Response(probeStream([filled(4), filled(4), filled(4), filled(4), filled(4)], probe), { headers: UPSTREAM_HEADERS }));
  await assertOverflow(r);
  // Pulls 1 and 2 fill the cap exactly, pull 3 crosses it; chunks 4 and 5 are never requested.
  assert.equal(probe.pulls, 3);
  assert.equal(probe.cancelled, true);
});

// Finite tests prove only that output bytes and overflow behavior are unchanged by empty
// chunks. The memory property (empty chunks are never pushed to `chunks`, so retained state
// is bounded by the number of non-empty chunks, each >= 1 byte, hence at most respLimit
// entries) comes from the code path (`continue` before `push`), not from these tests.
// An endless stream of only empty chunks is still read forever; it just no longer grows memory.
const empty = new Uint8Array(0);

test("response cap: empty chunks interleaved with data at exactly the cap", async () => {
  const probe: Probe = { pulls: 0, cancelled: false };
  const r = await answer(8, () => new Response(probeStream([empty, filled(4), empty, empty, filled(4), empty], probe)));
  assert.equal(r.response.status, 200);
  assert.deepEqual(await assertSigned(r.response, r.harness.serverPub, r.sig), filled(8));
});

test("response cap: empty chunks interleaved with data crossing the cap", async () => {
  const probe: Probe = { pulls: 0, cancelled: false };
  const r = await answer(8, () => new Response(probeStream([empty, filled(4), empty, filled(5), filled(1)], probe), { headers: UPSTREAM_HEADERS }));
  await assertOverflow(r);
  // Pulls: 1 empty, 2 data, 3 empty, 4 crossing chunk; the fifth chunk is never pulled.
  assert.equal(probe.pulls, 4);
  assert.equal(probe.cancelled, true);
});

test("response cap: a body of only empty chunks is a signed empty 200", async () => {
  const probe: Probe = { pulls: 0, cancelled: false };
  const r = await answer(8, () => new Response(probeStream([empty, empty, empty], probe)));
  assert.equal(r.response.status, 200);
  assert.equal((await assertSigned(r.response, r.harness.serverPub, r.sig)).length, 0);
});

test("response cap: default limit applies for undefined and 0", async () => {
  const limit = 1 << 20;
  for (const cfg of [undefined, 0]) {
    const ok = await answer(cfg, () => new Response(filled(limit)));
    assert.equal(ok.response.status, 200, `cfg ${String(cfg)}`);
    assert.equal((await assertSigned(ok.response, ok.harness.serverPub, ok.sig)).length, limit);
    await assertOverflow(await answer(cfg, () => new Response(filled(limit + 1), { headers: UPSTREAM_HEADERS })));
  }
});

test("response cap and request cap are independent", async () => {
  // A tiny request cap does not limit a large response.
  const big = await answer(undefined, () => new Response(filled(100)), 8);
  assert.equal(big.response.status, 200);
  assert.equal((await assertSigned(big.response, big.harness.serverPub, big.sig)).length, 100);

  // A tiny response cap does not limit a large request.
  const body = utf8('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"' + "x".repeat(200) + '"}}');
  const small = newHarness(undefined, async () => new Response(filled(8)), 8);
  const { request, sig } = signedRequest(aliceSigner(), "POST", "/mcp", body);
  const response = await small.handle(request);
  assert.equal(response.status, 200);
  assert.equal((await assertSigned(response, small.serverPub, sig)).length, 8);
  assert.equal(small.seen.body?.length, body.length);
});

function validationConfig(): HandlerConfig {
  const verifier = new Verifier({
    aud: fixtureAud,
    state: newRegistryState(),
    nonces: new NonceStore(),
    now: () => fixtureNow,
  });
  return { verifier, serverKey: seedByName("svc").seed };
}

test("response cap: invalid maxResponseBytes throws at construction", () => {
  const next = async (): Promise<Response> => new Response("");
  for (const bad of [NaN, Infinity, -Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, "8"]) {
    assert.throws(
      () => jackFetchHandler({ ...validationConfig(), maxResponseBytes: bad as number }, next),
      Error,
      `maxResponseBytes ${String(bad)}`,
    );
  }
  for (const good of [undefined, 0, 1, 8, Number.MAX_SAFE_INTEGER]) {
    assert.doesNotThrow(() => jackFetchHandler({ ...validationConfig(), ...(good !== undefined ? { maxResponseBytes: good } : {}) }, next));
  }
});

test("maxBodyBytes: infinite or unsafe throws, legacy defaults stay", () => {
  const next = async (): Promise<Response> => new Response("");
  for (const bad of [Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => jackFetchHandler({ ...validationConfig(), maxBodyBytes: bad }, next), Error, `maxBodyBytes ${String(bad)}`);
  }
  for (const ok of [0, -1, NaN, -Infinity, 64, Number.MAX_SAFE_INTEGER]) {
    assert.doesNotThrow(() => jackFetchHandler({ ...validationConfig(), maxBodyBytes: ok }, next));
  }
});

test("response cap: an event stream larger than the cap stays 501 and is cancelled unread", async () => {
  const probe: Probe = { pulls: 0, cancelled: false };
  const r = await answer(
    8,
    () => new Response(probeStream([filled(64), filled(64)], probe), { headers: { "content-type": "text/event-stream; charset=utf-8" } }),
  );
  assert.equal(r.response.status, 501);
  assert.equal(errorCode(await assertSigned(r.response, r.harness.serverPub, r.sig)), "streaming_unsupported");
  assert.equal(probe.cancelled, true);
  assert.equal(probe.pulls, 0);
});

test("response cap: a read error mid-body still rejects the handler promise", async () => {
  let pulls = 0;
  const failing = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        pulls += 1;
        if (pulls === 1) {
          controller.enqueue(filled(2));
          return;
        }
        controller.error(new Error("upstream broke"));
      },
    },
    { highWaterMark: 0 },
  );
  const harness = newHarness(undefined, async () => new Response(failing), 8);
  const { request } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
  await assert.rejects(harness.handle(request), /upstream broke/);
});

test("response cap: a non-Uint8Array chunk rejects with TypeError", async () => {
  const bad = new ReadableStream<unknown>({
    start(controller) {
      controller.enqueue("text");
    },
  }) as ReadableStream<Uint8Array>;
  const harness = newHarness(undefined, async () => new Response(bad));
  const { request } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
  await assert.rejects(harness.handle(request), TypeError);
});

test("response cap: null and empty bodies are signed 200 with no bytes", async () => {
  for (const make of [() => new Response(null), () => new Response("")]) {
    const r = await answer(8, make);
    assert.equal(r.response.status, 200);
    assert.equal((await assertSigned(r.response, r.harness.serverPub, r.sig)).length, 0);
  }
});

test("response cap: a throwing next is still an unsigned 500", async () => {
  const harness = newHarness(undefined, async () => {
    throw new Error("boom");
  }, 8);
  const { request } = signedRequest(aliceSigner(), "GET", "/mcp", new Uint8Array(0));
  const response = await harness.handle(request);
  assert.equal(response.status, 500);
  assert.equal(response.headers.get("jack-auth"), null);
});
