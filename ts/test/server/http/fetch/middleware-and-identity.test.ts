import { test } from "node:test";
import assert from "node:assert/strict";
import { parseRequestAuth } from "../../../../src/core/auth-header.js";
import { decodeBase64URLFixed, encodeBase64URL } from "../../../../src/core/encoding.js";
import { verify as verifyEd25519 } from "../../../../src/core/ed25519.js";
import { requestSigningString } from "../../../../src/core/signing.js";
import { signRequest, randomNonce } from "../../../../src/client/signing/auth.js";
import { NonceStore } from "../../../../src/server/registry/nonce.js";
import { MemoryState } from "../../../../src/server/registry/state.js";
import { Verifier } from "../../../../src/server/verify.js";
import type { VerifyResult } from "../../../../src/server/verify.js";
import { jackFetchHandler, jackIdentity } from "../../../../src/server/http/fetch.js";
import type { JackIdentity } from "../../../../src/server/verify.js";
import type { DurableAdmission } from "../../../../src/server/durable/admission.js";
import { loadRegistry } from "../../../support/fixtures/index.js";
import { fixtureAud, fixtureNow, seedSignerByName } from "../../../support/client-harness.js";
import { utf8, newRegistryState, toolCallBody, newHarness, signedRequest, assertSigned, errorCode, aliceSigner, rootSigner, toolCallBodyArgs, forwardedAnswer, promiseGate, answer, seedByName } from "./support.js";

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

test("middleware signs a HEAD refusal over the empty body after the nonce is recorded", async () => {
  // A HEAD reaches verification only on the modern profile (fetch.ts refuses a
  // legacy-era non-POST request with an UNSIGNED 405 before authentication).
  // A modern HEAD is then refused by S2 as a JSON-RPC 405 before any body
  // refusal, so the reachable non-rpcRefusal refusal of an authenticated HEAD
  // is a POST-commit durable-admission failure: the reservation runs after
  // the signature verifies and BEFORE the era rules, so the nonce is already
  // recorded when it refuses. A HEAD response carries no content, so the
  // refusal must sign the zero bytes the client actually receives.
  const svc = seedByName("svc");
  const durable: DurableAdmission = {
    reserveForVerify: () => ({
      accepted: false,
      httpStatus: 503,
      code: "state_changed",
      message: "verification state changed",
      nonceRecorded: true,
      finish: () => {},
    }),
  };
  const verifier = new Verifier({ aud: fixtureAud, state: newRegistryState(), durable, now: () => fixtureNow });
  let calls = 0;
  const handle = jackFetchHandler({ verifier, serverKey: svc.seed, profile: "modern" }, async () => {
    calls += 1;
    return new Response("nope");
  });
  const { request, sig } = signedRequest(aliceSigner(), "HEAD", "/mcp", new Uint8Array(0));
  const response = await handle(request);

  assert.equal(response.status, 503, "a post-commit durable-admission refusal keeps its status");
  const body = await assertSigned(response, svc.signer.publicKey(), sig);
  assert.equal(body.byteLength, 0, "a HEAD refusal transmits no body bytes");
  assert.equal(response.headers.get("content-length"), "0");
  assert.equal(calls, 0, "a refused request never reaches the wrapped handler");
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
