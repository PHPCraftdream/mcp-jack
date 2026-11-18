/** The rotation response-signing profile end-to-end through jackFetchHandler: selected-key signing, overlap/cutoff schedule, final gate and fail-closed answers. Linux-only like the private-file store tests. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestContext } from "node:test";
import { parseRequestAuth } from "../../../src/core/auth-header.js";
import { signRequest, randomNonce, verifyResponse } from "../../../src/client/signing/auth.js";
import { InMemorySigner } from "../../../src/client/signing/signer.js";
import { encodeBase64URL, keyId } from "../../../src/core/encoding.js";
import { MemoryAuditSink } from "../../../src/server/audit.js";
import { jackFetchHandler } from "../../../src/server/http/fetch.js";
import { Native } from "../../../src/server/native.js";
import { NonceStore } from "../../../src/server/registry/nonce.js";
import { MemoryState } from "../../../src/server/registry/state.js";
import { ServerKeyTool } from "../../../src/server/server-key-tool.js";
import { Verifier } from "../../../src/server/verify.js";
import type { NativeCall, NativeTools } from "../../../src/server/verify.js";
import { TOOL_SERVER_KEY } from "../../../src/server/verify.js";
import { rotation } from "../../../src/index.js";
import { corpus, WINDOW } from "../../support/rotation-server-fixtures.js";

const linux = process.platform === "linux";
const START = 1000;
const GRACE = rotation.ROTATION_GRACE_SECONDS;
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const CALLER = new InMemorySigner(createHash("sha256").update("server wiring caller").digest());
const signerSeed = (index: number): Uint8Array => createHash("sha256").update(`server wiring signer ${index}`).digest();

interface Wiring {
  handle: (req: Request) => Promise<Response>;
  provider: rotation.RotationServerProvider;
  store: rotation.RotationServerStore;
  caller: InMemorySigner;
  signers: readonly InMemorySigner[];
  kids: readonly string[];
  audit: MemoryAuditSink;
  nextCalls: { count: number };
  setStoreNow(value: number): void;
}

/** Store (private Linux file) + provider + ServerKeyTool routing + rotation handler in front of an echoing next. */
function wiring(context: TestContext, options: { storeNow?: () => number; serverKeys?: NativeTools } = {}): Wiring {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mcp-jack-server-wiring-")));
  chmodSync(dir, 0o700);
  context.after(() => rmSync(dir, { recursive: true, force: true }));
  const signers = [0, 1, 2].map((index) => new InMemorySigner(signerSeed(index)));
  const anchor = signers[0];
  assert.ok(anchor);
  const checkpoint: rotation.RotationCheckpoint = {
    ordinal: 0,
    hash: "-",
    kid: keyId(anchor.publicKey()),
    publicKeyB64u: encodeBase64URL(anchor.publicKey()),
    publishedAt: 0,
  };
  let storeNow = START;
  const clock = options.storeNow ?? ((): number => storeNow);
  const config: rotation.RotationServerStoreOptions = {
    binding: corpus.binding,
    checkpoint,
    window: WINDOW,
    anchorReference: "ref-0",
    now: clock,
  };
  const path = join(dir, "ring");
  rotation.RotationServerStore.initializeUnused(path, config);
  const store = rotation.RotationServerStore.open(path, config);
  const keys = signers.map((signer, index) => ({ reference: `ref-${index}`, signer }));
  const provider = new rotation.RotationServerProvider(store, keys);
  const state = new MemoryState();
  state.update((edit) => edit.putKey({ kid: CALLER.kid(), publicKey: encodeBase64URL(CALLER.publicKey()), name: "caller" }));
  const audit = new MemoryAuditSink();
  const serverKeys = options.serverKeys ?? new ServerKeyTool(store, provider);
  const verifier = new Verifier({
    aud: corpus.binding.aud,
    state,
    nonces: new NonceStore(),
    audit,
    native: new Native(),
    serverKeys,
    now: () => START,
  });
  const nextCalls = { count: 0 };
  const handle = jackFetchHandler({ verifier, rotationKeys: provider }, async (req) => {
    nextCalls.count += 1;
    const body = new Uint8Array(await req.arrayBuffer());
    return new Response(body.length === 0 ? null : body, { status: 200, headers: { "content-type": "application/json" } });
  });
  return {
    handle,
    provider,
    store,
    caller: CALLER,
    signers,
    kids: signers.map((signer) => keyId(signer.publicKey())),
    audit,
    nextCalls,
    setStoreNow: (value: number): void => { storeNow = value; },
  };
}

function signedRequest(signer: InMemorySigner, method: string, target: string, body: Uint8Array): { request: Request; sig: string } {
  const header = signRequest(signer, corpus.binding.aud, method, target, body, randomNonce(), START);
  const sig = parseRequestAuth([header]).sig;
  return {
    request: new Request("http://localhost" + target, {
      method,
      headers: { "jack-auth": header },
      ...(method === "POST" && body.length > 0 ? { body } : {}),
    }),
    sig,
  };
}

function toolCall(name: string, args: string): Uint8Array {
  return utf8(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${name}","arguments":${args}}}`);
}

/** Verifies the response signature with the client-side verifier against one pinned key; returns the body. */
async function assertSignedBy(response: Response, serverPub: Uint8Array, requestSig: string, now: number): Promise<Uint8Array> {
  const body = new Uint8Array(await response.arrayBuffer());
  const hv = response.headers.get("jack-auth");
  assert.ok(hv !== null, "response carries no jack-auth header");
  verifyResponse(serverPub, response.status, [hv], requestSig, body, now, WINDOW);
  return body;
}

/** The unsigned 503 fail-closed answer of the rotation profile: no jack-auth header, exact code and message. */
async function assertUnsignedRefusal(response: Response): Promise<void> {
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("jack-auth"), null, "a refused rotation answer must stay unsigned");
  const parsed = JSON.parse(Buffer.from(await response.arrayBuffer()).toString("utf-8")) as {
    error?: { code?: string; message?: string };
  };
  assert.equal(parsed.error?.code, "rotation_state_unavailable");
  assert.equal(parsed.error?.message, "response authorization unavailable");
}

test("rotation handler: forwarded answers are signed with the selected key", { skip: !linux }, async (context) => {
  const env = wiring(context);
  const body = utf8('{"jsonrpc":"2.0","id":1,"method":"tools/list"}');
  const { request, sig } = signedRequest(env.caller, "POST", "/mcp", body);
  const response = await env.handle(request);
  assert.equal(response.status, 200);
  const selected = env.signers[0];
  assert.ok(selected);
  const echoed = await assertSignedBy(response, selected.publicKey(), sig, START);
  assert.deepEqual(echoed, body);
  assert.equal(env.nextCalls.count, 1);
  assert.equal(env.audit.events().length, 0);
  const hv = response.headers.get("jack-auth");
  assert.ok(hv !== null);
  const other = env.signers[1];
  assert.ok(other);
  assert.throws(() => verifyResponse(other.publicKey(), 200, [hv], sig, body, START, WINDOW),
    "only the selected key's signature verifies");
});

test("rotation handler: the jack.server.key page is served and signed by the selected key", { skip: !linux }, async (context) => {
  const env = wiring(context);
  const anchor = env.signers[0];
  assert.ok(anchor);
  const published = env.provider.announce("ref-1", env.kids[1] as string);
  const { request, sig } = signedRequest(env.caller, "POST", "/mcp",
    toolCall(TOOL_SERVER_KEY, '{"after_ordinal":0,"after_hash":"-"}'));
  const response = await env.handle(request);
  assert.equal(response.status, 200);
  const body = await assertSignedBy(response, anchor.publicKey(), sig, START);
  const parsed = JSON.parse(Buffer.from(body).toString("utf-8")) as { result?: { structuredContent?: unknown } };
  assert.deepEqual(parsed.result?.structuredContent, {
    current: { kid: env.kids[0] as string, public_key: encodeBase64URL(anchor.publicKey()) },
    records: [published.record.wire],
    head: { ordinal: 1, hash: published.record.hash },
    complete: true,
  });
  assert.ok(rotation.decodeRotationResult(body, 1), "the exact wire page must re-decode like the client's own parser");
  assert.equal(env.nextCalls.count, 0);
  assert.equal(env.audit.events().length, 0);
});

test("rotation handler: the old key signs until activation and the new key after it", { skip: !linux }, async (context) => {
  const env = wiring(context);
  env.provider.announce("ref-1", env.kids[1] as string);
  const body = utf8('{"jsonrpc":"2.0","id":1,"method":"tools/list"}');
  const old = env.signers[0];
  assert.ok(old);
  const pending = env.signers[1];
  assert.ok(pending);

  // Just before activation the still-current key signs.
  env.setStoreNow(START + GRACE - 1);
  const first = signedRequest(env.caller, "POST", "/mcp", body);
  const response1 = await env.handle(first.request);
  assert.equal(response1.status, 200);
  const body1 = await assertSignedBy(response1, old.publicKey(), first.sig, START + GRACE - 1);
  assert.deepEqual(body1, body);
  const hv1 = response1.headers.get("jack-auth");
  assert.ok(hv1 !== null);
  assert.throws(() => verifyResponse(pending.publicKey(), 200, [hv1], first.sig, body1, START + GRACE - 1, WINDOW),
    "the pending key never signs early");

  // At activation the successor signs with a fresh nonce.
  env.setStoreNow(START + GRACE);
  const second = signedRequest(env.caller, "POST", "/mcp", body);
  const response2 = await env.handle(second.request);
  assert.equal(response2.status, 200);
  const body2 = await assertSignedBy(response2, pending.publicKey(), second.sig, START + GRACE);
  assert.deepEqual(body2, body);
  const hv2 = response2.headers.get("jack-auth");
  assert.ok(hv2 !== null);
  assert.throws(() => verifyResponse(old.publicKey(), 200, [hv2], second.sig, body2, START + GRACE, WINDOW),
    "the old key stopped signing at activation");
});

test("rotation handler: the cutoff is strict — at exactly the cutoff the successor signs", { skip: !linux }, async (context) => {
  const env = wiring(context);
  env.provider.announce("ref-1", env.kids[1] as string);
  env.setStoreNow(START + GRACE);
  const retired = env.signers[0];
  assert.ok(retired);
  const successor = env.signers[1];
  assert.ok(successor);
  const first = signedRequest(env.caller, "GET", "/mcp", new Uint8Array(0));
  const response = await env.handle(first.request);
  assert.equal(response.status, 200);
  await assertSignedBy(response, successor.publicKey(), first.sig, START + GRACE);
  const hv = response.headers.get("jack-auth");
  assert.ok(hv !== null);
  assert.throws(() => verifyResponse(retired.publicKey(), 200, [hv], first.sig, new Uint8Array(0), START + GRACE, WINDOW),
    "the retired key is ineligible at its exact cutoff");
});

test("rotation handler: retirement between selection and completion discards the signature", { skip: !linux }, async (context) => {
  const samples: number[] = [];
  let fallback = START;
  const env = wiring(context, { storeNow: () => { const next = samples.shift(); return next === undefined ? fallback : next; } });
  env.provider.announce("ref-1", env.kids[1] as string);
  const body = utf8('{"jsonrpc":"2.0","id":1,"method":"tools/list"}');
  const { request } = signedRequest(env.caller, "POST", "/mcp", body);
  // The authorize sample keeps the old key eligible; the completion sample crosses the cutoff.
  samples.push(START + GRACE - 1, START + GRACE);
  const response = await env.handle(request);
  await assertUnsignedRefusal(response);
  assert.equal(env.nextCalls.count, 1, "the forwarded call happened, only its signature was discarded");
});

test("rotation handler: closed and fenced stores fail closed with the unsigned refusal", { skip: !linux }, async (context) => {
  const closedEnv = wiring(context);
  closedEnv.store.close();
  const first = signedRequest(closedEnv.caller, "GET", "/mcp", new Uint8Array(0));
  await assertUnsignedRefusal(await closedEnv.handle(first.request));

  const fencedEnv = wiring(context);
  fencedEnv.store.fence();
  const second = signedRequest(fencedEnv.caller, "GET", "/mcp", new Uint8Array(0));
  await assertUnsignedRefusal(await fencedEnv.handle(second.request));
});

test("rotation handler: a page that does not match the committed ring refuses the response", { skip: !linux }, async (context) => {
  const impostor = new InMemorySigner(signerSeed(2));
  const wrongPage: NativeTools = {
    call: (c: NativeCall) => {
      assert.equal(c.tool, TOOL_SERVER_KEY);
      return {
        structured: {
          current: { kid: impostor.kid(), public_key: encodeBase64URL(impostor.publicKey()) },
          records: [],
          head: { ordinal: 0, hash: "-" },
          complete: true,
        },
      };
    },
  };
  const env = wiring(context, { serverKeys: wrongPage });
  const { request } = signedRequest(env.caller, "POST", "/mcp",
    toolCall(TOOL_SERVER_KEY, '{"after_ordinal":0,"after_hash":"-"}'));
  const response = await env.handle(request);
  await assertUnsignedRefusal(response);
});
