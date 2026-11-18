/** Routing and configuration rules of the candidate jack.server.key wiring (verifier dispatch + HandlerConfig profile checks); no rotation store needed. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { parseRequestAuth } from "../../../src/core/auth-header.js";
import { signRequest, randomNonce, verifyResponse } from "../../../src/client/signing/auth.js";
import { InMemorySigner } from "../../../src/client/signing/signer.js";
import { encodeBase64URL } from "../../../src/core/encoding.js";
import { MemoryAuditSink } from "../../../src/server/audit.js";
import { jackFetchHandler } from "../../../src/server/http/fetch.js";
import type { ResponseKeyProvider } from "../../../src/server/http/fetch.js";
import { Native } from "../../../src/server/native.js";
import { NonceStore } from "../../../src/server/registry/nonce.js";
import { MemoryState } from "../../../src/server/registry/state.js";
import { Verifier } from "../../../src/server/verify.js";
import type { NativeCall, NativeTools } from "../../../src/server/verify.js";
import { TOOL_SERVER_KEY } from "../../../src/server/verify.js";

const AUD = "https://routing.test";
const NOW = 1700000000;
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const caller = new InMemorySigner(createHash("sha256").update("routing test caller").digest());
const serverSeed = createHash("sha256").update("routing test static server key").digest();
const serverSigner = new InMemorySigner(serverSeed);

function registry(): MemoryState {
  const state = new MemoryState();
  state.update((edit) => edit.putKey({ kid: caller.kid(), publicKey: encodeBase64URL(caller.publicKey()), name: "caller" }));
  return state;
}

/** Verifier over the one-caller registry; optional tool routes via conditional spreads (exactOptionalPropertyTypes). */
function baseVerifier(extra: { native?: NativeTools; serverKeys?: NativeTools } = {}): Verifier {
  return new Verifier({
    aud: AUD,
    state: registry(),
    nonces: new NonceStore(),
    now: () => NOW,
    ...(extra.native !== undefined ? { native: extra.native } : {}),
    ...(extra.serverKeys !== undefined ? { serverKeys: extra.serverKeys } : {}),
  });
}

const echo = async (req: Request): Promise<Response> => new Response(await req.arrayBuffer(), { status: 200 });

function signedRequest(body: Uint8Array): { request: Request; sig: string } {
  const header = signRequest(caller, AUD, "POST", "/mcp", body, randomNonce(), NOW);
  const sig = parseRequestAuth([header]).sig;
  return { request: new Request("http://localhost/mcp", { method: "POST", headers: { "jack-auth": header }, body }), sig };
}

function toolCall(name: string, args: string): Uint8Array {
  return utf8(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${name}","arguments":${args}}}`);
}

async function assertSignedBy(response: Response, serverPub: Uint8Array, requestSig: string): Promise<Uint8Array> {
  const body = new Uint8Array(await response.arrayBuffer());
  const hv = response.headers.get("jack-auth");
  assert.ok(hv !== null, "response carries no jack-auth header");
  verifyResponse(serverPub, response.status, [hv], requestSig, body, NOW, 30);
  return body;
}

function errorCode(body: Uint8Array): string {
  const parsed = JSON.parse(Buffer.from(body).toString("utf-8")) as { error?: { code?: string } };
  assert.ok(parsed.error !== undefined && typeof parsed.error.code === "string");
  return parsed.error.code;
}

/** Never-called stubs; their type annotations keep the config literals exact. */
const unusedProvider: ResponseKeyProvider = { authorizeResponse: (): never => { throw new Error("authorizeResponse must not be called"); } };
const unusedTool: NativeTools = { call: (): never => { throw new Error("call must not be reached"); } };

/** Rotation profile stub: always authorizes the fixed signer at NOW and has a no-op final gate (selection/final-gate behaviour is covered by the store-backed wiring tests). */
const fixedProvider: ResponseKeyProvider = {
  authorizeResponse: () => ({
    signer: {
      publicKeyB64u: encodeBase64URL(serverSigner.publicKey()),
      publicKey: () => serverSigner.publicKey(),
      sign: (message: Uint8Array) => serverSigner.sign(message),
    },
    timestamp: NOW,
    final: (): void => {},
    release: (): void => {},
  }),
};

test("handler config: both response-signing profiles are a construction error", () => {
  assert.throws(() => jackFetchHandler({ verifier: baseVerifier(), serverKey: serverSeed, rotationKeys: unusedProvider }, echo),
    /select exactly one response signing profile/);
});

test("handler config: neither profile is the classic serverKey error", () => {
  assert.throws(() => jackFetchHandler({ verifier: baseVerifier() }, echo),
    /HandlerConfig.serverKey must be an Ed25519 private key/);
});

test("handler config: verifier routing without a rotation profile is rejected", () => {
  assert.throws(() => jackFetchHandler({ verifier: baseVerifier({ serverKeys: unusedTool }), serverKey: serverSeed }, echo),
    /candidate server-key delivery requires ResponseKeys/);
});

test("verifier routesServerKey reflects the serverKeys configuration", () => {
  assert.equal(baseVerifier().routesServerKey, false);
  assert.equal(baseVerifier({ serverKeys: unusedTool }).routesServerKey, true);
});

test("without rotation jack.server.key stays denied exactly as today: signed 403, no audit, not forwarded", async () => {
  const audit = new MemoryAuditSink();
  const seen = { next: 0 };
  const next = async (req: Request): Promise<Response> => {
    seen.next += 1;
    return echo(req);
  };
  const handle = jackFetchHandler({
    verifier: new Verifier({ aud: AUD, state: registry(), nonces: new NonceStore(), audit, native: new Native(), now: () => NOW }),
    serverKey: serverSeed,
  }, next);
  const { request, sig } = signedRequest(toolCall(TOOL_SERVER_KEY, "{}"));
  const response = await handle(request);
  assert.equal(response.status, 403);
  const body = await assertSignedBy(response, serverSigner.publicKey(), sig);
  assert.equal(errorCode(body), "operation_denied");
  assert.equal(seen.next, 0);
  assert.deepEqual(audit.events(), []);
});

test("with serverKeys configured jack.server.key is dispatched to serverKeys, not native", async () => {
  const routed: string[] = [];
  const serverKeys: NativeTools = {
    call: (c: NativeCall) => {
      routed.push(c.tool);
      return { structured: { routed: true } };
    },
  };
  const handle = jackFetchHandler({
    verifier: baseVerifier({ native: new Native(), serverKeys }),
    rotationKeys: fixedProvider,
  }, echo);
  const { request, sig } = signedRequest(toolCall(TOOL_SERVER_KEY, "{}"));
  const response = await handle(request);
  assert.equal(response.status, 200);
  const body = await assertSignedBy(response, serverSigner.publicKey(), sig);
  const parsed = JSON.parse(Buffer.from(body).toString("utf-8")) as { result?: { structuredContent?: { routed?: boolean } } };
  assert.equal(parsed.result?.structuredContent?.routed, true);
  assert.deepEqual(routed, [TOOL_SERVER_KEY]);
});

test("current-v1 tools keep native routing while serverKeys is configured", async () => {
  const serverKeys: NativeTools = {
    call: (): never => { throw new Error("whoami must not reach serverKeys"); },
  };
  const handle = jackFetchHandler({
    verifier: baseVerifier({ native: new Native(), serverKeys }),
    rotationKeys: fixedProvider,
  }, echo);
  const { request, sig } = signedRequest(toolCall("jack.whoami", "{}"));
  const response = await handle(request);
  assert.equal(response.status, 200);
  const body = await assertSignedBy(response, serverSigner.publicKey(), sig);
  const parsed = JSON.parse(Buffer.from(body).toString("utf-8")) as { result?: { structuredContent?: { kid?: string; name?: string; admin?: boolean } } };
  assert.equal(parsed.result?.structuredContent?.kid, caller.kid());
  assert.equal(parsed.result?.structuredContent?.name, "caller");
  assert.equal(parsed.result?.structuredContent?.admin, false);
});
