/**
 * Durable admission seam end-to-end tests (candidate profile, spec/candidate/
 * durable-nonces.md sections 1, 2, 5): real Ed25519-signed requests through a
 * Verifier wired with the DurableNonceAdmission seam, the fetch adapter and
 * the node adapter. Linux-gated like the durable store tests (exclusive owner
 * marker file); every clock touch uses the injected clock.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import type { IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import type { KeyObject } from "node:crypto";
import { createPrivateKey, createPublicKey, randomBytes, sign as nodeSign } from "node:crypto";
import { chmodSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeBase64URL, keyId } from "../src/encoding.js";
import { requestSigningString } from "../src/signing.js";
import { formatRequestAuth, parseRequestAuth } from "../src/auth-header.js";
import { randomNonce, verifyResponse } from "../src/client/auth.js";
import { Native } from "../src/server/native.js";
import { NonceStore } from "../src/server/nonce.js";
import { MemoryState, inviteIdOf } from "../src/server/state.js";
import type { RegistryEntry } from "../src/server/state.js";
import { Verifier } from "../src/server/verify.js";
import type { VerifyRequest } from "../src/server/verify.js";
import { jackFetchHandler } from "../src/server/fetch.js";
import { serveNode } from "../src/server/node.js";
import { DurableNonceStore } from "../src/server/durable-store.js";
import { DurableNonceAdmission } from "../src/server/durable-admission.js";

const linux = process.platform === "linux";

const DEPLOYMENT = "durable-admission-test-deployment";
const WINDOW = 30;
const AUD = "https://durable.test";
const PING = '{"jsonrpc":"2.0","id":1,"method":"ping"}';
const NEXT_JSON = '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}';
const TARGET = "/mcp";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Scripted clock: consumes values in order, then repeats the last one. */
function scriptClock(...values: number[]): () => number {
  let index = 0;
  return () => {
    const value = values[Math.min(index, values.length - 1)] as number;
    index++;
    return value;
  };
}

/** Private 0700 scratch directory with a store file path inside it. */
function directory(): string {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mcp-jack-durable-admission-")));
  chmodSync(dir, 0o700);
  return join(dir, "nonce-store");
}

/** Fresh Ed25519 key material with its derived kid. */
function freshKey(): { priv: KeyObject; pub: Uint8Array; kid: string } {
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const priv = createPrivateKey({ key: Buffer.concat([pkcs8Prefix, randomBytes(32)]), format: "der", type: "pkcs8" });
  const der = createPublicKey(priv).export({ type: "spki", format: "der" });
  const pub = new Uint8Array(der.subarray(der.length - 32));
  return { priv, pub, kid: keyId(pub) };
}

/** Signs one request header over the EXACT body bytes at the given ts/nonce. */
function signedHeader(key: { priv: KeyObject; kid: string }, ts: number, nonce: string, body: Uint8Array): string {
  const msg = requestSigningString("POST", TARGET, AUD, key.kid, ts, nonce, body);
  const sig = encodeBase64URL(new Uint8Array(nodeSign(null, Buffer.from(msg), key.priv)));
  return formatRequestAuth({ kid: key.kid, ts, nonce, sig });
}

interface SignedRequest {
  /** Jack-Auth header value, exactly as signed. */
  readonly header: string;
  readonly nonce: string;
  /** The request signature carried by the header. */
  readonly sig: string;
}

/** One fresh-nonce signed request over the ping body. */
function signOne(key: { priv: KeyObject; kid: string }, ts: number): SignedRequest {
  const nonce = encodeBase64URL(randomNonce());
  const header = signedHeader(key, ts, nonce, utf8(PING));
  return { header, nonce, sig: parseRequestAuth([header]).sig };
}

/** A fetch Request carrying the signed header and the exact ping bytes. */
function fetchRequest(signed: SignedRequest): Request {
  return new Request("http://localhost" + TARGET, {
    method: "POST",
    headers: { "jack-auth": signed.header },
    body: Buffer.from(utf8(PING)),
  });
}

/** Registry state holding exactly one registered caller key. */
function registryWith(entry: RegistryEntry): MemoryState {
  const state = new MemoryState();
  state.update((edit) => edit.putKey(entry));
  return state;
}

interface Rig {
  readonly verifier: Verifier;
  readonly store: DurableNonceStore;
  readonly nonces: NonceStore;
  readonly clock: () => number;
  /** The registered caller key. */
  readonly caller: { priv: KeyObject; pub: Uint8Array; kid: string };
}

/** Opens a fresh durable store and wires it into a verifier with the seam. */
function rig(clock: () => number, path: string, opts?: { window?: number }): Rig {
  const store = DurableNonceStore.open(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
  const admission = new DurableNonceAdmission({ store, now: clock });
  const caller = freshKey();
  const nonces = new NonceStore();
  const verifier = new Verifier({
    aud: AUD,
    state: registryWith({ kid: caller.kid, publicKey: encodeBase64URL(caller.pub), name: "svc" }),
    nonces,
    native: new Native(),
    now: clock,
    durable: admission,
    ...(opts?.window !== undefined ? { window: opts.window } : {}),
  });
  return { verifier, store, nonces, clock, caller };
}

/** Wraps the rig's verifier in the fetch adapter with the given server key. */
function fetchHandler(rigValue: Rig, serverKey: KeyObject): (req: Request) => Promise<Response> {
  return jackFetchHandler({ verifier: rigValue.verifier, serverKey }, async () =>
    new Response(NEXT_JSON, { headers: { "content-type": "application/json" } }));
}

/** Reads the JSON error envelope {error:{code}} of a response. */
async function errorCode(res: Response): Promise<string> {
  const bytes = new Uint8Array(await res.arrayBuffer());
  const parsed = JSON.parse(Buffer.from(bytes).toString("utf-8")) as { error?: { code?: string } };
  return parsed.error?.code ?? "";
}

test("durable admission: accepted request, volatile store untouched, replay after crash/restart refused unsigned",
  { skip: !linux }, async () => {
    const path = directory();
    const clock = scriptClock(100);
    DurableNonceStore.initializeUnused(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    const first = rig(clock, path);
    const serverKey = freshKey();
    let calls = 0;
    const handle = jackFetchHandler({ verifier: first.verifier, serverKey: serverKey.priv }, async () => {
      calls++;
      return new Response(NEXT_JSON, { headers: { "content-type": "application/json" } });
    });

    const r1 = signOne(first.caller, 100);
    const res1 = await handle(fetchRequest(r1));
    assert.equal(res1.status, 200, "first request accepted");
    const hv1 = res1.headers.get("jack-auth");
    assert.ok(hv1 !== null, "first answer signed");
    const body1 = new Uint8Array(await res1.arrayBuffer());
    verifyResponse(serverKey.pub, 200, [hv1], r1.sig, body1, 100, WINDOW);
    assert.equal(calls, 1, "wrapped handler dispatched");
    assert.equal(first.nonces.len(), 0, "volatile store untouched while durable is configured");
    assert.equal(first.store.state().counts.live, 1, "reservation committed");

    // Simulated crash/restart: close the store, reopen it, wire a new rig.
    // The finish ran with the response, so no serving lease is outstanding.
    first.store.close();
    const second = rig(clock, path);
    const handle2 = jackFetchHandler({ verifier: second.verifier, serverKey: serverKey.priv }, async () => {
      calls++;
      return new Response(NEXT_JSON, { headers: { "content-type": "application/json" } });
    });
    const res2 = await handle2(fetchRequest(r1));
    assert.equal(res2.status, 401, "replay refused after restart");
    assert.equal(await errorCode(res2), "replayed_nonce", "replay code");
    assert.equal(res2.headers.get("jack-auth"), null, "replayed_nonce stays unsigned (no nonce-recorded receipt)");
    assert.equal(calls, 1, "replay never dispatched");
    assert.equal(second.nonces.len(), 0, "volatile store still untouched");
    assert.equal(second.store.state().counts.live, 1, "committed reservation survived the restart");
    second.store.close();
  });

test("durable admission: stale post-commit sample refuses 401 without dispatch and keeps the reservation",
  { skip: !linux }, async () => {
    const path = directory();
    // init, open, verify, entry, intent, final, post-commit: 131 is stale.
    const clock = scriptClock(100, 100, 100, 100, 100, 100, 131);
    DurableNonceStore.initializeUnused(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    const r = rig(clock, path);
    const serverKey = freshKey();
    let calls = 0;
    const handle = jackFetchHandler({ verifier: r.verifier, serverKey: serverKey.priv }, async () => {
      calls++;
      return new Response(NEXT_JSON, { headers: { "content-type": "application/json" } });
    });
    const sr = signOne(r.caller, 100);
    const res = await handle(fetchRequest(sr));
    assert.equal(res.status, 401, "stale post-commit sample refuses");
    const bytes = new Uint8Array(await res.arrayBuffer());
    const parsed = JSON.parse(Buffer.from(bytes).toString("utf-8")) as { error?: { code?: string } };
    assert.equal(parsed.error?.code, "timestamp_out_of_window", "spec section 2 code");
    const hv = res.headers.get("jack-auth");
    assert.ok(hv !== null, "committed reservation makes the refusal signed");
    // The refusal was signed at the post-commit sample (131).
    verifyResponse(serverKey.pub, res.status, [hv], sr.sig, bytes, 131, WINDOW);
    assert.equal(calls, 0, "never dispatched");
    assert.equal(r.store.state().counts.live, 1, "committed reservation kept");
    r.store.close();
  });

test("durable admission: clock_unsafe then durability_unavailable surface unsigned 503 through the fetch adapter",
  { skip: !linux }, async () => {
    const path = directory();
    // init 100, open 100, verify 100, entry sample 99: below high water.
    const clock = scriptClock(100, 100, 100, 99);
    DurableNonceStore.initializeUnused(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    const r = rig(clock, path);
    let calls = 0;
    const handle = jackFetchHandler({ verifier: r.verifier, serverKey: freshKey().priv }, async () => {
      calls++;
      return new Response(NEXT_JSON, { headers: { "content-type": "application/json" } });
    });
    const res1 = await handle(fetchRequest(signOne(r.caller, 100)));
    assert.equal(res1.status, 503, "clock_unsafe status");
    assert.equal(res1.headers.get("jack-auth"), null, "unsigned 503");
    assert.equal(await errorCode(res1), "clock_unsafe", "spec section 5 code");
    assert.equal(calls, 0, "never dispatched");
    // The unsafe latch fenced the store: the next admission is unavailable.
    const res2 = await handle(fetchRequest(signOne(r.caller, 100)));
    assert.equal(res2.status, 503, "fenced store refuses");
    assert.equal(res2.headers.get("jack-auth"), null, "still unsigned");
    assert.equal(await errorCode(res2), "durability_unavailable", "fenced code");
  });

test("durable admission: window mismatch and explicit fence answer 503 state_changed / durability_unavailable",
  { skip: !linux }, async () => {
    const path = directory();
    const clock = scriptClock(100);
    DurableNonceStore.initializeUnused(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    // Verifier window differs from the store's immutable W: state_changed.
    const r = rig(clock, path, { window: 25 });
    const handle = fetchHandler(r, freshKey().priv);
    const res = await handle(fetchRequest(signOne(r.caller, 100)));
    assert.equal(res.status, 503, "state_changed status");
    assert.equal(await errorCode(res), "state_changed", "spec section 5 code");
    assert.equal(res.headers.get("jack-auth"), null, "unsigned 503");
    // Explicit fence: durability_unavailable.
    r.store.fence();
    const res2 = await handle(fetchRequest(signOne(r.caller, 100)));
    assert.equal(res2.status, 503, "fenced status");
    assert.equal(await errorCode(res2), "durability_unavailable", "fenced code");
  });

test("durable admission: node adapter finishes the admission after the response is written",
  { skip: !linux }, async (t) => {
    const path = directory();
    const clock = scriptClock(100);
    DurableNonceStore.initializeUnused(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    const r = rig(clock, path);
    const server = createServer(serveNode(fetchHandler(r, freshKey().priv), {}));
    t.after(() => server.close());
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address() as AddressInfo;
    const sr = signOne(r.caller, 100);
    const out = await rawRequest(addr.port, { "jack-auth": sr.header }, Buffer.from(utf8(PING)));
    assert.equal(out.status, 200, "accepted over node adapter");
    assert.ok(out.headers["jack-auth"] !== undefined, "signed answer written");
    // The admission finished only AFTER the write: the store drains and closes
    // cleanly once the response is on the wire.
    r.store.close();
    // A durable 503 also surfaces through the node adapter (fenced store).
    r.store.fence();
    const sr2 = signOne(r.caller, 100);
    const out2 = await rawRequest(addr.port, { "jack-auth": sr2.header }, Buffer.from(utf8(PING)));
    assert.equal(out2.status, 503, "durable 503 through node adapter");
    const parsed = JSON.parse(out2.body.toString("utf-8")) as { error?: { code?: string } };
    assert.equal(parsed.error?.code, "durability_unavailable", "fenced code over node adapter");
    assert.equal(out2.headers["jack-auth"], undefined, "still unsigned");
  });

/** Sends one raw node:http request and collects status/headers/body. */
function rawRequest(port: number, headers: Record<string, string>, body: Buffer): Promise<{
  status: number; headers: IncomingHttpHeaders; body: Buffer;
}> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: TARGET, headers, agent: false,
      signal: AbortSignal.timeout(2000) });
    const chunks: Buffer[] = [];
    req.on("response", (res) => {
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      const settle = (): void => {
        req.destroy();
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) });
      };
      res.on("end", settle);
      res.on("error", settle);
      res.on("close", settle);
    });
    req.on("error", reject);
    if (body.length > 0) req.write(body);
    req.end();
  });
}

test("durable admission: enrollment reserves durably before invite consumption and state change",
  { skip: !linux }, () => {
    const path = directory();
    const clock = scriptClock(100);
    DurableNonceStore.initializeUnused(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    const store = DurableNonceStore.open(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    const admission = new DurableNonceAdmission({ store, now: clock });
    const state = new MemoryState();
    const raw = new Uint8Array(32).fill(7);
    const code = encodeBase64URL(raw);
    state.update((edit) => edit.putInvite({ inviteId: inviteIdOf(raw), createdBy: "root", createdAt: 99, expiresAt: 200 }));
    const nonces = new NonceStore();
    const verifier = new Verifier({ aud: AUD, state, nonces, native: new Native(), now: clock, durable: admission });
    const k = freshKey();
    const args = JSON.stringify({ public_key: encodeBase64URL(k.pub), code });
    const enrollBody = utf8(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.enroll","arguments":${args}}}`);
    const nonce = encodeBase64URL(randomNonce());
    const msg = requestSigningString("POST", TARGET, AUD, k.kid, 100, nonce, enrollBody);
    const sig = encodeBase64URL(new Uint8Array(nodeSign(null, Buffer.from(msg), k.priv)));
    const res = verifier.verify({ method: "POST", target: TARGET,
      authValues: [formatRequestAuth({ kid: k.kid, ts: 100, nonce, sig })], body: enrollBody });
    assert.equal(res.accepted, true, "enrollment accepted");
    assert.equal(res.native, true, "answered by the native tool");
    // The durable reservation was committed BEFORE the invite was consumed.
    assert.equal(store.state().counts.live, 1, "nonce reserved durably");
    assert.equal(state.lookupInvite(inviteIdOf(raw)), undefined, "invite consumed after the reservation");
    assert.equal(nonces.len(), 0, "volatile store untouched");
    store.close();
  });

test("durable admission: absent option keeps the volatile default path identical", () => {
  const key = freshKey();
  const nonces = new NonceStore();
  const verifier = new Verifier({
    aud: AUD,
    state: registryWith({ kid: key.kid, publicKey: encodeBase64URL(key.pub), name: "svc" }),
    nonces,
    native: new Native(),
    now: () => 100,
  });
  const nonce = encodeBase64URL(randomNonce());
  const msg = requestSigningString("POST", TARGET, AUD, key.kid, 100, nonce, utf8(PING));
  const sig = encodeBase64URL(new Uint8Array(nodeSign(null, Buffer.from(msg), key.priv)));
  const req: VerifyRequest = { method: "POST", target: TARGET,
    authValues: [formatRequestAuth({ kid: key.kid, ts: 100, nonce, sig })], body: utf8(PING) };
  const res = verifier.verify(req);
  assert.equal(res.accepted, true, "accepted");
  assert.equal(nonces.len(), 1, "volatile store used");
  const replay = verifier.verify(req);
  assert.equal(replay.accepted, false, "volatile replay refused");
  assert.equal(replay.httpStatus, 401, "volatile replay status");
  assert.equal(replay.code, "replayed_nonce", "volatile replay code");
  assert.equal(replay.nonceRecorded, true, "volatile replay is nonce-recorded");
});
