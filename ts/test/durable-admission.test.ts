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
import { DurableNonceAdmission, takeResultFinish } from "../src/server/durable-admission.js";

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
  readonly clock: () => number;
  /** The registered caller key. */
  readonly caller: { priv: KeyObject; pub: Uint8Array; kid: string };
}

/** Reusable caller key passed into a second rig (same kid after restart). */
interface ExistingKey { priv: KeyObject; pub: Uint8Array; kid: string }

/** Opens a fresh durable store and wires it into a verifier with the seam. */
function rig(clock: () => number, path: string, opts?: { window?: number },
  existing?: ExistingKey): Rig {
  const store = DurableNonceStore.open(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
  const admission = new DurableNonceAdmission({ store, now: clock });
  const caller = existing ?? freshKey();
  // T8 exactly-one-nonce-profile: `nonces` must be ABSENT when `durable` is
  // configured, so no volatile store is wired into this verifier at all (the
  // durable path never touches one; see verify.ts step 5).
  const verifier = new Verifier({
    aud: AUD,
    state: registryWith({ kid: caller.kid, publicKey: encodeBase64URL(caller.pub), name: "svc" }),
    native: new Native(),
    now: clock,
    durable: admission,
    ...(opts?.window !== undefined ? { window: opts.window } : {}),
  });
  return { verifier, store, clock, caller };
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
    // The durable profile reserves in the durable store itself; the verifier
    // is built without any volatile store (exactly-one-nonce-profile), so the
    // old "volatile store untouched" check would be vacuous. The real
    // guarantee asserted here is the committed durable reservation below.
    assert.equal(first.store.state().counts.live, 1, "reservation committed");

    // Simulated crash/restart: close the store, reopen it, wire a new rig.
    // The finish ran with the response, so no serving lease is outstanding.
    first.store.close();
    // Reuse the first caller's key: the replay must be the same kid/nonce.
    const second = rig(clock, path, undefined, first.caller);
    const handle2 = jackFetchHandler({ verifier: second.verifier, serverKey: serverKey.priv }, async () => {
      calls++;
      return new Response(NEXT_JSON, { headers: { "content-type": "application/json" } });
    });
    const res2 = await handle2(fetchRequest(r1));
    assert.equal(res2.status, 401, "replay refused after restart");
    assert.equal(await errorCode(res2), "replayed_nonce", "replay code");
    assert.equal(res2.headers.get("jack-auth"), null, "replayed_nonce stays unsigned (no nonce-recorded receipt)");
    assert.equal(calls, 1, "replay never dispatched");
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
    const root = freshKey();
    // Admin root key registered first: enrollment needs a live admin creator.
    state.update((edit) => edit.putKey({ kid: root.kid, publicKey: encodeBase64URL(root.pub), name: "root", admin: true }));
    const raw = new Uint8Array(32).fill(7);
    const code = encodeBase64URL(raw);
    state.update((edit) => edit.putInvite({ inviteId: inviteIdOf(raw), createdBy: "root", createdAt: 99, expiresAt: 200 }));
    const k = freshKey();
    // Exactly-one-nonce-profile: no volatile store alongside `durable`.
    const verifier = new Verifier({ aud: AUD, state, native: new Native(), now: clock, durable: admission });
    const args = JSON.stringify({ name: "svc-enrolled", public_key: encodeBase64URL(k.pub), code });
    const enrollBody = utf8(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.enroll","arguments":${args}}}`);
    const nonce = encodeBase64URL(randomNonce());
    const msg = requestSigningString("POST", TARGET, AUD, k.kid, 100, nonce, enrollBody);
    const sig = encodeBase64URL(new Uint8Array(nodeSign(null, Buffer.from(msg), k.priv)));
    const res = verifier.verify({ method: "POST", target: TARGET,
      authValues: [formatRequestAuth({ kid: k.kid, ts: 100, nonce, sig })], body: enrollBody });
    assert.equal(res.accepted, true,
      `enrollment accepted (status=${res.httpStatus} code=${res.code} message=${res.message})`);
    assert.equal(res.native, true,
      `answered by the native tool (status=${res.httpStatus} code=${res.code} message=${res.message})`);
    // The durable reservation was committed BEFORE the invite was consumed.
    assert.equal(store.state().counts.live, 1, "nonce reserved durably");
    assert.equal(state.lookupInvite(inviteIdOf(raw)), undefined, "invite consumed after the reservation");
    // The verifier is built without any volatile store (exactly-one-nonce-profile), so the
    // old "volatile store untouched" check would be vacuous and is omitted.
    // The adapters finish the admission after the response; the direct verifier call does it here.
    takeResultFinish(res)?.();
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
  // A replay rejection has no nonce-recorded receipt and stays unsigned.
  assert.equal(replay.nonceRecorded, false, "volatile replay has no nonce-recorded receipt");
  assert.equal(replay.requestSig, "", "volatile replay stays unsigned");
});

// ---------------------------------------------------------------------------
// T6/T7 probes: unexpected transaction failures fence the store (Go Reserve,
// durable/admit.go:33-46) and the receipt binding matches Go receiptMatches
// field-for-field (server/admission.go:129-138).
// ---------------------------------------------------------------------------

import { DURABLE_MAX_TIMESTAMP } from "../src/server/durable-format.js";
import type { DurableReceipt } from "../src/server/durable-format.js";
import type { DurableAdmissionRequest, DurableAdmissionOutcome } from "../src/server/durable-admission.js";
import type { DurableNonceReservation } from "../src/server/durable-store.js";

/** One directly-admissable signed request for the seam (no verifier needed). */
function seamRequest(key: { priv: KeyObject; kid: string }, ts: number): DurableAdmissionRequest {
  const nonce = encodeBase64URL(randomNonce());
  const msg = requestSigningString("POST", TARGET, AUD, key.kid, ts, nonce, utf8(PING));
  const sig = encodeBase64URL(new Uint8Array(nodeSign(null, Buffer.from(msg), key.priv)));
  return { kid: key.kid, nonce, signature: sig, signingBytes: msg, timestamp: ts, window: WINDOW,
    caller: undefined };
}

/**
 * TEST-ONLY store view handing the adapter one tampered committed receipt
 * (receiptMatches probes): reserve delegates to the real store, every other
 * member is redirected so mutation cannot be shadowed on the view.
 */
function tamperedStore(store: DurableNonceStore,
  mutate: (receipt: DurableReceipt) => DurableReceipt): DurableNonceStore {
  const view = Object.create(store) as DurableNonceStore;
  view.reserve = (request: Parameters<DurableNonceStore["reserve"]>[0]): DurableNonceReservation => {
    const reservation = store.reserve(request);
    return { receipt: mutate(reservation.receipt), release: reservation.release };
  };
  view.fence = (): void => store.fence();
  view.isFenced = (): boolean => store.isFenced();
  return view;
}

/** Opens a store at t=100 and runs one admission through a receipt-tampering view. */
function probeReceipt(mutate: (receipt: DurableReceipt) => DurableReceipt):
  { readonly outcome: DurableAdmissionOutcome; readonly store: DurableNonceStore } {
  const path = directory();
  const clock = scriptClock(100);
  DurableNonceStore.initializeUnused(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
  const store = DurableNonceStore.open(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
  const admission = new DurableNonceAdmission({ store: tamperedStore(store, mutate), now: clock });
  const outcome = admission.reserveForVerify(seamRequest(freshKey(), 100));
  return { outcome, store };
}

/** A committed receipt that is not bound to the request must fence and refuse. */
function assertReceiptRefused(outcome: DurableAdmissionOutcome, store: DurableNonceStore): void {
  assert.equal(outcome.accepted, false, "mismatched receipt must be refused");
  if (outcome.accepted) return;
  assert.equal(outcome.httpStatus, 503, "receipt mismatch is durability_unavailable");
  assert.equal(outcome.code, "durability_unavailable", "receipt mismatch code");
  // The refusal happens BEFORE the post-commit sample, so nothing is reported
  // as nonce-recorded even though the reservation committed.
  assert.equal(outcome.nonceRecorded, false,
    "receipt mismatch precedes the post-commit sample (nonce-recorded stays false)");
  outcome.finish();
  assert.equal(store.isFenced(), true, "receipt mismatch fences the store");
  // A fenced owner cannot close cleanly (the scratch directory is left as-is).
  assert.throws(() => store.close(), { code: "durability_unavailable" });
}

test("durable admission: receipt intent id not bound to the request refuses and fences",
  { skip: !linux }, () => {
    const { outcome, store } = probeReceipt((receipt) => ({ ...receipt, intentId: "Tampered-Intent" }));
    assertReceiptRefused(outcome, store);
  });

test("durable admission: receipt format version not 1 refuses and fences",
  { skip: !linux }, () => {
    const { outcome, store } = probeReceipt((receipt) => ({ ...receipt, version: receipt.version + 1 }));
    assertReceiptRefused(outcome, store);
  });

test("durable admission: receipt with non-positive store generation refuses and fences",
  { skip: !linux }, () => {
    const { outcome, store } = probeReceipt((receipt) => ({ ...receipt, storeGeneration: 0 }));
    assertReceiptRefused(outcome, store);
  });

test("durable admission: receipt with non-positive owner generation refuses and fences",
  { skip: !linux }, () => {
    const { outcome, store } = probeReceipt((receipt) => ({ ...receipt, ownerGeneration: 0 }));
    assertReceiptRefused(outcome, store);
  });

test("durable admission: receipt with negative high water refuses and fences",
  { skip: !linux }, () => {
    const { outcome, store } = probeReceipt((receipt) => ({ ...receipt, highWater: -1 }));
    assertReceiptRefused(outcome, store);
  });

test("durable admission: receipt high water above the durable timestamp bound refuses and fences",
  { skip: !linux }, () => {
    const { outcome, store } =
      probeReceipt((receipt) => ({ ...receipt, highWater: DURABLE_MAX_TIMESTAMP + 1 }));
    assertReceiptRefused(outcome, store);
  });

test("durable admission: receipt high water farther than the window after the request refuses and fences",
  { skip: !linux }, () => {
    const { outcome, store } = probeReceipt((receipt) => ({ ...receipt, highWater: 100 + WINDOW + 1 }));
    assertReceiptRefused(outcome, store);
  });

test("durable admission: receipt high water farther than the window before the request refuses and fences",
  { skip: !linux }, () => {
    const { outcome, store } = probeReceipt((receipt) => ({ ...receipt, highWater: 100 - WINDOW - 1 }));
    assertReceiptRefused(outcome, store);
  });

test("durable admission: an unexpected error at the final sample fences the store and reports durability_unavailable",
  { skip: !linux }, () => {
    const path = directory();
    // Samples: init, startup, entry, intent, FINAL; the final call throws a
    // plain Error AFTER the intent transaction committed.
    let calls = 0;
    const clock = (): number => {
      calls++;
      if (calls === 5) throw new Error("clock exploded");
      return 100;
    };
    DurableNonceStore.initializeUnused(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    const store = DurableNonceStore.open(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    const admission = new DurableNonceAdmission({ store, now: () => 100 });
    const out = admission.reserveForVerify(seamRequest(freshKey(), 100));
    assert.equal(out.accepted, false, "unexpected failure must not be accepted");
    if (!out.accepted) {
      assert.equal(out.httpStatus, 503, "the raw Error is mapped to durability_unavailable");
      assert.equal(out.code, "durability_unavailable", "the raw Error never reaches the adapter");
      // A refused reserve is never reported as recorded (Go storageRejection); only
      // a returned receipt yields nonce-recorded.
      assert.equal(out.nonceRecorded, false, "a failed reserve carries no nonce-recorded receipt");
      out.finish();
    }
    assert.equal(store.isFenced(), true, "an unexpected failure fences the store");
    assert.equal(store.state().counts.intents, 1, "the committed intent stays behind the fence");
    // The fenced store refuses further admission with the mapped code.
    const again = admission.reserveForVerify(seamRequest(freshKey(), 100));
    assert.equal(again.accepted, false, "fenced store refuses");
    if (!again.accepted) {
      assert.equal(again.httpStatus, 503, "fenced status");
      assert.equal(again.code, "durability_unavailable", "fenced code");
    }
    assert.throws(() => store.close(), { code: "durability_unavailable" },
      "a fenced store cannot close cleanly");
  });

// ---------------------------------------------------------------------------
// T8 probes: Verifier constructor durable configuration validation (Go
// NewVerifier, server/verify.go: exactly one nonce profile; durable window
// 0..120) and the operation-id collision retry (durable/admit.go: two random
// attempts before fencing; spec section 1: on collision, allocate a new ID).
// ---------------------------------------------------------------------------

/** Stub seam that satisfies the Verifier's DurableAdmission shape without a store. */
const stubDurable = {
  reserveForVerify(): never {
    throw new Error("constructor validation test must not reserve");
  },
};

test("verifier constructor: selecting BOTH a volatile and a durable nonce store throws", () => {
  const key = freshKey();
  assert.throws(
    () => new Verifier({
      aud: AUD,
      state: registryWith({ kid: key.kid, publicKey: encodeBase64URL(key.pub), name: "svc" }),
      nonces: new NonceStore(),
      durable: stubDurable,
      native: new Native(),
      now: () => 100,
    }),
    /select exactly one nonce profile/,
    "both nonce profiles must be rejected",
  );
});

test("verifier constructor: durable bounds keep their established error", () => {
  const key = freshKey();
  for (const window of [-1, 121]) {
    assert.throws(
      () => new Verifier({
        aud: AUD,
        state: registryWith({ kid: key.kid, publicKey: encodeBase64URL(key.pub), name: "svc" }),
        durable: stubDurable,
        native: new Native(),
        now: () => 100,
        window,
      }),
      /durable window must be between 1 and 120 seconds/,
      `durable window ${window} must retain the durable bound error`,
    );
  }
});

test("verifier constructor: durable window fractions and unsafe integers use shared validation", () => {
  const key = freshKey();
  for (const window of [1.5, 2 ** 53]) {
    assert.throws(
      () => new Verifier({
        aud: AUD,
        state: registryWith({ kid: key.kid, publicKey: encodeBase64URL(key.pub), name: "svc" }),
        durable: stubDurable,
        native: new Native(),
        now: () => 100,
        window,
      }),
      /server: window must be 0 \(default 30\) or an integer between 1 and 120 seconds/,
      `durable window ${window} must be rejected`,
    );
  }
});

test("verifier constructor: durable window 120 is accepted (and 0 falls back to the default)", () => {
  const key = freshKey();
  assert.doesNotThrow(
    () => new Verifier({
      aud: AUD,
      state: registryWith({ kid: key.kid, publicKey: encodeBase64URL(key.pub), name: "svc" }),
      durable: stubDurable,
      native: new Native(),
      now: () => 100,
      window: 120,
    }),
    "window 120 is the inclusive maximum",
  );
  assert.doesNotThrow(
    () => new Verifier({
      aud: AUD,
      state: registryWith({ kid: key.kid, publicKey: encodeBase64URL(key.pub), name: "svc" }),
      durable: stubDurable,
      native: new Native(),
      now: () => 100,
      window: 0,
    }),
    "window 0 keeps the DEFAULT_WINDOW fallback like Go",
  );
});

test("verifier constructor: a volatile window above 120 is rejected", () => {
  const key = freshKey();
  // spec 01 section 4/task165: volatile and durable profiles share the 1..120-second window bound.
  assert.throws(
    () => new Verifier({
      aud: AUD,
      state: registryWith({ kid: key.kid, publicKey: encodeBase64URL(key.pub), name: "svc" }),
      nonces: new NonceStore(),
      native: new Native(),
      now: () => 100,
      window: 121,
    }),
    /server: window must be 0 \(default 30\) or an integer between 1 and 120 seconds/,
    "volatile profile shares the 120 second bound",
  );
});

test("durable store: a colliding operation id is retried ONCE before any fence (Go parity)",
  { skip: !linux }, () => {
    const path = directory();
    const clock = scriptClock(100);
    DurableNonceStore.initializeUnused(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    const first = DurableNonceStore.open(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    const admission = new DurableNonceAdmission({ store: first, now: clock });
    const initial = admission.reserveForVerify(seamRequest(freshKey(), 100));
    assert.equal(initial.accepted, true, "first reservation commits");
    if (initial.accepted) initial.finish();
    const collidingId = first.state().live[0]?.operationId;
    assert.ok(collidingId !== undefined && collidingId !== "", "the committed receipt exposes its operation id");
    first.close();

    // Reopen with a seam that returns the colliding id exactly once: the
    // second attempt must allocate a NEW id and commit (Go durable/admit.go
    // retries a collision once; without the fix the store fences instead).
    let calls = 0;
    const reopened = DurableNonceStore.open(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock,
      injectOperationId: () => {
        calls++;
        return calls === 1 ? (collidingId as string) : encodeBase64URL(randomBytes(16));
      } });
    const retryAdmission = new DurableNonceAdmission({ store: reopened, now: clock });
    const outcome = retryAdmission.reserveForVerify(seamRequest(freshKey(), 100));
    assert.equal(outcome.accepted, true, "a single collision is retried, not fenced");
    if (outcome.accepted) outcome.finish();
    assert.equal(calls, 2, "the colliding id is replaced by exactly one fresh id");
    assert.equal(reopened.state().live.some((row) => row.operationId === collidingId), true,
      "the original record is kept");
    assert.equal(reopened.state().live.length, 2, "the retried reservation committed beside it");
    assert.equal(reopened.isFenced(), false, "a retried collision never fences");
    reopened.close();
  });

test("durable store: two colliding operation ids still fence (retry is once, not unbounded)",
  { skip: !linux }, () => {
    const path = directory();
    const clock = scriptClock(100);
    DurableNonceStore.initializeUnused(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    const first = DurableNonceStore.open(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock });
    const admission = new DurableNonceAdmission({ store: first, now: clock });
    const initial = admission.reserveForVerify(seamRequest(freshKey(), 100));
    assert.equal(initial.accepted, true, "first reservation commits");
    if (initial.accepted) initial.finish();
    const collidingId = first.state().live[0]?.operationId as string;
    first.close();

    const reopened = DurableNonceStore.open(path, { deploymentId: DEPLOYMENT, window: WINDOW, now: clock,
      injectOperationId: () => collidingId });
    const retryAdmission = new DurableNonceAdmission({ store: reopened, now: clock });
    const outcome = retryAdmission.reserveForVerify(seamRequest(freshKey(), 100));
    assert.equal(outcome.accepted, false, "a persistent collision cannot commit");
    if (!outcome.accepted) {
      assert.equal(outcome.httpStatus, 503, "persistent collision status");
      assert.equal(outcome.code, "durability_unavailable", "persistent collision code");
    }
    assert.equal(reopened.isFenced(), true, "two collisions fence the store like Go");
    assert.throws(() => reopened.close(), { code: "durability_unavailable" },
      "a fenced store cannot close cleanly");
  });
