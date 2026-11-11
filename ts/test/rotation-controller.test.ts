import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { TestContext } from "node:test";
import { client, Code, encodeBase64URL, formatResponseAuth, JackError, parseRequestAuth, responseSigningString, rotation } from "../src/index.js";
import { RotationController } from "../src/rotation-controller.js";
import type { RotationResponse } from "../src/rotation-controller.js";

const linux = process.platform === "linux";
const denied = (code: string) => (error: unknown): boolean => error instanceof JackError && error.httpStatus === 0 && error.code === code;

function signer(label: string): client.InMemorySigner {
  return new client.InMemorySigner(createHash("sha256").update(`mcp-jack controller fixture ${label}`).digest());
}

function response(key: client.Signer, requestSignature: string, timestamp: number, body = Buffer.from("{not-json")): RotationResponse {
  const message = responseSigningString(200, requestSignature, key.kid(), timestamp, body);
  return { status: 200, requestSignature, body,
    headers: [formatResponseAuth({ kid: key.kid(), ts: timestamp, sig: encodeBase64URL(key.sign(Buffer.from(message))) })] };
}

function setup(context: TestContext, endpoint = "https://controller.example.test/mcp") {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mcp-jack-controller-")));
  chmodSync(root, 0o700);
  const key = signer("anchor");
  const next = signer("next");
  const user = signer("user");
  const binding = { endpoint, aud: "controller-audience" };
  const checkpoint = { ordinal: 0, hash: "-", kid: key.kid(), publicKeyB64u: encodeBase64URL(key.publicKey()), publishedAt: 0 };
  const clock: { now: number; calls: number; hook?: () => number } = { now: 1000, calls: 0 };
  const options = { binding, checkpoint, window: 30, now: () => { clock.calls++; return clock.hook?.() ?? clock.now; } };
  const path = join(root, "trust");
  rotation.RotationTrustStore.initializeUnused(path, options);
  const store = rotation.RotationTrustStore.open(path, options);
  context.after(() => { try { store.close(); } catch { /* Только test-owned cleanup. */ } rmSync(root, { recursive: true, force: true }); });
  const controller = new RotationController(store);
  const request = client.signRequest(user, binding.aud, "POST", "/mcp", new Uint8Array(), new Uint8Array(16), 1000);
  const requestSignature = parseRequestAuth([request]).sig;
  return { key, next, user, binding, checkpoint, clock, options, store, controller, requestSignature };
}

function installNext(environment: ReturnType<typeof setup>): void {
  const { store, key, next, binding, checkpoint } = environment;
  const current = store.snapshot();
  const record = rotation.createRotationRecord(binding, checkpoint, key, next, 1000);
  const anchor = current.snapshot.keys[0];
  assert.ok(anchor);
  const desired: rotation.RotationTrustSnapshot = { ...current.snapshot, head: { ordinal: 1, hash: record.hash },
    records: [record.wire], keys: [{ ...anchor, knownCutoff: record.activatesAt },
      { ordinal: 1, kid: record.newKid, publicKeyB64u: record.publicKeyB64u, notBefore: record.activatesAt, knownCutoff: null }],
    revision: current.snapshot.revision + 1, clock: current.clock };
  store.compareAndSwap(current.snapshot, desired, current.clock);
}

test("controller: exact owned signed body without parsing, with inclusive freshness and no trust mutation", { skip: !linux }, (context) => {
  const environment = setup(context);
  const { controller, key, requestSignature, store, clock } = environment;
  const input = response(key, requestSignature, 1000);
  const before = store.snapshot().snapshot;
  const calls = clock.calls;
  const verified = controller.verifyResponse(input);
  assert.deepEqual(verified, input.body);
  assert.equal(clock.calls - calls, 3, "one preliminary and two authoritative samples");
  assert.deepEqual(store.snapshot().snapshot, before);
  verified.fill(0);
  assert.notDeepEqual(verified, input.body);
  const sequence = [1000, 1000, 1030];
  clock.hook = () => { const value = sequence.shift(); assert.notEqual(value, undefined); return value as number; };
  assert.deepEqual(controller.verifyResponse(input), input.body);
  assert.equal(sequence.length, 0);
  assert.equal(store.snapshot().clock.highWater, 1030);
});

test("controller: unknown key precedes body/clock; bad signature never advances durable H", { skip: !linux }, (context) => {
  const { controller, next, key, requestSignature, store, clock } = setup(context);
  const unknown = response(next, requestSignature, 0);
  let bodyReads = 0;
  Object.defineProperty(unknown, "body", { get() { bodyReads++; throw new Error("must not inspect unknown carrier body"); } });
  const calls = clock.calls;
  assert.throws(() => controller.verifyResponse(unknown), denied(Code.UNKNOWN_SERVER_KEY));
  assert.equal(clock.calls, calls);
  assert.equal(bodyReads, 0);
  const valid = response(key, requestSignature, 1000);
  clock.now = 1010;
  const tampered = { ...valid, body: Buffer.from("changed bytes") };
  assert.throws(() => controller.verifyResponse(tampered), denied(Code.BAD_SIGNATURE));
  assert.equal(clock.calls, calls + 1);
  assert.equal(store.snapshot().clock.highWater, 1000);
  assert.throws(() => controller.verifyResponse({ ...valid, requestSignature: "another-request" }), denied(Code.BAD_SIGNATURE));
  assert.throws(() => controller.verifyResponse({ ...valid, status: 201 }), denied(Code.BAD_SIGNATURE));
  assert.equal(store.snapshot().clock.highWater, 1000);
  const oversized = { ...valid, body: Buffer.alloc(1024 * 1024 + 1) };
  const beforeSize = clock.calls;
  assert.throws(() => controller.verifyResponse(oversized), denied("rotation_result_invalid"));
  assert.equal(clock.calls, beforeSize);
});

test("controller: final freshness/rollback refuse without undoing committed clock", { skip: !linux }, (context) => {
  for (const final of [1031, 999]) {
    const { controller, key, requestSignature, store, clock } = setup(context);
    const sequence = [1000, 1000, final];
    clock.hook = () => { const value = sequence.shift(); assert.notEqual(value, undefined); return value as number; };
    assert.throws(() => controller.verifyResponse(response(key, requestSignature, 1000)),
      denied(final === 999 ? "rotation_clock_unsafe" : Code.TIMESTAMP_OUT_OF_WINDOW));
    assert.equal(sequence.length, 0);
    if (final === 1031) {
      assert.equal(store.snapshot().clock.highWater, 1031);
      assert.equal(store.snapshot().snapshot.revision, 1);
    } else {
      clock.hook = () => 2000;
      assert.throws(() => store.advanceAndCheck(), (error) => error instanceof rotation.RotationError && error.code === "rotation_clock_unsafe");
      assert.throws(() => store.close(), (error) => error instanceof rotation.RotationError);
    }
  }
});

test("controller: exact known cutoff is final authority, and static pin does not adopt NEXT", { skip: !linux }, (context) => {
  const environment = setup(context);
  installNext(environment);
  const { controller, key, next, requestSignature, clock, store } = environment;
  const activation = 1000 + rotation.ROTATION_GRACE_SECONDS;
  const old = response(key, requestSignature, activation - 1);
  const sequence = [activation - 1, activation - 1, activation];
  clock.hook = () => { const value = sequence.shift(); assert.notEqual(value, undefined); return value as number; };
  assert.throws(() => controller.verifyResponse(old), denied("rotation_key_interval"));
  assert.equal(sequence.length, 0);
  clock.hook = () => activation;
  const current = response(next, requestSignature, activation);
  assert.deepEqual(controller.verifyResponse(current), current.body);
  assert.equal(store.snapshot().snapshot.revision, 2);
  assert.throws(() => client.verifyResponse(key.publicKey(), current.status, current.headers, current.requestSignature, current.body, activation, 30),
    denied(Code.UNKNOWN_SERVER_KEY));
  const lower = response(next, requestSignature, activation - 1);
  assert.throws(() => controller.verifyResponse(lower), denied("rotation_key_interval"));
});

test("controller: state change before authority is rejected once; input buffers are owned before callbacks", { skip: !linux }, (context) => {
  const environment = setup(context);
  const { controller, key, requestSignature, clock, store } = environment;
  const racing = response(key, requestSignature, 1000);
  const original = racing.body;
  let reads = 0;
  Object.defineProperty(racing, "body", { get() { reads++; installNext(environment); return original; } });
  assert.throws(() => controller.verifyResponse(racing), denied("rotation_state_changed"));
  assert.equal(reads, 1);
  assert.equal(store.snapshot().snapshot.revision, 2, "competing exact ACK not rolled back");
  const owned = response(key, requestSignature, 1000);
  const expected = Buffer.from(owned.body);
  clock.hook = () => { owned.body.fill(0); (owned.headers as string[])[0] = "changed header"; return 1000; };
  assert.deepEqual(controller.verifyResponse(owned), expected);
  delete clock.hook;
  store.close();
  assert.throws(() => controller.verifyResponse(response(key, requestSignature, 1000)), denied("rotation_state_unavailable"));
});

test("controller: real loopback HTTP binds actual request signature to exact response bytes", { skip: !linux }, async (context) => {
  const key = signer("anchor");
  const body = Buffer.from("HTTP public response, not a native key page");
  let requests = 0;
  const server = createServer((request, outgoing) => {
    requests++;
    const value = request.headers["jack-auth"];
    const signature = parseRequestAuth(value === undefined ? [] : typeof value === "string" ? [value] : value).sig;
    const signed = response(key, signature, 1000, body);
    outgoing.writeHead(signed.status, { "jack-auth": signed.headers[0] as string, "content-length": body.length });
    outgoing.end(body);
  });
  context.after(async () => { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const endpoint = `http://127.0.0.1:${address.port}/mcp`;
  const { controller, user, binding, requestSignature } = setup(context, endpoint);
  const request = client.signRequest(user, binding.aud, "POST", "/mcp", new Uint8Array(), new Uint8Array(16), 1000);
  const received = await fetch(endpoint, { method: "POST", headers: { "Jack-Auth": request }, signal: AbortSignal.timeout(10_000) });
  const auth = received.headers.get("jack-auth");
  assert.ok(auth);
  const verified = controller.verifyResponse({ status: received.status, headers: [auth], requestSignature,
    body: new Uint8Array(await received.arrayBuffer()) });
  assert.deepEqual(verified, body);
  assert.equal(requests, 1, "no hidden refresh/fetch/retry");
});

test("controller: foreign callback/input errors are sanitized and clock failure fences", { skip: !linux }, (context) => {
  const { controller, key, requestSignature, clock, store } = setup(context);
  const input = response(key, requestSignature, 1000);
  const throwing = response(key, requestSignature, 1000);
  Object.defineProperty(throwing, "body", { get() { throw new Error("private input detail"); } });
  const calls = clock.calls;
  assert.throws(() => controller.verifyResponse(throwing), (error) => denied("rotation_state_unknown")(error) && !String(error).includes("private input detail"));
  assert.equal(clock.calls, calls);
  assert.deepEqual(controller.verifyResponse(input), input.body);
  clock.hook = () => { throw new Error("private clock detail"); };
  assert.throws(() => controller.verifyResponse(input), (error) => denied("rotation_clock_unavailable")(error) && !String(error).includes("private clock detail"));
  delete clock.hook;
  assert.throws(() => store.close(), (error) => error instanceof rotation.RotationError);
  assert.throws(() => controller.verifyResponse(input), denied("rotation_state_unavailable"));
});
