import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { bodyHash, decodeBase64URLFixed } from "../src/encoding.js";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync } from "node:fs";
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

function response(key: client.Signer, requestSignature: string, timestamp: number, body = Buffer.from("{not-json"), status = 200): RotationResponse {
  const message = responseSigningString(status, requestSignature, key.kid(), timestamp, body);
  return { status, requestSignature, body,
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
  return { key, next, user, binding, checkpoint, clock, options, path, root, store, controller, requestSignature };
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

interface PageOptions {
  head?: rotation.RotationCursor;
  complete?: boolean;
  current?: client.Signer;
  signer?: client.Signer;
  timestamp?: number;
  id?: string | number;
  status?: number;
}

function signedPage(environment: ReturnType<typeof setup>, records: readonly rotation.RotationRecord[], options: PageOptions = {}): RotationResponse {
  const signing = options.signer ?? environment.key;
  const current = options.current ?? signing;
  const tail = records[records.length - 1];
  const head = options.head ?? (tail === undefined ? environment.store.snapshot().snapshot.head : { ordinal: tail.ordinal, hash: tail.hash });
  const payload = { current: { kid: current.kid(), public_key: encodeBase64URL(current.publicKey()) },
    records: records.map((record) => record.wire), head, complete: options.complete ?? true };
  const id = options.id ?? "refresh";
  const body = Buffer.from(JSON.stringify({ jsonrpc: "2.0", id,
    result: { content: [{ type: "text", text: JSON.stringify(payload) }], structuredContent: payload, isError: false } }));
  const timestamp = options.timestamp ?? environment.clock.now;
  const cursor = environment.store.snapshot().snapshot.head;
  const requestBody = Buffer.from(JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call",
    params: { name: "jack.server.key", arguments: { after_ordinal: cursor.ordinal, after_hash: cursor.hash } } }));
  const request = client.signRequest(environment.user, environment.binding.aud, "POST", "/mcp", requestBody, randomBytes(16), timestamp);
  return response(signing, parseRequestAuth([request]).sig, timestamp, body, options.status ?? 200);
}

function firstRecord(environment: ReturnType<typeof setup>, publishedAt = 1000): rotation.RotationRecord {
  return rotation.createRotationRecord(environment.binding, environment.checkpoint, environment.key, environment.next, publishedAt);
}

test("refresh controller: explicit overlapping pages ACK terminal only; duplicate is no-op and clean reopen retains state", { skip: !linux }, (context) => {
  const environment = setup(context);
  const { controller, store, clock, binding, next } = environment;
  const empty = controller.acceptRefresh(signedPage(environment, []), "refresh", store.snapshot().snapshot.head);
  assert.equal(empty.committed, false);
  assert.equal(empty.revision, 1);
  assert.deepEqual(empty.terminal, { ordinal: 0, hash: "-" });
  const first = firstRecord(environment);
  const third = signer("third");
  const previous = { ordinal: first.ordinal, hash: first.hash, kid: first.newKid, publicKeyB64u: first.publicKeyB64u, publishedAt: first.publishedAt };
  const second = rotation.createRotationRecord(binding, previous, next, third, 1000);
  const head = { ordinal: second.ordinal, hash: second.hash };
  const calls = clock.calls;
  const one = controller.acceptRefresh(signedPage(environment, [first], { head, complete: false }), "refresh", environment.checkpoint);
  assert.equal(clock.calls - calls, 4);
  assert.deepEqual(one, { head, terminal: { ordinal: 1, hash: first.hash }, complete: false, committed: true, revision: 2 });
  assert.equal(store.snapshot().snapshot.head.ordinal, 1, "advertised head does not ACK an unfetched page");
  const two = controller.acceptRefresh(signedPage(environment, [second]), "refresh", one.terminal);
  assert.deepEqual(two, { head, terminal: head, complete: true, committed: true, revision: 3 });
  const before = store.snapshot();
  const duplicateCalls = clock.calls;
  const duplicate = controller.acceptRefresh(signedPage(environment, [second]), "refresh", head);
  assert.equal(duplicate.committed, false);
  assert.equal(duplicate.revision, 3);
  assert.equal(clock.calls - duplicateCalls, 3);
  assert.deepEqual(store.snapshot(), before);
  store.close();
  const reopened = rotation.RotationTrustStore.open(environment.path, environment.options);
  context.after(() => { try { reopened.close(); } catch { /* Только test-owned cleanup. */ } });
  assert.deepEqual(reopened.snapshot().snapshot, before.snapshot);
  const restored = new RotationController(reopened);
  clock.now = first.activatesAt;
  const current = response(third, environment.requestSignature, first.activatesAt);
  assert.deepEqual(restored.verifyResponse(current), current.body);
  assert.throws(() => restored.verifyResponse(response(next, environment.requestSignature, first.activatesAt)), denied("rotation_key_interval"));
  reopened.close();
});

test("refresh controller: unknown/current/ID/status/cursor/future-proof/reuse refusals do not ACK", { skip: !linux }, (context) => {
  const environment = setup(context);
  const { controller, store, clock } = environment;
  const first = firstRecord(environment);
  const cursor = store.snapshot().snapshot.head;
  const unknown = signedPage(environment, [first], { signer: environment.next });
  let reads = 0;
  Object.defineProperty(unknown, "body", { get() { reads++; throw new Error("unknown carrier body inspected"); } });
  const calls = clock.calls;
  assert.throws(() => controller.acceptRefresh(unknown, "refresh", cursor), denied(Code.UNKNOWN_SERVER_KEY));
  assert.equal(reads, 0);
  assert.equal(clock.calls, calls);
  const refused: [RotationResponse, string | number, rotation.RotationCursor, string][] = [
    [signedPage(environment, [first], { current: environment.next }), "refresh", cursor, "rotation_result_invalid"],
    [signedPage(environment, [first]), "wrong-id", cursor, "rotation_result_invalid"],
    [signedPage(environment, [first], { status: 400 }), "refresh", cursor, "rotation_result_invalid"],
    [signedPage(environment, [first]), "refresh", { ordinal: 1, hash: first.hash }, "rotation_gap"],
    [signedPage(environment, [firstRecord(environment, 1001)]), "refresh", cursor, "rotation_record_invalid"],
  ];
  const retained = { ordinal: first.ordinal, hash: first.hash, kid: first.newKid, publicKeyB64u: first.publicKeyB64u, publishedAt: first.publishedAt };
  const reused = rotation.createRotationRecord(environment.binding, retained, environment.next, environment.key, 1000);
  refused.push([signedPage(environment, [first, reused]), "refresh", cursor, "rotation_record_invalid"]);
  for (const proofIndex of [10, 11]) {
    const lines = first.wire.split("\n");
    const encoded = lines[proofIndex];
    assert.ok(encoded);
    const proof = decodeBase64URLFixed(encoded, 64);
    proof[0] = (proof[0] as number) ^ 1;
    lines[proofIndex] = encodeBase64URL(proof);
    const wire = lines.join("\n");
    const changed = { ...first, wire, hash: bodyHash(Buffer.from(wire)) };
    refused.push([signedPage(environment, [changed]), "refresh", cursor, "rotation_record_invalid"]);
  }
  for (const [page, id, after, code] of refused) {
    assert.throws(() => controller.acceptRefresh(page, id, after), denied(code));
    assert.equal(store.snapshot().snapshot.revision, 1);
    assert.equal(store.snapshot().snapshot.records.length, 0);
  }
});

test("refresh controller: strict first bridge expiry; late final cutoff never rolls back confirmed ACK", { skip: !linux }, (context) => {
  for (const lateAck of [false, true]) {
    const environment = setup(context);
    const first = firstRecord(environment);
    const { controller, store, clock } = environment;
    clock.now = first.activatesAt - 1;
    const page = signedPage(environment, [first]);
    const cursor = store.snapshot().snapshot.head;
    const before = first.activatesAt - 1;
    const sequence = lateAck ? [before, before, before, first.activatesAt] : [before, before, first.activatesAt];
    clock.hook = () => { const value = sequence.shift(); assert.notEqual(value, undefined); return value as number; };
    assert.throws(() => controller.acceptRefresh(page, "refresh", cursor), denied(lateAck ? "rotation_key_interval" : "rotation_bridge_expired"));
    assert.equal(sequence.length, 0);
    delete clock.hook;
    const state = store.snapshot();
    assert.equal(state.snapshot.revision, lateAck ? 2 : 1);
    assert.equal(state.snapshot.head.ordinal, lateAck ? 1 : 0);
    assert.equal(state.clock.highWater, first.activatesAt);
    if (lateAck) assert.deepEqual(state.snapshot.records, [first.wire]);
  }
});

test("refresh controller: real pre/post-rename unknown CAS keeps one-attempt gate, never returns ACK or retries", { skip: !linux }, (context) => {
  const moduleURL = new URL("../src/rotation-controller.js", import.meta.url).href;
  const sdkURL = new URL("../src/index.js", import.meta.url).href;
  for (const outcome of ["before", "after"]) {
    const environment = setup(context);
    const first = firstRecord(environment);
    const page = signedPage(environment, [first]);
    environment.store.close();
    const serialized = JSON.stringify({ options: environment.options, response: { ...page, body: Buffer.from(page.body).toString("base64url") } });
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import fs from 'node:fs';
      import {syncBuiltinESMExports} from 'node:module';
      const {rotation} = await import(process.argv[1]);
      const {RotationController} = await import(process.argv[2]);
      const data = JSON.parse(process.argv[5]);
      data.options.now = () => 1000;
      const store = rotation.RotationTrustStore.open(process.argv[3], data.options);
      const controller = new RotationController(store);
      const input = {...data.response, body: Buffer.from(data.response.body, 'base64url')};
      const cursor = store.snapshot().snapshot.head;
      const rename = fs.renameSync;
      let attempts = 0;
      fs.renameSync = (...args) => {
        attempts++;
        if(process.argv[4] === 'after') rename(...args);
        throw new Error('injected lost trust CAS outcome');
      };
      syncBuiltinESMExports();
      let refused = false;
      try { controller.acceptRefresh(input, 'refresh', cursor); }
      catch(error) { if(error.code !== 'rotation_state_unknown' || error.httpStatus !== 0) throw error; refused = true; }
      if(!refused || attempts !== 1) process.exit(2);
      try { controller.acceptRefresh(input, 'refresh', cursor); process.exit(3); }
      catch(error) { if(error.code !== 'rotation_state_unavailable') throw error; }
      try { store.close(); process.exit(4); }
      catch(error) { if(error.code !== 'rotation_state_unavailable') throw error; }
      if(attempts !== 1 || !fs.existsSync(process.argv[3]+'.owner')) process.exit(5);
    `, sdkURL, moduleURL, environment.path, outcome, serialized], { timeout: 10_000, encoding: "utf8" });
    assert.equal(child.error, undefined);
    assert.equal(child.status, 0, child.stderr);
    const outer = JSON.parse(readFileSync(environment.path, "utf8")) as { payload: string };
    const bundle = JSON.parse(outer.payload) as { snapshot: string; dirty: boolean };
    const snapshot = JSON.parse(bundle.snapshot) as { trust_revision: number; head: { ordinal: number } };
    assert.equal(snapshot.trust_revision, outcome === "after" ? 2 : 1);
    assert.equal(snapshot.head.ordinal, outcome === "after" ? 1 : 0);
    assert.equal(bundle.dirty, true);
    assert.equal(existsSync(environment.path + ".owner"), true);
    assert.throws(() => rotation.RotationTrustStore.open(environment.path, environment.options),
      (error) => error instanceof rotation.RotationError && error.code === "rotation_state_unavailable");
    const retained = readdirSync(environment.root).filter((name) => name.startsWith(".trust.") && name.endsWith(".tmp"));
    assert.equal(retained.length, outcome === "before" ? 1 : 0);
  }
});
