import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestContext } from "node:test";
import { test } from "node:test";
import { client, Code, encodeBase64URL, JackError, keyId, rotation, ServerKeyTool, TOOL_SERVER_KEY } from "../src/index.js";
import type { NativeCall } from "../src/index.js";
import { corpus, denies, WINDOW } from "./rotation-server-fixtures.js";

const linux = process.platform === "linux";
const GRACE = rotation.ROTATION_GRACE_SECONDS;
const unavailable = denies("rotation_state_unavailable");

interface Environment {
  readonly store: rotation.RotationServerStore;
  readonly provider: rotation.RotationServerProvider;
  readonly signers: readonly client.InMemorySigner[];
  readonly keys: readonly rotation.RotationServerKey[];
  readonly kids: readonly string[];
  readonly path: string;
  setNow(value: number): void;
}

function seed(index: number): client.InMemorySigner {
  return new client.InMemorySigner(createHash("sha256").update(`server provider fixture ${index}`).digest());
}

/** Store с anchor-ключом signer 0 и provider с pinned handles `ref-<i>` для перечисленных индексов. */
function environment(context: TestContext, pinned: readonly number[] = [0, 1, 2], start = 1000): Environment {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mcp-jack-server-provider-")));
  chmodSync(dir, 0o700);
  context.after(() => rmSync(dir, { recursive: true, force: true }));
  const signers = [0, 1, 2].map(seed);
  const first = signers[0];
  assert.ok(first);
  const root: rotation.RotationCheckpoint = { ordinal: 0, hash: "-", kid: keyId(first.publicKey()), publicKeyB64u: encodeBase64URL(first.publicKey()), publishedAt: 0 };
  let current = start;
  const config: rotation.RotationServerStoreOptions = { binding: corpus.binding, checkpoint: root, window: WINDOW, anchorReference: "ref-0", now: () => current };
  const path = join(dir, "ring");
  rotation.RotationServerStore.initializeUnused(path, config);
  const store = rotation.RotationServerStore.open(path, config);
  const keys = pinned.map((index) => ({ reference: `ref-${index}`, signer: signers[index] as client.InMemorySigner }));
  return { store, provider: new rotation.RotationServerProvider(store, keys), signers, keys, path,
    kids: signers.map((signer) => keyId(signer.publicKey())), setNow: (value) => { current = value; } };
}

function publicKey(env: Environment, index: number): string {
  const signer = env.signers[index];
  assert.ok(signer);
  return encodeBase64URL(signer.publicKey());
}

test("server provider: fixed-P announcements pick the greatest eligible signer and keep pending handles required", { skip: !linux }, (context) => {
  const env = environment(context);
  const selected = (): string => {
    const { snapshot } = env.store.snapshot();
    return env.provider.selectSigner(snapshot, env.store.checkSnapshotClock(snapshot)).publicKeyB64u;
  };
  assert.equal(selected(), publicKey(env, 0));
  const first = env.provider.announce("ref-1", env.kids[1] as string);
  assert.equal(first.revision, 2);
  assert.equal(first.record.ordinal, 1);
  assert.equal(first.record.publishedAt, 1000, "P is the single fresh sample");
  assert.equal(first.record.activatesAt, 1000 + GRACE);
  assert.equal(selected(), publicKey(env, 0), "the announced key is pending, not yet eligible");
  env.setNow(1000 + GRACE);
  assert.equal(selected(), publicKey(env, 1), "activation moves signing to the new key");
  env.setNow(1000 + GRACE + 10);
  const second = env.provider.announce("ref-2", env.kids[2] as string);
  assert.equal(second.record.publishedAt, 1000 + GRACE + 10);
  assert.equal(second.record.ordinal, 2);
  assert.equal(second.revision, 3);
  assert.equal(selected(), publicKey(env, 1));
  const { snapshot } = env.store.snapshot();
  assert.equal(snapshot.trust.records.length, 2);
  assert.deepEqual(snapshot.signerReferences.map((entry) => entry.reference), ["ref-0", "ref-1", "ref-2"]);
  env.setNow(1000 + 2 * GRACE + 10);
  assert.equal(selected(), publicKey(env, 2));
});

test("server provider: announce refusals never retry or change the committed ring", { skip: !linux }, (context) => {
  const env = environment(context);
  const kid = (index: number): string => env.kids[index] as string;
  assert.throws(() => env.provider.announce("ref-1", kid(2)), unavailable, "reference and kid must be one configured identity");
  assert.throws(() => env.provider.announce("ref-9", kid(1)), unavailable);
  assert.throws(() => env.provider.announce("ref-0", kid(0)), unavailable, "a key already in the ring cannot be announced");
  env.provider.announce("ref-1", kid(1));
  assert.throws(() => env.provider.announce("ref-1", kid(1)), unavailable, "duplicate announcement");
  const before = env.store.snapshot().snapshot;
  assert.throws(() => env.provider.announce("ref-1", kid(1)), unavailable);
  assert.deepEqual(env.store.snapshot().snapshot, before);
  // Reentrant announce из signer callback того же provider отклоняется, внешняя публикация завершается.
  const nestedEnv = environment(context, [0]);
  const next = nestedEnv.signers[1] as client.InMemorySigner;
  let provider: rotation.RotationServerProvider | undefined;
  let nested: unknown;
  const wrapped = {
    publicKey: () => next.publicKey(),
    sign: (message: Uint8Array) => {
      try { provider?.announce("ref-1", nestedEnv.kids[1] as string); } catch (error) { nested = error; }
      return next.sign(message);
    },
  };
  provider = new rotation.RotationServerProvider(nestedEnv.store, [nestedEnv.keys[0] as rotation.RotationServerKey, { reference: "ref-1", signer: wrapped }]);
  assert.equal(provider.announce("ref-1", nestedEnv.kids[1] as string).revision, 2);
  assert.throws(() => { throw nested; }, unavailable);
  assert.equal(nestedEnv.store.snapshot().snapshot.trust.revision, 2);
});

test("server provider: handles, readiness and retired keys", { skip: !linux }, (context) => {
  const env = environment(context);
  env.provider.announce("ref-1", env.kids[1] as string);
  // Pending handle обязателен: provider без него не готов к serving.
  assert.throws(() => new rotation.RotationServerProvider(env.store, [env.keys[0] as rotation.RotationServerKey]), unavailable);
  assert.doesNotThrow(() => new rotation.RotationServerProvider(env.store, [env.keys[0] as rotation.RotationServerKey, env.keys[1] as rotation.RotationServerKey]));
  // После cutoff retired handle необязателен, но current signer обязателен.
  env.setNow(1000 + GRACE + 1);
  assert.doesNotThrow(() => new rotation.RotationServerProvider(env.store, [env.keys[1] as rotation.RotationServerKey]));
  assert.throws(() => new rotation.RotationServerProvider(env.store, [env.keys[0] as rotation.RotationServerKey]), unavailable);
});

test("server provider: configured handles are validated and copied", { skip: !linux }, (context) => {
  const env = environment(context);
  const good = env.keys[0] as rotation.RotationServerKey;
  const signer = env.signers[0] as client.InMemorySigner;
  const bad: [string, readonly rotation.RotationServerKey[]][] = [
    ["empty inventory", []],
    ["empty reference", [{ ...good, reference: "" }]],
    ["oversized reference", [{ ...good, reference: "x".repeat(rotation.ROTATION_MAX_SIGNER_REFERENCE_BYTES + 1) }]],
    ["lone surrogate reference", [{ ...good, reference: "\ud800" }]],
    ["short public key", [{ ...good, signer: { publicKey: () => new Uint8Array(31), sign: (m: Uint8Array) => signer.sign(m) } }]],
    ["throwing public key", [{ ...good, signer: { publicKey: () => { throw new Error("private detail"); }, sign: (m: Uint8Array) => signer.sign(m) } }]],
    ["missing sign", [{ ...good, signer: { publicKey: () => signer.publicKey() } as unknown as rotation.RotationServerKey["signer"] }]],
    ["duplicate identity", [good, good]],
    ["anchor handle absent", [env.keys[1] as rotation.RotationServerKey]],
  ];
  for (const [label, keys] of bad) assert.throws(() => new rotation.RotationServerProvider(env.store, keys), unavailable, label);
  // Pinned public key не меняется вместе с callback после конструктора.
  let advertised = signer.publicKey();
  const mutable = { reference: "ref-0", signer: { publicKey: () => advertised, sign: (m: Uint8Array) => signer.sign(m) } };
  const provider = new rotation.RotationServerProvider(env.store, [mutable]);
  advertised = new Uint8Array(32);
  const { snapshot } = env.store.snapshot();
  const chosen = provider.selectSigner(snapshot, env.store.checkSnapshotClock(snapshot));
  assert.equal(chosen.publicKeyB64u, publicKey(env, 0));
  assert.equal(encodeBase64URL(chosen.publicKey()), publicKey(env, 0));
});

function call(overrides: Partial<NativeCall> = {}): NativeCall {
  return { tool: TOOL_SERVER_KEY, arguments: '{"after_ordinal":0,"after_hash":"-"}', caller: { kid: "caller", publicKey: "unused", name: "caller" },
    kid: "caller", ts: 1000, now: 1000, aud: corpus.binding.aud, state: undefined as never, target: "", ...overrides };
}

function refusal(status: number, code: string): (error: unknown) => boolean {
  return (error) => error instanceof JackError && error.httpStatus === status && error.code === code;
}

test("jack.server.key tool: one ring view, selected signer and exact refusal mapping", { skip: !linux }, (context) => {
  const env = environment(context);
  const tool = new ServerKeyTool(env.store, env.provider);
  const published = env.provider.announce("ref-1", env.kids[1] as string);
  const result = tool.call(call());
  assert.deepEqual(result.structured, { current: { kid: env.kids[0], public_key: publicKey(env, 0) }, records: [published.record.wire],
    head: { ordinal: 1, hash: published.record.hash }, complete: true });
  const caughtUp = tool.call(call({ arguments: `{"after_ordinal":1,"after_hash":"${published.record.hash}"}` }));
  assert.deepEqual(caughtUp.structured, { current: { kid: env.kids[0], public_key: publicKey(env, 0) }, records: [],
    head: { ordinal: 1, hash: published.record.hash }, complete: true });
  env.setNow(1000 + GRACE);
  const moved = tool.call(call()).structured as rotation.RotationServerKeyPage;
  assert.equal(moved.current.public_key, publicKey(env, 1), "activation changes only the signer, not the ring view");
  assert.deepEqual(moved.records, [published.record.wire]);

  const cases: [string, Partial<NativeCall>, (error: unknown) => boolean][] = [
    ["wrong tool", { tool: "jack.whoami" }, refusal(403, Code.OPERATION_DENIED)],
    ["anonymous caller", { caller: undefined }, refusal(403, Code.OPERATION_DENIED)],
    ["missing arguments", { arguments: undefined }, refusal(400, Code.INVALID_PARAMS)],
    ["unknown argument", { arguments: '{"after_ordinal":0,"after_hash":"-","x":1}' }, refusal(400, Code.INVALID_PARAMS)],
    ["wrong audience", { aud: "https://other.example.test" }, refusal(503, "rotation_state_unavailable")],
    ["wrong hash", { arguments: `{"after_ordinal":1,"after_hash":"${published.record.hash.slice(1)}A"}` }, refusal(409, "rotation_checkpoint_unavailable")],
    ["cursor beyond head", { arguments: `{"after_ordinal":2,"after_hash":"${published.record.hash}"}` }, refusal(409, "rotation_checkpoint_unavailable")],
  ];
  for (const [label, overrides, expected] of cases) assert.throws(() => tool.call(call(overrides)), expected, label);

  // Clock rollback latches unsafe: нет подписанного ответа, без fallback на старый key.
  env.setNow(1);
  assert.throws(() => tool.call(call()), refusal(503, "rotation_state_unavailable"));
  assert.throws(() => tool.call(call()), refusal(503, "rotation_state_unavailable"));
});

test("jack.server.key tool: leases are released on every path so the store can close", { skip: !linux }, (context) => {
  const env = environment(context);
  const tool = new ServerKeyTool(env.store, env.provider);
  env.provider.announce("ref-1", env.kids[1] as string);
  tool.call(call());
  assert.throws(() => tool.call(call({ arguments: "{}" })), refusal(400, Code.INVALID_PARAMS));
  assert.throws(() => tool.call(call({ aud: "other" })), refusal(503, "rotation_state_unavailable"));
  env.store.close();
  assert.throws(() => tool.call(call()), refusal(503, "rotation_state_unavailable"));
});
