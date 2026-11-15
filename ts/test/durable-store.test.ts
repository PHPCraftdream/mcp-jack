/**
 * Durable nonce store unit tests: lifetime owner, admission ordering,
 * restart/crash behaviour, high-water latch, bounded purge, capacity limits
 * and strict loading. Linux-gated like the rotation server-store tests;
 * every clock touch uses the injected clock.
 */
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createHash, randomBytes } from "node:crypto";
import { bodyHash, decodeBase64URLFixed, encodeBase64URL } from "../src/encoding.js";
import { DurableNonceStore } from "../src/server/durable-store.js";
import { intentIdOf, pairKeyOf } from "../src/server/durable-format.js";
import type { DurableStoreOptions } from "../src/server/durable-store.js";
import type { DurableDocument, DurableMetadata, DurableReceipt } from "../src/server/durable-format.js";
import { JackError } from "../src/errors.js";

const linux = process.platform === "linux";
const DEPLOYMENT = "durable-store-test-deployment";
const WINDOW = 30;

type Inject = (phase: "intent" | "final") => "commit" | "abort" | undefined;

function directory(): { dir: string; path: string } {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mcp-jack-durable-store-")));
  chmodSync(dir, 0o700);
  return { dir, path: join(dir, "nonce-store") };
}

/** Scripted clock: consumes values in order, then repeats the last one. */
function scriptClock(...values: number[]): () => number {
  let index = 0;
  return () => {
    const value = values[Math.min(index, values.length - 1)] as number;
    index++;
    return value;
  };
}

function options(now: () => number, inject?: Inject): DurableStoreOptions {
  return inject === undefined
    ? { deploymentId: DEPLOYMENT, window: WINDOW, now }
    : { deploymentId: DEPLOYMENT, window: WINDOW, now, injectTransactionFailure: inject };
}

function admission(kid: string, nonce: string, ts: number, validate: (now: number) => boolean = () => true) {
  return {
    kid, nonce,
    signature: encodeBase64URL(randomBytes(64)),
    signingBytes: `mcp-jack/v1 request bytes for ${kid}/${nonce}`,
    timestamp: ts, window: WINDOW, validate,
  };
}

/** Synthetic identities of the shared-vector contract. */
function synthetic(name: string): { kid: string; nonce: string } {
  return {
    kid: encodeBase64URL(createHash("sha256").update(`candidate-vector/kid/${name}`).digest()),
    nonce: encodeBase64URL(createHash("sha256").update(`candidate-vector/nonce/${name}`).digest().subarray(0, 16)),
  };
}

function meta(overrides: Partial<DurableMetadata> = {}): DurableMetadata {
  return { deployment: DEPLOYMENT, storeId: encodeBase64URL(randomBytes(16)), generation: 1, owner: 1,
    window: WINDOW, highWater: 100, live: 0, intents: 0, tombstones: 0, dirty: false, unsafe: false, ...overrides };
}

function rowFor(name: string, index: number): DurableReceipt {
  const identity = synthetic(name);
  const signatureRaw = randomBytes(64);
  const signature = encodeBase64URL(signatureRaw);
  const requestHash = bodyHash(Buffer.from(`seed-signing/${index}`, "utf8"));
  const operationId = createHash("sha256").update(`seed-op/${index}`).digest().subarray(0, 16);
  return {
    version: 1, deploymentId: DEPLOYMENT, storeGeneration: 1, ownerGeneration: 1,
    // Intent identity per spec section 1: the strict loader recomputes it.
    intentId: intentIdOf(DEPLOYMENT, decodeBase64URLFixed(identity.kid, 32),
      decodeBase64URLFixed(identity.nonce, 16), signatureRaw, decodeBase64URLFixed(requestHash, 32),
      operationId),
    operationId: encodeBase64URL(operationId),
    kid: identity.kid, nonce: identity.nonce,
    signature,
    requestHash,
    timestamp: 100, retainUntil: 130, highWater: 100,
  };
}

/** Rows must be stored in primary-key order; the loader rejects anything else. */
function sortByPair(rows: readonly DurableReceipt[]): DurableReceipt[] {
  return [...rows].sort((a, b) =>
    Buffer.compare(pairKeyOf(decodeBase64URLFixed(a.kid, 32), decodeBase64URLFixed(a.nonce, 16)),
      pairKeyOf(decodeBase64URLFixed(b.kid, 32), decodeBase64URLFixed(b.nonce, 16))));
}

function doc(m: DurableMetadata, live: readonly DurableReceipt[], intents: readonly DurableReceipt[],
  tombstones: readonly DurableReceipt[]): DurableDocument {
  return { meta: { ...m, live: live.length, intents: intents.length, tombstones: tombstones.length },
    live: [...live], intents: [...intents], tombstones: [...tombstones] };
}

function denies(status: number, code: string): (error: unknown) => boolean {
  return (error: unknown) => {
    assert.ok(error instanceof JackError, `expected JackError, got ${String(error)}`);
    assert.equal((error as JackError).httpStatus, status);
    assert.equal((error as JackError).code, code);
    return true;
  };
}

function unavailable(error: unknown): boolean {
  return denies(503, "durability_unavailable")(error);
}

/** A crashed process leaves its owner marker behind; an operator removes it. */
function simulateCrash(path: string): void {
  unlinkSync(path + ".owner");
}

test("durable store: initialize, exclusive owner, reserve, unsigned replay, clean reopen", { skip: !linux },
  (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const config = options(scriptClock(100, 100, 100, 100));
    assert.throws(() => DurableNonceStore.open(path, config), unavailable);
    DurableNonceStore.initializeUnused(path, config);
    assert.equal(existsSync(path + ".owner"), false);
    const store = DurableNonceStore.open(path, config);
    assert.throws(() => DurableNonceStore.open(path, config), unavailable, "second owner must be refused");

    const id = synthetic("basic");
    const before = store.diskWrites;
    const reservation = store.reserve(admission(id.kid, id.nonce, 100));
    assert.equal(store.clockSamples, 4, "startup sample plus exactly three admission samples");
    assert.equal(store.diskWrites - before, 2, "intent plus final transactions");
    assert.equal(reservation.receipt.timestamp, 100);
    assert.equal(reservation.receipt.retainUntil, 130);
    assert.equal(reservation.receipt.highWater, 100);
    assert.equal(reservation.receipt.deploymentId, DEPLOYMENT);
    reservation.release();

    // A replay is unsigned (no receipt) and writes nothing.
    const writesBeforeReplay = store.diskWrites;
    assert.throws(() => store.reserve(admission(id.kid, id.nonce, 100)), denies(401, "replayed_nonce"));
    assert.equal(store.diskWrites, writesBeforeReplay);
    assert.equal(store.state().counts.live, 1);

    store.close();
    assert.throws(() => store.reserve(admission(id.kid, id.nonce, 100)), unavailable);
    assert.equal(existsSync(path + ".owner"), false, "a clean close removes the owner marker");
    const reopened = DurableNonceStore.open(path, config);
    assert.throws(() => reopened.reserve(admission(id.kid, id.nonce, 100)), denies(401, "replayed_nonce"),
      "replay denied after restart at the same second");
    assert.equal(reopened.state().counts.live, 1);
    reopened.close();
  });

test("durable store: delayed crypto and delayed final refuse and clean up the intent", { skip: !linux },
  (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const config = options(scriptClock(100, 100, 100, 131));
    DurableNonceStore.initializeUnused(path, config);
    const store = DurableNonceStore.open(path, config);
    const id = synthetic("delayed-final");
    assert.throws(() => store.reserve(admission(id.kid, id.nonce, 100)), denies(401, "timestamp_out_of_window"));
    assert.equal(store.state().counts.intents, 0, "confirmed intent must be cleaned up");
    assert.equal(store.state().counts.live, 0);
    assert.equal(store.state().meta.highWater, 100);
    assert.equal(store.isFenced(), false);
    store.close();

    // Delayed crypto before the intent: nothing reserved at all.
    const path2 = join(dir, "nonce-store-2");
    const config2 = options(scriptClock(100, 100, 100, 131));
    DurableNonceStore.initializeUnused(path2, config2);
    const store2 = DurableNonceStore.open(path2, config2);
    assert.throws(() => store2.reserve(admission(id.kid, id.nonce, 100)), denies(401, "timestamp_out_of_window"));
    assert.equal(store2.state().meta.highWater, 100,
      "H stays at the startup sample; the refusal advanced no expiry decision (never 131)");
    store2.close();
  });

test("durable store: purge at H=216 then restart at 215 fails closed and the latch persists", { skip: !linux },
  (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    DurableNonceStore.seedDocumentForTest(path, doc(meta({ highWater: 216 }), [], [], []));
    const config = options(scriptClock(216, 215, 215, 215));
    const store = DurableNonceStore.open(path, config);
    const id = synthetic("rollback");
    assert.throws(() => store.reserve(admission(id.kid, id.nonce, 215)), denies(503, "clock_unsafe"));
    assert.equal(store.isFenced(), true);
    assert.equal(store.state().meta.highWater, 216, "never clamp or clear at catch-up");
    simulateCrash(path);
    // Reopen is refused: the unsafe latch is durable across restart.
    assert.throws(() => DurableNonceStore.open(path, config), unavailable);
    const snapshot = DurableNonceStore.inspectRecovery(path, config);
    assert.equal(snapshot.unsafe, true, "clock latch persists at catch-up");
    assert.equal(snapshot.highWater, 216);
  });

test("durable store: crash after intent never auto-redelivers; reconciled store keeps the dirty gate",
  { skip: !linux }, (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const config = options(scriptClock(100, 100, 100, 100), (phase) => (phase === "intent" ? "commit" : undefined));
    DurableNonceStore.initializeUnused(path, config);
    const store = DurableNonceStore.open(path, config);
    const id = synthetic("crash-intent");
    assert.throws(() => store.reserve(admission(id.kid, id.nonce, 100)), unavailable);
    assert.equal(store.isFenced(), true);
    assert.equal(store.state().counts.intents, 1, "the intent committed before the simulated crash");
    simulateCrash(path);
    // Dirty startup is always closed until explicit recovery.
    assert.throws(() => DurableNonceStore.open(path, config), unavailable);
    const snapshot = DurableNonceStore.inspectRecovery(path, config);
    assert.equal(snapshot.intents.length, 1);
    assert.equal(snapshot.dirty, true);
    // The exact intent receipt reconciles to a terminal no-redelivery tombstone.
    DurableNonceStore.reconcileUnknown(path, config, snapshot.hash, snapshot.intents[0] as DurableReceipt);
    const after = DurableNonceStore.inspectRecovery(path, config);
    assert.equal(after.intents.length, 0);
    assert.equal(after.tombstones.length, 1);
    assert.equal(after.live.length, 0);
    assert.equal(after.dirty, true, "reconciled stores keep the dirty gate");
    assert.throws(() => DurableNonceStore.open(path, config), unavailable,
      "a reconciled store still refuses reopen");
  });

test("durable store: unknown final commit fences and reconciles found and absent to tombstones", { skip: !linux },
  (context) => {
    for (const injection of ["commit", "abort"] as const) {
      const { dir, path } = directory();
      context.after(() => rmSync(dir, { recursive: true, force: true }));
      const config = options(scriptClock(100, 100, 100, 100),
        (phase) => (phase === "final" ? injection : undefined));
      DurableNonceStore.initializeUnused(path, config);
      const store = DurableNonceStore.open(path, config);
      const id = synthetic(`unknown-final-${injection}`);
      assert.throws(() => store.reserve(admission(id.kid, id.nonce, 100)), unavailable);
      assert.equal(store.isFenced(), true);
      simulateCrash(path);
      const snapshot = DurableNonceStore.inspectRecovery(path, config);
      const row = injection === "commit" ? snapshot.live[0] : snapshot.intents[0];
      assert.ok(row, "recovery must find the surviving row");
      assert.equal(snapshot.dirty, true);
      DurableNonceStore.reconcileUnknown(path, config, snapshot.hash, row as DurableReceipt);
      const after = DurableNonceStore.inspectRecovery(path, config);
      assert.equal(after.tombstones.length, 1, "both outcomes are terminal no-redelivery");
      assert.equal(after.live.length + after.intents.length, 0);
      assert.throws(() => DurableNonceStore.open(path, config), unavailable);
    }
  });

test("durable store: reconcile refuses clean stores and wrong hashes; inspect refuses an open owner",
  { skip: !linux }, (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const config = options(scriptClock(100, 100, 100, 100));
    DurableNonceStore.initializeUnused(path, config);
    const store = DurableNonceStore.open(path, config);
    const id = synthetic("reconcile-refusals");
    // Release the reservation so close() sees no outstanding serving lease.
    const reservation = store.reserve(admission(id.kid, id.nonce, 100));
    reservation.release();
    // Inspection requires the exclusive owner to be gone.
    assert.throws(() => DurableNonceStore.inspectRecovery(path, config), unavailable);
    store.close();
    const snapshot = DurableNonceStore.inspectRecovery(path, config);
    assert.equal(snapshot.dirty, false);
    assert.throws(() => DurableNonceStore.reconcileUnknown(path, config, snapshot.hash,
      snapshot.live[0] as DurableReceipt), unavailable, "a clean store is not reconcilable");
    assert.throws(() => DurableNonceStore.reconcileUnknown(path, config, "wrong-hash",
      snapshot.live[0] as DurableReceipt), unavailable, "a stale hash is not reconcilable");
  });

test("durable store: conversion at 4096 combined entries is permitted; over-cap loads reject", { skip: !linux },
  (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    // 4095 live rows: one intent fits and converts at exactly 4096 combined.
    const rows = sortByPair(Array.from({ length: 4095 }, (_, index) => rowFor(`capacity-${index}`, index)));
    DurableNonceStore.seedDocumentForTest(path, doc(meta({ live: rows.length }), rows, [], []));
    const config = options(scriptClock(100, 100, 100, 100));
    const store = DurableNonceStore.open(path, config);
    const id = synthetic("capacity-edge");
    const reservation = store.reserve(admission(id.kid, id.nonce, 100));
    assert.equal(store.state().counts.live, 4096, "conversion at 4096 combined entries is permitted");
    reservation.release();
    store.close();

    // One more live pair would exceed the cap: reject at load, never truncate.
    const over = sortByPair([...rows, rowFor("capacity-extra-a", 999999), rowFor("capacity-extra-b", 1000000)]);
    DurableNonceStore.seedDocumentForTest(path, doc(meta({ live: over.length }), over, [], []));
    assert.throws(() => DurableNonceStore.open(path, config), unavailable);
  });

test("durable store: intents and tombstones count against capacity without live eviction", { skip: !linux },
  (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const config = options(scriptClock(100, 100, 100, 100));
    const id = synthetic("capacity-counted");

    // 4095 live rows plus one outstanding intent exhausts the combined cap.
    const rows = sortByPair([...Array.from({ length: 4095 }, (_, index) => rowFor(`capacity-${index}`, index)),
      rowFor("capacity-intent", 500000)]);
    const pendingIntent = rows[rows.length - 1] as DurableReceipt;
    DurableNonceStore.seedDocumentForTest(path, doc(meta({ live: rows.length - 1, intents: 1 }),
      rows.slice(0, rows.length - 1), [pendingIntent], []));
    const store = DurableNonceStore.open(path, config);
    assert.throws(() => store.reserve(admission(id.kid, id.nonce, 100)), denies(503, "capacity_exhausted"),
      "the outstanding intent counts against the combined cap");
    assert.equal(store.state().counts.live, 4095, "no live row is evicted");
    assert.throws(() => store.close(), unavailable, "close refuses while an outstanding intent remains");

    // 64 tombstones exhaust the unknown cap.
    const path3 = join(dir, "nonce-store-tomb");
    const tombstones = sortByPair(Array.from({ length: 64 }, (_, index) => {
      const row = rowFor(`tombstone-${index}`, index);
      return { ...row, timestamp: 60, retainUntil: 90, highWater: 61 };
    }));
    DurableNonceStore.seedDocumentForTest(path3, doc(meta({ highWater: 100, tombstones: tombstones.length }),
      [], [], tombstones));
    const store3 = DurableNonceStore.open(path3, config);
    assert.throws(() => store3.reserve(admission(id.kid, id.nonce, 100)), denies(503, "capacity_exhausted"));
    assert.equal(store3.state().counts.tombstones, 64, "no tombstone is evicted");
    assert.throws(() => store3.close(), unavailable, "close refuses at the tombstone cap");
  });

test("durable store: purge removes at most 128 expired rows per transaction", { skip: !linux }, (context) => {
  const { dir, path } = directory();
  context.after(() => rmSync(dir, { recursive: true, force: true }));
  // 200 rows expired at 91 (ts=61, W=30); H=100; entry at 101 purges a bounded batch.
  const expired = sortByPair(Array.from({ length: 200 }, (_, index) => {
    const row = rowFor(`expired-${index}`, index);
    return { ...row, timestamp: 61, retainUntil: 91, highWater: 61 };
  }));
  const config = options(scriptClock(100, 101, 101, 101));
  DurableNonceStore.seedDocumentForTest(path, doc(meta({ live: expired.length }), expired, [], []));
  const store = DurableNonceStore.open(path, config);
  const id = synthetic("purge-bounded");
  const reservation = store.reserve(admission(id.kid, id.nonce, 101));
  assert.equal(store.state().counts.live, 200 - 128 + 1, "exactly 128 expired rows removed, then the new row");
  assert.equal(store.state().meta.highWater, 101);
  reservation.release();
  // A second admission purges the remaining expired rows.
  const second = synthetic("purge-bounded-2");
  const secondReservation = store.reserve(admission(second.kid, second.nonce, 101));
  assert.equal(store.state().counts.live, 2, "only the two fresh rows remain");
  secondReservation.release();
  store.close();
});

test("durable store: expiry equality stays live; only retainUntil+1 after an H advance expires", { skip: !linux },
  (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const row = rowFor("expiry", 0);
    const config = options(scriptClock(129, 130, 130, 130));
    DurableNonceStore.seedDocumentForTest(path, doc(meta({ highWater: 129, live: 1 }), [row], [], []));
    const store = DurableNonceStore.open(path, config);
    assert.throws(() => store.reserve(admission(row.kid, row.nonce, 100)), denies(401, "replayed_nonce"),
      "retainUntil equality is live; the replay must not extend retention");
    assert.equal(store.state().meta.highWater, 129, "no expiry decision, no H advance");
    store.close();

    const config2 = options(scriptClock(129, 131, 131, 131));
    DurableNonceStore.seedDocumentForTest(path, doc(meta({ highWater: 129, live: 1 }), [row], [], []));
    const store2 = DurableNonceStore.open(path, config2);
    const fresh = synthetic("expiry-plus-one");
    const reservation = store2.reserve(admission(fresh.kid, fresh.nonce, 131));
    assert.equal(store2.state().counts.live, 1, "the expired row was purged and the pair is reusable");
    assert.equal(store2.state().meta.highWater, 131);
    reservation.release();
    store2.close();
  });

test("durable store: snapshot change, window mismatch and out-of-domain timestamps refuse", { skip: !linux },
  (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const config = options(scriptClock(100, 100, 100, 100));
    DurableNonceStore.initializeUnused(path, config);
    const store = DurableNonceStore.open(path, config);
    const id = synthetic("refusals");
    // Window mismatch is detected before any clock callback.
    const wrongWindow = { ...admission(id.kid, id.nonce, 100), window: 15 };
    const writesBefore = store.diskWrites;
    assert.throws(() => store.reserve(wrongWindow), denies(503, "state_changed"));
    assert.equal(store.diskWrites, writesBefore);
    // Snapshot change at the first authoritative sample.
    assert.throws(() => store.reserve(admission(id.kid, id.nonce, 100, () => false)),
      denies(503, "state_changed"));
    // Out-of-domain timestamp.
    assert.throws(() => store.reserve(admission(id.kid, id.nonce, 999999999999)),
      denies(401, "timestamp_out_of_window"));
    assert.equal(store.state().counts.live + store.state().counts.intents, 0, "no reservation was made");
    store.close();
  });

test("durable store: invalid clock samples fail closed and fence durably", { skip: !linux }, (context) => {
  const { dir, path } = directory();
  context.after(() => rmSync(dir, { recursive: true, force: true }));
  const config = options(scriptClock(100, 100, Number.NaN));
  DurableNonceStore.initializeUnused(path, config);
  const store = DurableNonceStore.open(path, config);
  const id = synthetic("bad-clock");
  // init=100, startup=100: open succeeds; the reserve entry sample is invalid.
  assert.throws(() => store.reserve(admission(id.kid, id.nonce, 100)), denies(503, "clock_unsafe"));
  assert.equal(store.isFenced(), true);
  simulateCrash(path);
  const snapshot = DurableNonceStore.inspectRecovery(path, config);
  assert.equal(snapshot.unsafe, true, "the unsafe latch is durable");
  assert.throws(() => DurableNonceStore.open(path, config), unavailable);
});

test("durable store: strict loading rejects tampered and noncanonical documents", { skip: !linux }, (context) => {
  const { dir, path } = directory();
  context.after(() => rmSync(dir, { recursive: true, force: true }));
  const row = rowFor("strict", 0);
  DurableNonceStore.seedDocumentForTest(path, doc(meta({ live: 1 }), [row], [], []));
  const config = options(scriptClock(100));
  // The un-tampered seed must open cleanly: refusals below come from tampering.
  {
    const probe = DurableNonceStore.open(path, config);
    probe.close();
  }
  const good = Buffer.from(readFileSync(path));

  // One flipped payload byte breaks the seal: load refuses, no repair.
  const tampered = Buffer.from(good);
  const flipAt = tampered.length - 70;
  tampered[flipAt] = (tampered[flipAt] as number) ^ 0xff;
  const tamperedPath = join(dir, "tampered");
  writeFileSync(tamperedPath, tampered, { mode: 0o600 });
  assert.throws(() => DurableNonceStore.open(tamperedPath, config), unavailable);

  // Trailing bytes are foreign: load refuses.
  const trailing = Buffer.concat([good, Buffer.from(" junk", "utf8")]);
  const trailingPath = join(dir, "trailing");
  writeFileSync(trailingPath, trailing, { mode: 0o600 });
  assert.throws(() => DurableNonceStore.open(trailingPath, config), unavailable);

  // The same pair twice in one document is noncanonical: load refuses.
  const duplicatePath = join(dir, "duplicate");
  DurableNonceStore.seedDocumentForTest(duplicatePath, doc(meta({ live: 2 }), [row, row], [], []));
  assert.throws(() => DurableNonceStore.open(duplicatePath, config), unavailable);
});
