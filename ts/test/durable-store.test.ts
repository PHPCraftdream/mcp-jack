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
    // A clean store with an unresolved intent refuses Open (Go
    // ErrRecoveryRequired), so the intent is seeded AFTER open through the
    // test-only seam, mirroring Go seedVectorState.
    DurableNonceStore.seedDocumentForTest(path, doc(meta({ live: rows.length - 1 }),
      rows.slice(0, rows.length - 1), [], []));
    const store = DurableNonceStore.open(path, config);
    store.seedRecordsForTest(doc(store.state().meta, rows.slice(0, rows.length - 1), [pendingIntent], []));
    assert.throws(() => store.reserve(admission(id.kid, id.nonce, 100)), denies(503, "capacity_exhausted"),
      "the outstanding intent counts against the combined cap");
    assert.equal(store.state().counts.live, 4095, "no live row is evicted");
    assert.throws(() => store.close(), unavailable, "close refuses while an outstanding intent remains");

    // 64 tombstones exhaust the unknown cap; seeded after open for the same reason.
    const path3 = join(dir, "nonce-store-tomb");
    DurableNonceStore.seedDocumentForTest(path3, doc(meta({ highWater: 100 }), [], [], []));
    const store3 = DurableNonceStore.open(path3, config);
    const tombstones = sortByPair(Array.from({ length: 64 }, (_, index) => {
      const row = rowFor(`tombstone-${index}`, index);
      return { ...row, timestamp: 60, retainUntil: 90, highWater: 61 };
    }));
    store3.seedRecordsForTest(doc(store3.state().meta, [], [], tombstones));
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

/** Sealed envelope with a correct checksum over an arbitrary (possibly noncanonical) payload. */
function sealedEnvelope(payload: string): Buffer {
  return Buffer.from(JSON.stringify({ payload, checksum: bodyHash(Buffer.from(payload, "utf8")) }), "utf8");
}

/** Payload text of the canonical seed store file. */
function seededPayload(good: Buffer): string {
  return (JSON.parse(Buffer.from(good).toString("utf8")) as { payload: string }).payload;
}

test("durable store: load refuses duplicate members, whitespace and noncanonical numbers",
  { skip: !linux }, (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const row = rowFor("canonical", 0);
    DurableNonceStore.seedDocumentForTest(path, doc(meta({ live: 1 }), [row], [], []));
    const config = options(scriptClock(100));
    // Happy path: the store written by encodeDocument opens byte-identically.
    {
      const probe = DurableNonceStore.open(path, config);
      probe.close();
    }
    const good = Buffer.from(readFileSync(path));
    const payload = seededPayload(good);
    const refuse = (name: string, bytes: Uint8Array): void => {
      const variant = join(dir, name);
      writeFileSync(variant, bytes, { mode: 0o600 });
      assert.throws(() => DurableNonceStore.open(variant, config), unavailable,
        `${name} must be refused as invalid store format`);
    };

    // Duplicated member at the top (envelope) level: checksum is valid, still refused.
    const duplicateTop = Buffer.from(
      `{"payload":${JSON.stringify(payload)},"checksum":"${bodyHash(Buffer.from(payload, "utf8"))}",` +
      `"payload":${JSON.stringify(payload)}}`, "utf8");
    refuse("duplicate-top", duplicateTop);

    // Duplicated member nested inside the meta object: refused.
    const deploymentMember = `"deployment":"${DEPLOYMENT}",`;
    assert.ok(payload.includes(deploymentMember), "seed payload contains the deployment member");
    refuse("duplicate-meta", sealedEnvelope(payload.replace(deploymentMember,
      `${deploymentMember}${deploymentMember}`)));

    // Duplicated member nested inside a record object: refused.
    const kidMember = `"kid":"${row.kid}",`;
    assert.ok(payload.includes(kidMember), "seed payload contains the record kid member");
    refuse("duplicate-record", sealedEnvelope(payload.replace(kidMember, `${kidMember}${kidMember}`)));

    // Leading whitespace before the document: refused.
    refuse("leading-space", Buffer.concat([Buffer.from(" ", "utf8"), good]));

    // Trailing whitespace after the document: refused.
    refuse("trailing-space", Buffer.concat([good, Buffer.from("\n", "utf8")]));

    // Trailing bytes after the document: refused.
    refuse("trailing-bytes", Buffer.concat([good, Buffer.from("x", "utf8")]));

    // Noncanonical integer spellings with identical numeric value: refused.
    const timestampMember = `"timestamp":100,`;
    assert.ok(payload.includes(timestampMember), "seed payload contains the timestamp member");
    refuse("number-fraction", sealedEnvelope(payload.replace(timestampMember, `"timestamp":30.0,`)));
    refuse("number-exponent", sealedEnvelope(payload.replace(timestampMember, `"timestamp":3e1,`)));
    refuse("number-negative-zero", sealedEnvelope(payload.replace(timestampMember, `"timestamp":-0,`)));

    // The canonical bytes still open after all refusals.
    const canonical = join(dir, "canonical");
    writeFileSync(canonical, good, { mode: 0o600 });
    const reopened = DurableNonceStore.open(canonical, config);
    reopened.close();
  });

function recoveryRequired(error: unknown): boolean {
  return denies(503, "durability_unavailable")(error) &&
    (error as JackError).message === "durable: recovery required";
}

/** Go ErrInvalidStore surfaces as a plain invalid-store failure, not unavailable. */
function invalidStore(error: unknown): boolean {
  return !(error instanceof JackError) && (error as Error).message === "durable: invalid store";
}

test("durable store: open refuses a clean store with unresolved intents until explicit recovery",
  { skip: !linux }, (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const config = options(scriptClock(100));
    const intent = rowFor("open-intent", 0);
    // Clean (dirty=false) with one unresolved intent: Go readStoreSnapshot
    // refuses Open with ErrRecoveryRequired.
    DurableNonceStore.seedDocumentForTest(path, doc(meta(), [], [intent], []));
    assert.throws(() => DurableNonceStore.open(path, config), recoveryRequired,
      "a clean store with unresolved intents must refuse open");
    // Recovery inspection still loads the same file (only open refuses).
    const snapshot = DurableNonceStore.inspectRecovery(path, config);
    assert.equal(snapshot.dirty, false);
    assert.equal(snapshot.intents.length, 1);
    assert.equal(snapshot.intents[0]?.intentId, intent.intentId);
  });

test("durable store: open refuses a clean store at the tombstone cap until explicit recovery",
  { skip: !linux }, (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const config = options(scriptClock(100));
    const expired = sortByPair(Array.from({ length: 64 }, (_, index) => {
      const row = rowFor(`cap-tombstone-${index}`, index);
      return { ...row, timestamp: 60, retainUntil: 90, highWater: 61 };
    }));
    DurableNonceStore.seedDocumentForTest(path, doc(meta(), [], [], expired));
    assert.throws(() => DurableNonceStore.open(path, config), recoveryRequired,
      "a clean store at the tombstone cap must refuse open");
    // Below the cap a clean store still opens.
    const belowPath = join(dir, "below-cap");
    DurableNonceStore.seedDocumentForTest(belowPath, doc(meta(), [], [], expired.slice(0, 63)));
    const below = DurableNonceStore.open(belowPath, config);
    below.close();
    // Recovery inspection still loads the capped file.
    const snapshot = DurableNonceStore.inspectRecovery(path, config);
    assert.equal(snapshot.tombstones.length, 64);
  });

test("durable store: recovery inspect and reconcile refuse a deployment or window mismatch",
  { skip: !linux }, (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const intent = rowFor("mismatch-intent", 0);
    // A crashed dirty store with one unresolved intent (the recovery profile).
    DurableNonceStore.seedDocumentForTest(path, doc(meta({ dirty: true }), [], [intent], []));
    const config = options(scriptClock(100));
    const snapshot = DurableNonceStore.inspectRecovery(path, config);
    assert.equal(snapshot.intents.length, 1);
    const wrongDeployment = { ...config, deploymentId: "other-deployment" };
    const wrongWindow = { ...config, window: 31 };
    assert.throws(() => DurableNonceStore.inspectRecovery(path, wrongDeployment), invalidStore,
      "inspect must refuse a deployment mismatch");
    assert.throws(() => DurableNonceStore.inspectRecovery(path, wrongWindow), invalidStore,
      "inspect must refuse a window mismatch");
    const receipt = snapshot.intents[0] as DurableReceipt;
    assert.throws(() => DurableNonceStore.reconcileUnknown(path, wrongDeployment, snapshot.hash, receipt),
      invalidStore, "reconcile must refuse a deployment mismatch");
    assert.throws(() => DurableNonceStore.reconcileUnknown(path, wrongWindow, snapshot.hash, receipt),
      invalidStore, "reconcile must refuse a window mismatch");
    // A refused inspect/reconcile must not leave a stale owner marker: the
    // store was never mutated (Go releases the lock cleanly on failure).
    assert.equal(existsSync(path + ".owner"), false,
      "a failed inspect must not leave an owner marker");
    // The matching options still reconcile the exact row.
    DurableNonceStore.reconcileUnknown(path, config, snapshot.hash, receipt);
    const after = DurableNonceStore.inspectRecovery(path, config);
    assert.equal(after.tombstones.length, 1);
    assert.equal(after.intents.length, 0);
    assert.equal(existsSync(path + ".owner"), false);

    // The same refusals on a clean store must leave it fully openable: the
    // mismatched inspect changes nothing and holds no fence afterwards.
    const cleanPath = join(dir, "mismatch-clean");
    DurableNonceStore.seedDocumentForTest(cleanPath, doc(meta(), [], [], []));
    assert.throws(() => DurableNonceStore.inspectRecovery(cleanPath, wrongDeployment), invalidStore,
      "inspect must refuse a deployment mismatch on a clean store");
    assert.throws(() => DurableNonceStore.inspectRecovery(cleanPath, wrongWindow), invalidStore,
      "inspect must refuse a window mismatch on a clean store");
    assert.equal(existsSync(cleanPath + ".owner"), false,
      "a refused clean-store inspect must not leave an owner marker");
    const reopened = DurableNonceStore.open(cleanPath, config);
    reopened.close();
    assert.equal(existsSync(cleanPath + ".owner"), false, "a clean close removes the owner marker");
  });

test("durable store: recovery holds the exclusive owner and reads through private-file checks",
  { skip: !linux }, (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const intent = rowFor("owner-intent", 0);
    const config = options(scriptClock(100));

    // A store file that is not a private 0600 file refuses inspection
    // (the private-file checks of the open path apply to recovery too).
    DurableNonceStore.seedDocumentForTest(path, doc(meta({ dirty: true }), [], [intent], []));
    chmodSync(path, 0o644);
    assert.throws(() => DurableNonceStore.inspectRecovery(path, config), unavailable,
      "a non-private store file must refuse inspection");
    assert.throws(() => DurableNonceStore.reconcileUnknown(path, config, "x", intent), unavailable);
    chmodSync(path, 0o600);
    const snapshot = DurableNonceStore.inspectRecovery(path, config);
    assert.equal(snapshot.intents.length, 1);

    // A live owner marker fences recovery: the exclusive owner is taken even
    // for inspection (Go InspectRecovery). A clean store opens and holds the
    // marker; the unresolved intent is seeded through the test-only seam.
    const livePath = join(dir, "live-owner");
    DurableNonceStore.seedDocumentForTest(livePath, doc(meta(), [], [], []));
    const live = DurableNonceStore.open(livePath, config);
    live.seedRecordsForTest(doc(live.state().meta, [], [intent], []));
    assert.equal(existsSync(livePath + ".owner"), true, "an open store holds the owner marker");
    assert.throws(() => DurableNonceStore.inspectRecovery(livePath, config), unavailable,
      "recovery must refuse while a live owner holds the marker");
    assert.throws(() => DurableNonceStore.reconcileUnknown(livePath, config, "x", intent), unavailable,
      "reconcile must refuse while a live owner holds the marker");
    // The owner abandons the marker (simulated crash with the intent outstanding).
    simulateCrash(livePath);
    const crashed = DurableNonceStore.inspectRecovery(livePath, config);
    assert.equal(crashed.dirty, true);
    assert.equal(crashed.intents.length, 1);
    DurableNonceStore.reconcileUnknown(livePath, config, crashed.hash, crashed.intents[0] as DurableReceipt);
    const after = DurableNonceStore.inspectRecovery(livePath, config);
    assert.equal(after.tombstones.length, 1);
    assert.equal(after.intents.length, 0);
  });

test("durable store: an unexpected non-JackError inside reserve fences the owner and reports durability_unavailable",
  { skip: !linux }, (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    // Samples: init, startup, entry, intent, FINAL. The final clock call
    // throws a plain Error after the intent transaction committed.
    let calls = 0;
    const clock = (): number => {
      calls++;
      if (calls === 5) throw new Error("clock exploded");
      return 100;
    };
    const config = options(clock);
    DurableNonceStore.initializeUnused(path, config);
    const store = DurableNonceStore.open(path, config);
    const identity = synthetic("fence-clock");
    assert.throws(() => store.reserve(admission(identity.kid, identity.nonce, 100)), unavailable,
      "a plain Error from the transaction must surface as durability_unavailable");
    // Go Reserve: the panic fenced the store before reporting.
    assert.equal(store.isFenced(), true, "unexpected failure must fence the store");
    // The intent was already committed when the final sample threw: it stays.
    assert.equal(store.state().counts.intents, 1, "committed intent stays behind the fence");
    // The fenced owner refuses further admission and cannot close cleanly.
    assert.throws(() => store.reserve(admission(identity.kid, identity.nonce, 100)), unavailable,
      "a fenced store refuses admission");
    assert.throws(() => store.close(), unavailable);
  });

test("durable store: a fenced close releases the owner marker and reports recovery-required (Go/Rust parity)",
  { skip: !linux }, (context) => {
    const { dir, path } = directory();
    context.after(() => rmSync(dir, { recursive: true, force: true }));
    const config = options(scriptClock(100, 100, Number.NaN));
    DurableNonceStore.initializeUnused(path, config);
    const store = DurableNonceStore.open(path, config);
    const id = synthetic("fenced-close");
    assert.throws(() => store.reserve(admission(id.kid, id.nonce, 100)), denies(503, "clock_unsafe"));
    assert.equal(store.isFenced(), true);
    // Go Close reports ErrRecoveryRequired and releases the bbolt lock; Rust
    // reports RecoveryRequired and removes its marker (durable/store.go Close;
    // rust/src/server/durable_store.rs close).
    assert.throws(() => store.close(), (error: unknown) => unavailable(error) &&
      (error as JackError).message === "durable: recovery required");
    assert.equal(existsSync(path + ".owner"), false, "a fenced close releases the owner marker");
    store.close();
    // The persisted dirty epoch and unsafe latch keep the store fail-closed.
    assert.throws(() => DurableNonceStore.open(path, config), unavailable);
    // Recovery inspection runs at once: no manual marker removal is needed.
    const snapshot = DurableNonceStore.inspectRecovery(path, config);
    assert.equal(snapshot.dirty, true);
    assert.equal(snapshot.unsafe, true);
  });
