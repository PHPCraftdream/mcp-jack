import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { rotation } from "../src/index.js";
import { corpus, denies, overlapping, root, WINDOW } from "./rotation-server-fixtures.js";

const { RotationServerStore, RotationTrustStore } = rotation;
type Store = rotation.RotationServerStore;
type Snapshot = rotation.RotationServerSnapshot;

const linux = process.platform === "linux";
const ANCHOR_REFERENCE = "opaque-provider/anchor";
const unavailable = denies("rotation_state_unavailable");
const changed = denies("rotation_state_changed");

function options(now: () => number, anchorReference = ANCHOR_REFERENCE): rotation.RotationServerStoreOptions {
  return { binding: corpus.binding, checkpoint: root, window: WINDOW, anchorReference, now };
}

function directory(): string {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mcp-jack-server-store-")));
  chmodSync(dir, 0o700);
  return dir;
}

function disk(path: string): { owner: number; dirty: boolean; clock: string; snapshot: string; domain: string } {
  const outer = JSON.parse(readFileSync(path, "utf8")) as { payload: string };
  return JSON.parse(outer.payload) as { owner: number; dirty: boolean; clock: string; snapshot: string; domain: string };
}

/** Следующая fixed-P публикация: P равно текущему clock.highWater, record — независимо подписанный fixture. */
function extension(previous: Snapshot, record: rotation.RotationRecord, clock: rotation.RotationClockTuple): Snapshot {
  const trust = previous.trust;
  const keys = trust.keys.map((key, index) => index === trust.keys.length - 1 ? { ...key, knownCutoff: record.activatesAt } : key);
  keys.push({ ordinal: record.ordinal, kid: record.newKid, publicKeyB64u: record.publicKeyB64u, notBefore: record.activatesAt, knownCutoff: null });
  return { formatVersion: 1, signerReferences: [...previous.signerReferences, { kid: record.newKid, reference: `opaque-provider/${record.newKid}` }],
    trust: { ...trust, head: { ordinal: record.ordinal, hash: record.hash }, records: [...trust.records, record.wire], keys,
      revision: trust.revision + 1, clock } };
}

test("server store: dirty-before-clock, exclusive owner, two fixed-P publications and clean reopen", { skip: !linux }, (context) => {
  const dir = directory();
  context.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "ring");
  const [first, second] = overlapping();
  assert.ok(first && second);
  let now = first.publishedAt;
  let samples = 0;
  const config = options(() => {
    samples++;
    assert.equal(existsSync(`${path}.owner`), true, "lifetime marker must precede every clock sample");
    assert.equal(disk(path).dirty, true);
    return now;
  });
  assert.throws(() => RotationServerStore.open(path, config), unavailable);
  assert.equal(samples, 0);
  RotationServerStore.initializeUnused(path, config);
  assert.equal(samples, 1);
  assert.equal(disk(path).dirty, false);
  assert.equal(disk(path).domain, "mcp-jack/server-ring/private-file/v1");
  assert.equal(existsSync(`${path}.owner`), false);
  const initial = readFileSync(path);
  assert.throws(() => RotationServerStore.initializeUnused(path, config), unavailable);
  assert.deepEqual(readFileSync(path), initial);
  const store = RotationServerStore.open(path, config);
  assert.equal(disk(path).owner, 2);
  assert.throws(() => RotationServerStore.open(path, config), unavailable);

  const anchored = store.snapshot();
  assert.equal(anchored.snapshot.trust.revision, 1);
  assert.deepEqual(anchored.snapshot.signerReferences, [{ kid: root.kid, reference: ANCHOR_REFERENCE }]);
  const guardBefore = disk(path).clock;
  const clock = store.advanceAndCheck();
  assert.equal(clock.highWater, first.publishedAt);
  const published = extension(anchored.snapshot, first, clock);
  store.compareAndSwap(anchored.snapshot, published, clock);
  assert.equal(disk(path).clock, guardBefore, "publication must not rewrite the logical ClockGuard");
  assert.throws(() => store.compareAndSwap(anchored.snapshot, published, clock), changed);
  assert.throws(() => store.checkSnapshotClock(anchored.snapshot), changed);

  now = second.publishedAt;
  const current = store.snapshot();
  assert.equal(current.snapshot.trust.records.length, 1);
  const advanced = store.checkSnapshotClock(current.snapshot);
  assert.equal(advanced.highWater, second.publishedAt);
  store.compareAndSwap(current.snapshot, extension(current.snapshot, second, advanced), advanced);
  const committed = store.snapshot().snapshot;
  assert.equal(committed.trust.records.length, 2);
  assert.equal(committed.signerReferences.length, 3);

  store.close();
  store.close();
  assert.equal(disk(path).dirty, false);
  assert.equal(existsSync(`${path}.owner`), false);
  assert.throws(() => store.advanceAndCheck(), denies("rotation_clock_unavailable"));
  const reopened = RotationServerStore.open(path, config);
  assert.deepEqual(reopened.snapshot().snapshot, committed);
  assert.equal(disk(path).owner, 3);
  reopened.close();
});

test("server store: publication refusals leave the committed ring and guard untouched", { skip: !linux }, (context) => {
  const dir = directory();
  context.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "ring");
  const [first, second] = overlapping();
  assert.ok(first && second);
  const config = options(() => first.publishedAt);
  RotationServerStore.initializeUnused(path, config);
  const store = RotationServerStore.open(path, config);
  const { snapshot } = store.snapshot();
  const clock = store.advanceAndCheck();
  const good = extension(snapshot, first, clock);
  const before = readFileSync(path);
  const replaced: Snapshot = { ...good, signerReferences: [{ kid: root.kid, reference: "replacement" }, ...good.signerReferences.slice(1)] };
  const cases: [string, Snapshot, (error: unknown) => boolean][] = [
    ["batched two authorizations", extension(good, second, clock), unavailable],
    ["replaced reference", replaced, unavailable],
    ["fenced target", { ...good, trust: { ...good.trust, fenced: true } }, unavailable],
    ["moved P", { ...good, trust: { ...good.trust, clock: { ...clock, highWater: clock.highWater + 1 } } }, changed],
    ["clock tuple of another revision", { ...good, trust: { ...good.trust, clock: { ...clock, revision: clock.revision + 1 } } }, changed],
  ];
  for (const [label, desired, expected] of cases) {
    assert.throws(() => store.compareAndSwap(snapshot, desired, clock), expected, label);
    assert.deepEqual(readFileSync(path), before, label);
  }
  assert.throws(() => store.compareAndSwap(snapshot, good, { ...clock, revision: clock.revision + 1 }), changed);
  assert.throws(() => store.compareAndSwap(good, good, clock), unavailable);
  assert.deepEqual(readFileSync(path), before);
  store.compareAndSwap(snapshot, good, clock);
  store.close();
});

test("server store: rollback or invalid time latches unsafe without lowering H and blocks clean close", { skip: !linux }, (context) => {
  const dir = directory();
  context.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const invalid of [99, -1, NaN, Infinity, 1.5]) {
    const path = join(dir, `ring-${String(invalid)}`);
    let now = 100;
    let samples = 0;
    const config = options(() => { samples++; return now; });
    RotationServerStore.initializeUnused(path, config);
    const store = RotationServerStore.open(path, config);
    now = invalid;
    assert.throws(() => store.advanceAndCheck(), denies("rotation_clock_unsafe"));
    const guard = JSON.parse(disk(path).clock) as { high_water: number; unsafe: boolean };
    assert.equal(guard.high_water, 100);
    assert.equal(guard.unsafe, true);
    const latched = readFileSync(path);
    const calls = samples;
    now = 200;
    assert.throws(() => store.advanceAndCheck(), denies("rotation_clock_unsafe"));
    assert.equal(samples, calls, "latched guard must not sample again");
    assert.deepEqual(readFileSync(path), latched);
    assert.throws(() => store.close(), unavailable);
    assert.equal(existsSync(`${path}.owner`), true);
    assert.throws(() => RotationServerStore.open(path, config), unavailable);
  }
});

test("server store: throwing, reentrant or fencing clock callbacks fence without cleanup", { skip: !linux }, (context) => {
  const dir = directory();
  context.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const mode of ["throw", "reentrant", "fence"]) {
    const path = join(dir, mode);
    let store: Store | undefined;
    let active = false;
    const config = options(() => {
      if (active) {
        if (mode === "throw") throw new Error("private callback detail");
        if (mode === "fence") store?.fence();
        else assert.throws(() => store?.rawClock(), denies("rotation_clock_unavailable"));
        return 101;
      }
      return 100;
    });
    RotationServerStore.initializeUnused(path, config);
    store = RotationServerStore.open(path, config);
    const before = readFileSync(path);
    active = true;
    assert.throws(() => store?.advanceAndCheck(), denies("rotation_clock_unavailable"));
    assert.deepEqual(readFileSync(path), before);
    assert.throws(() => store?.close(), unavailable);
    assert.equal(existsSync(`${path}.owner`), true);
    assert.throws(() => RotationServerStore.open(path, config), unavailable);
  }
});

test("server store: serving leases hold the dirty epoch and drain before a clean close", { skip: !linux }, (context) => {
  const dir = directory();
  context.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "ring");
  const config = options(() => 100);
  RotationServerStore.initializeUnused(path, config);
  const store = RotationServerStore.open(path, config);
  const one = store.acquireServingLease();
  const two = store.acquireServingLease();
  assert.throws(() => store.close(), unavailable);
  assert.equal(disk(path).dirty, true, "a lease must keep the dirty serving epoch");
  assert.throws(() => store.snapshot(), unavailable, "closing refuses new final gates");
  assert.throws(() => store.acquireServingLease(), unavailable);
  one();
  one();
  assert.throws(() => store.close(), unavailable, "release is idempotent and must not release the second lease");
  two();
  store.close();
  assert.equal(disk(path).dirty, false);
  assert.throws(() => store.acquireServingLease(), unavailable);
  const reopened = RotationServerStore.open(path, config);
  reopened.fence();
  assert.throws(() => reopened.acquireServingLease(), unavailable);
  assert.equal(existsSync(`${path}.owner`), true);
});

test("server store: client and server files, anchors and profiles are never interchangeable", { skip: !linux }, (context) => {
  const dir = directory();
  context.after(() => rmSync(dir, { recursive: true, force: true }));
  const config = options(() => 100);
  const serverPath = join(dir, "server");
  const clientPath = join(dir, "client");
  RotationServerStore.initializeUnused(serverPath, config);
  RotationTrustStore.initializeUnused(clientPath, { binding: corpus.binding, checkpoint: root, window: WINDOW, now: () => 100 });
  const serverBytes = readFileSync(serverPath);
  const clientBytes = readFileSync(clientPath);
  assert.throws(() => RotationTrustStore.open(serverPath, { binding: corpus.binding, checkpoint: root, window: WINDOW, now: () => 100 }));
  assert.throws(() => RotationServerStore.open(clientPath, config));
  assert.throws(() => RotationServerStore.open(serverPath, options(() => 100, "opaque-provider/other")));
  assert.throws(() => RotationServerStore.open(serverPath, { ...config, window: WINDOW + 1 }));
  for (const bad of [{ ...config, anchorReference: "" }, { ...config, anchorReference: "x".repeat(rotation.ROTATION_MAX_SIGNER_REFERENCE_BYTES + 1) }]) {
    assert.throws(() => RotationServerStore.initializeUnused(join(dir, "bad"), bad), unavailable);
  }
  assert.deepEqual(readFileSync(serverPath), serverBytes);
  assert.deepEqual(readFileSync(clientPath), clientBytes);
  assert.equal(existsSync(`${serverPath}.owner`), false);
  assert.equal(existsSync(`${clientPath}.owner`), false);
  assert.equal(existsSync(join(dir, "bad")), false);
  RotationServerStore.open(serverPath, config).close();
});
