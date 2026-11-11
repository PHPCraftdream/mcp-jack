import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { rotation } from "../src/index.js";
import { fixture } from "./fixtures.js";

const RotationTrustStore = rotation.RotationTrustStore;
type Store = rotation.RotationTrustStore;

interface Corpus {
  binding: rotation.RotationBinding;
  keys: Record<string, { kid: string; public_key: string }>;
  valid_chains: Record<string, string[]>;
}
const corpus = fixture("candidate/rotation-vectors.json") as unknown as Corpus;
const anchor = corpus.keys["anchor"];
assert.ok(anchor);
const checkpoint: rotation.RotationCheckpoint = { ordinal: 0, hash: "-", kid: anchor.kid, publicKeyB64u: anchor.public_key, publishedAt: 0 };
const linux = process.platform === "linux";
const moduleURL = new URL("../src/rotation-store.js", import.meta.url).href;
const code = (expected: string) => (error: unknown): boolean => error instanceof rotation.RotationError && error.code === expected;
const options = (now: () => number) => ({ binding: corpus.binding, checkpoint, window: 30, now });

function directory(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mcp-jack-trust-store-")));
  chmodSync(root, 0o700);
  return root;
}

function disk(path: string): { owner: number; dirty: boolean; clock: string; snapshot: string } {
  const outer = JSON.parse(readFileSync(path, "utf8")) as { payload: string };
  return JSON.parse(outer.payload) as { owner: number; dirty: boolean; clock: string; snapshot: string };
}

function extension(previous: rotation.RotationTrustSnapshot, clock: rotation.RotationClockTuple, count?: number): rotation.RotationTrustSnapshot {
  const chain = corpus.valid_chains["overlapping"];
  assert.ok(chain);
  const wires = count === undefined ? chain : chain.slice(0, count);
  const records = rotation.verifyRotationChain(wires.map((wire) => Buffer.from(wire)), corpus.binding, checkpoint);
  const keys: rotation.RotationTrustKey[] = [{ ordinal: 0, kid: checkpoint.kid, publicKeyB64u: checkpoint.publicKeyB64u, notBefore: 0, knownCutoff: null }];
  for (const record of records) {
    const tail = keys.pop();
    assert.ok(tail);
    keys.push({ ...tail, knownCutoff: record.activatesAt }, { ordinal: record.ordinal, kid: record.newKid,
      publicKeyB64u: record.publicKeyB64u, notBefore: record.activatesAt, knownCutoff: null });
  }
  const head = records[records.length - 1];
  assert.ok(head);
  return { ...previous, head: { ordinal: head.ordinal, hash: head.hash }, records: [...wires], keys, revision: previous.revision + 1, clock };
}

test("trust store: dirty-before-clock, exclusive owner, exact state/clock CAS and clean reopen", { skip: !linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "state");
  let now = 2_000_000_000;
  let samples = 0;
  const config = options(() => {
    samples++;
    assert.equal(existsSync(path + ".owner"), true);
    assert.equal(disk(path).dirty, true);
    return now;
  });
  assert.throws(() => RotationTrustStore.open(path, config), code("rotation_state_unavailable"));
  assert.equal(samples, 0);
  RotationTrustStore.initializeUnused(path, config);
  assert.equal(samples, 1);
  assert.equal(disk(path).dirty, false);
  assert.equal(existsSync(path + ".owner"), false);
  const initial = readFileSync(path);
  assert.throws(() => RotationTrustStore.initializeUnused(path, config), code("rotation_state_unavailable"));
  assert.deepEqual(readFileSync(path), initial);
  assert.equal(samples, 1);
  for (const wrong of [{ ...config, window: 31 }, { ...config, binding: { ...corpus.binding, aud: "other" } }]) {
    assert.throws(() => RotationTrustStore.open(path, wrong));
    assert.deepEqual(readFileSync(path), initial);
    assert.equal(existsSync(path + ".owner"), false);
    assert.equal(samples, 1);
  }
  const store = RotationTrustStore.open(path, config);
  assert.equal(disk(path).owner, 2);
  assert.equal(samples, 2);
  assert.throws(() => RotationTrustStore.open(path, config), code("rotation_state_unavailable"));
  assert.equal(samples, 2);
  const first = store.snapshot();
  const next = extension(first.snapshot, first.clock, 1);
  const guardBefore = disk(path).clock;
  store.compareAndSwap(first.snapshot, next, first.clock);
  assert.equal(disk(path).clock, guardBefore);
  assert.equal(samples, 2, "trust CAS must not sample a replacement clock");
  assert.throws(() => store.compareAndSwap(first.snapshot, next, first.clock), code("rotation_state_changed"));
  now++;
  assert.throws(() => store.checkSnapshotClock(first.snapshot), code("rotation_state_changed"));
  const second = store.snapshot();
  assert.equal(second.clock.highWater, now, "stale snapshot cannot suppress clock advance");
  assert.equal(second.snapshot.revision, next.revision);
  assert.equal(second.snapshot.clock.highWater, first.clock.highWater);
  const afterAdvance = readFileSync(path);
  const full = extension(second.snapshot, first.clock);
  assert.throws(() => store.compareAndSwap(second.snapshot, full, first.clock), code("rotation_state_changed"));
  assert.deepEqual(readFileSync(path), afterAdvance);
  assert.equal(store.checkSnapshotClock(second.snapshot).highWater, now);
  const currentGuard = disk(path).clock;
  store.compareAndSwap(second.snapshot, extension(second.snapshot, second.clock), second.clock);
  assert.equal(disk(path).clock, currentGuard);
  const committed = store.snapshot().snapshot;
  store.close();
  store.close();
  assert.equal(disk(path).dirty, false);
  assert.equal(existsSync(path + ".owner"), false);
  assert.throws(() => store.advanceAndCheck(), code("rotation_clock_unavailable"));
  const reopened = RotationTrustStore.open(path, config);
  assert.deepEqual(reopened.snapshot().snapshot, committed);
  assert.equal(reopened.snapshot().clock.highWater, now);
  assert.equal(disk(path).owner, 3);
  reopened.close();
});

test("trust store: rollback/invalid time latch survives catch-up without lowering H", { skip: !linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  for (const invalid of [99, -1, NaN, Infinity, 1.5]) {
    const path = join(root, `state-${String(invalid)}`);
    let now = 100;
    let samples = 0;
    const config = options(() => { samples++; return now; });
    RotationTrustStore.initializeUnused(path, config);
    const store = RotationTrustStore.open(path, config);
    now = invalid;
    assert.throws(() => store.advanceAndCheck(), code("rotation_clock_unsafe"));
    const clock = JSON.parse(disk(path).clock) as { high_water: number; unsafe: boolean };
    assert.equal(clock.high_water, 100);
    assert.equal(clock.unsafe, true);
    const latched = readFileSync(path);
    const calls = samples;
    now = 200;
    assert.throws(() => store.advanceAndCheck(), code("rotation_clock_unsafe"));
    assert.equal(samples, calls);
    assert.deepEqual(readFileSync(path), latched);
    assert.throws(() => store.close(), code("rotation_state_unavailable"));
    assert.equal(existsSync(path + ".owner"), true);
    assert.throws(() => RotationTrustStore.open(path, config), code("rotation_state_unavailable"));
  }
});

test("trust store: throwing/reentrant clock fences without subsequent write or cleanup", { skip: !linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  for (const mode of ["throw", "reentrant", "fence"]) {
    const path = join(root, mode);
    let store: Store | undefined;
    let active = false;
    const config = options(() => {
      if (active) {
        if (mode === "throw") throw new Error("private callback detail");
        if (mode === "fence") store?.fence();
        else assert.throws(() => store?.rawClock(), code("rotation_clock_unavailable"));
        return 101;
      }
      return 100;
    });
    RotationTrustStore.initializeUnused(path, config);
    store = RotationTrustStore.open(path, config);
    const before = readFileSync(path);
    active = true;
    assert.throws(() => store?.advanceAndCheck(), code("rotation_clock_unavailable"));
    assert.deepEqual(readFileSync(path), before);
    assert.throws(() => store?.close(), code("rotation_state_unavailable"));
    assert.equal(existsSync(path + ".owner"), true);
    assert.throws(() => RotationTrustStore.open(path, config), code("rotation_state_unavailable"));
  }
});

test("trust store: initialization failure retains dirty gate; corruption never samples clock", { skip: !linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "failed-init");
  assert.throws(() => RotationTrustStore.initializeUnused(path, options(() => { throw new Error("private detail"); })), code("rotation_state_unknown"));
  assert.equal(disk(path).dirty, true);
  assert.equal(existsSync(path + ".owner"), true);
  let calls = 0;
  assert.throws(() => RotationTrustStore.open(path, options(() => { calls++; return 100; })), code("rotation_state_unavailable"));
  assert.equal(calls, 0);
  const corrupt = join(root, "corrupt");
  RotationTrustStore.initializeUnused(corrupt, options(() => 100));
  writeFileSync(corrupt, "{not valid protected state", { mode: 0o600 });
  const bytes = readFileSync(corrupt);
  assert.throws(() => RotationTrustStore.open(corrupt, options(() => { calls++; return 100; })));
  assert.deepEqual(readFileSync(corrupt), bytes);
  assert.equal(calls, 0);
  assert.equal(existsSync(corrupt + ".owner"), false);
});

test("trust store: actual pre/post-rename clock uncertainty has no retry or clean release", { skip: !linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  for (const outcome of ["before", "after"]) {
    const path = join(root, outcome);
    RotationTrustStore.initializeUnused(path, options(() => 100));
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import fs from 'node:fs';
      import {syncBuiltinESMExports} from 'node:module';
      const {RotationTrustStore} = await import(process.argv[1]);
      const config = JSON.parse(process.argv[4]);
      let now = 100;
      config.now = () => now;
      const store = RotationTrustStore.open(process.argv[2], config);
      const rename = fs.renameSync;
      let attempts = 0;
      fs.renameSync = (...args) => {
        attempts++;
        if (process.argv[3] === 'after') rename(...args);
        throw new Error('injected lost outcome');
      };
      syncBuiltinESMExports();
      now = 101;
      let refused = false;
      try { store.advanceAndCheck(); }
      catch(error) { if(error.code !== 'rotation_clock_unavailable') throw error; refused = true; }
      if (!refused || attempts !== 1) process.exit(2);
      try { store.close(); process.exit(3); }
      catch(error) { if(error.code !== 'rotation_state_unavailable') throw error; }
      if (attempts !== 1 || !fs.existsSync(process.argv[2]+'.owner')) process.exit(4);
    `, moduleURL, path, outcome, JSON.stringify(options(() => 100))], { timeout: 3000, encoding: "utf8" });
    assert.equal(child.error, undefined);
    assert.equal(child.status, 0, child.stderr);
    const guard = JSON.parse(disk(path).clock) as { high_water: number };
    assert.equal(guard.high_water, outcome === "after" ? 101 : 100);
    assert.equal(disk(path).dirty, true);
    assert.throws(() => RotationTrustStore.open(path, options(() => 101)), code("rotation_state_unavailable"));
  }
});

test("trust store: unsupported platform refuses before clock or file creation", { skip: linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "state");
  let calls = 0;
  const config = options(() => { calls++; return 100; });
  assert.throws(() => RotationTrustStore.initializeUnused(path, config), code("rotation_state_unavailable"));
  assert.throws(() => RotationTrustStore.open(path, config), code("rotation_state_unavailable"));
  assert.equal(calls, 0);
  assert.equal(existsSync(path), false);
  assert.equal(existsSync(path + ".owner"), false);
});

test("trust store: actual init/trust-CAS lost outcomes keep restart gate and never retry", { skip: !linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  for (const phase of ["init", "trust"]) for (const outcome of ["before", "after"]) {
    const path = join(root, `${phase}-${outcome}`);
    let desired: rotation.RotationTrustSnapshot | undefined;
    if (phase === "trust") {
      RotationTrustStore.initializeUnused(path, options(() => 100));
      const preparing = RotationTrustStore.open(path, options(() => 100));
      const state = preparing.snapshot();
      desired = extension(state.snapshot, state.clock);
      preparing.close();
    }
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import fs from 'node:fs';
      import {syncBuiltinESMExports} from 'node:module';
      const {RotationTrustStore} = await import(process.argv[1]);
      const config = JSON.parse(process.argv[4]);
      config.now = () => 100;
      const phase = process.argv[5];
      const store = phase === 'trust' ? RotationTrustStore.open(process.argv[2], config) : undefined;
      const previous = store?.snapshot();
      const rename = fs.renameSync;
      let attempts = 0;
      fs.renameSync = (...args) => {
        attempts++;
        if (process.argv[3] === 'after') rename(...args);
        throw new Error('injected lost outcome');
      };
      syncBuiltinESMExports();
      let refused = false;
      try {
        if (phase === 'init') RotationTrustStore.initializeUnused(process.argv[2], config);
        else store.compareAndSwap(previous.snapshot, JSON.parse(process.argv[6]), previous.clock);
      } catch(error) { if(error.code !== 'rotation_state_unknown') throw error; refused = true; }
      if (!refused || attempts !== 1) process.exit(2);
      if (store !== undefined) {
        try { store.close(); process.exit(3); }
        catch(error) { if(error.code !== 'rotation_state_unavailable') throw error; }
      }
      if (attempts !== 1 || !fs.existsSync(process.argv[2]+'.owner')) process.exit(4);
    `, moduleURL, path, outcome, JSON.stringify(options(() => 100)), phase, JSON.stringify(desired ?? null)], { timeout: 3000, encoding: "utf8" });
    assert.equal(child.error, undefined);
    assert.equal(child.status, 0, child.stderr);
    const state = disk(path);
    const guard = JSON.parse(state.clock) as { high_water: number };
    if (phase === "init") {
      assert.equal(state.dirty, outcome === "before");
      assert.equal(guard.high_water, outcome === "after" ? 100 : 0);
    } else {
      const snapshot = JSON.parse(state.snapshot) as { trust_revision: number };
      assert.equal(snapshot.trust_revision, outcome === "after" ? 2 : 1);
      assert.equal(state.dirty, true);
      assert.equal(guard.high_water, 100);
    }
    assert.equal(existsSync(path + ".owner"), true);
    const committed = readFileSync(path);
    assert.throws(() => RotationTrustStore.open(path, options(() => 100)), code("rotation_state_unavailable"));
    assert.deepEqual(readFileSync(path), committed);
  }
});

test("trust store: options getter errors are sanitized before any file or clock work", (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "state");
  const config = options(() => { throw new Error("clock must not be called"); });
  let reads = 0;
  Object.defineProperty(config, "now", { get() { reads++; throw new Error("private options detail"); } });
  for (const action of [() => RotationTrustStore.initializeUnused(path, config), () => RotationTrustStore.open(path, config)]) {
    assert.throws(action, (error) => code("rotation_state_unavailable")(error) && !String(error).includes("private options detail"));
  }
  assert.equal(reads, 2);
  assert.equal(existsSync(path), false);
  assert.equal(existsSync(path + ".owner"), false);
});

test("trust store: abandoned child dirty epoch independently blocks startup without stale marker", { skip: !linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "state");
  RotationTrustStore.initializeUnused(path, options(() => 100));
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    const {RotationTrustStore} = await import(process.argv[1]);
    const config = JSON.parse(process.argv[3]);
    config.now = () => 100;
    RotationTrustStore.open(process.argv[2], config);
    process.exit(0);
  `, moduleURL, path, JSON.stringify(options(() => 100))], { timeout: 3000, encoding: "utf8" });
  assert.equal(child.error, undefined);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(disk(path).dirty, true);
  const before = readFileSync(path);
  const marker = readFileSync(path + ".owner");
  // Только test-owned evidence: убираем marker как причину отказа, не восстанавливаем store.
  const archived = join(root, "abandoned-owner-evidence");
  renameSync(path + ".owner", archived);
  let calls = 0;
  assert.throws(() => RotationTrustStore.open(path, options(() => { calls++; return 100; })), code("rotation_state_unavailable"));
  assert.equal(calls, 0);
  assert.deepEqual(readFileSync(path), before);
  assert.deepEqual(readFileSync(archived), marker);
  assert.equal(existsSync(path + ".owner"), false);
});

test("trust store: each open/init captures the clock getter once and owns its callback", { skip: !linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "state");
  let getterReads = 0;
  let samples = 0;
  const config = options(() => 100);
  Object.defineProperty(config, "now", { configurable: true, get() {
    getterReads++;
    return () => { samples++; return 100; };
  } });
  RotationTrustStore.initializeUnused(path, config);
  assert.equal(getterReads, 1);
  const store = RotationTrustStore.open(path, config);
  assert.equal(getterReads, 2);
  Object.defineProperty(config, "now", { get() { throw new Error("must not reread caller options"); } });
  assert.equal(store.rawClock(), 100);
  assert.equal(store.advanceAndCheck().highWater, 100);
  store.close();
  assert.equal(getterReads, 2);
  assert.equal(samples, 4);
});

test("rotation namespace exposes semantic store without private file or wire helpers", () => {
  for (const name of ["RotationFileOwner", "createUnusedOwner", "pack", "unpack", "invalidStore", "anchorSnapshot"]) {
    assert.equal(name in rotation, false, `private helper leaked: ${name}`);
  }
});
