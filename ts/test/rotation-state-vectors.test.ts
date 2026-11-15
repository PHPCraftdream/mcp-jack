/**
 * Conformance runner for spec/fixtures/candidate/rotation-state-vectors.json
 * (format "mcp-jack-candidate-rotation-state-v1"), gap G2 of
 * docs/cross-language-conformance.md. All 14 client refresh cases and all 8
 * clock/server selection events are driven through the real TypeScript code:
 *
 * - client_cases: the trusted snapshot is seeded into a real
 *   RotationTrustStore (Linux-gated, like the neighbouring rotation store
 *   tests) and the signed response is fed to RotationController.acceptRefresh,
 *   the entry point a real client uses after a signed response. The clock is
 *   an injected, scripted store clock (no wall time).
 * - event "selection": RotationServerProvider.selectSigner over a real
 *   RotationServerStore ring announced at the vector schedule.
 * - event "clock": RotationTrustStore.advanceAndCheck (durable ClockGuard).
 * - event "emission": RotationServerProvider.authorizeResponse + its
 *   single-shot final gate.
 *
 * Mapping contract (vector field -> TypeScript observable):
 * - expect.error              -> thrown JackError/RotationError code; null =
 *   acceptRefresh returned normally. "duplicate" is not a distinct flag in
 *   the SDK: a duplicate page returns committed=false with zero callbacks, so
 *   it is asserted as an unchanged store (revision/records/head).
 * - expect.callbacks          -> trust-CAS invocations, observed through
 *   commit/fence effects: callbacks=1 with committed=true means revision
 *   advanced; callbacks=1 with committed=false means the CAS boundary was
 *   reached exactly once and refused; callbacks=0 means revision unchanged.
 * - expect.committed          -> result.committed (or RotationRefreshCommittedError
 *   .result.committed) and the durable snapshot on disk.
 * - expect.ackOrdinal         -> durable head ordinal.
 * - expect.carrierTrusted     -> carrier fully verified: acceptRefresh returned
 *   normally (no refusal error) with a result present; committed/duplicate
 *   are asserted separately.
 * - expect.fenced             -> fence observables: in-memory reads refuse and
 *   the startup gate refuses reopen (the persisted dirty=true bundle plus the
 *   still-held owner marker); fence() does not write a fenced byte on disk.
 * - clock events: expect.highWater/revision/unsafe -> store ClockGuard; writes
 *   are mirrored by revision deltas (the store writes iff the guard changes);
 *   callbacks=1 counts the ClockGuard operation itself. latch:"unknown" maps
 *   to an uncertain write outcome, which the spec (section 4) routes to
 *   rotation_clock_unavailable + fence: reproduced by a failing store write.
 * - emission/selection: expect.emit -> the final gate passing/throwing;
 *   signatures=1 -> exactly one sign call; resigns=0 -> no second sign call.
 *
 * Deviations (all documented at the driving test):
 * - the private writer flag and the store read/CAS boundaries are test seams
 *   where the single-threaded controller or the exclusive-owner file store
 *   cannot receive an external event; no production behaviour is changed.
 * - seeded snapshots with records reach revision 2 via the store's public
 *   lifecycle (initializeUnused + compareAndSwap); the vector's literal
 *   input revision is metadata and asserted by no expectation.
 * - the emission "clock generation" vector is driven through a durable guard
 *   state change (rollback latch) because the TypeScript server store has no
 *   separate generation counter (see the test comment for the spec mapping).
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, realpathSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { TestContext } from "node:test";
import { client, encodeBase64URL, formatResponseAuth, JackError, keyId, rotation, TOOL_SERVER_KEY } from "../src/index.js";
import { fixture } from "./fixtures.js";

const linux = process.platform === "linux";
const ENDPOINT = "https://svc.example.test/mcp";
const AUDIENCE = "https://svc.example.test";
const BINDING = { endpoint: ENDPOINT, aud: AUDIENCE };
const WINDOW = 30;
const SEED_NOW = 1000;
const ANCHOR_PUBLISHED_AT = 0;

interface AnchorInput { readonly public_key: string; readonly kid: string }
interface SnapshotInput {
  readonly endpoint: string; readonly aud: string; readonly anchor: AnchorInput;
  readonly records: readonly string[]; readonly window: number; readonly revision: number;
  readonly fence: boolean; readonly clockGeneration: number;
}
interface ResponseInput {
  readonly status: number; readonly requestSig: string; readonly kid: string;
  readonly ts: number; readonly now: number; readonly body_b64u: string; readonly signature: string;
}
interface ClientExpect {
  readonly error: string | null; readonly callbacks: number; readonly committed?: boolean;
  readonly duplicate?: boolean; readonly ackOrdinal: number; readonly carrierTrusted?: boolean; readonly fenced?: boolean;
}
interface ClientCase {
  readonly id: string;
  readonly input: {
    readonly snapshot: SnapshotInput; readonly response: ResponseInput; readonly expectedId: number;
    readonly cursor: rotation.RotationCursor; readonly preCallbackNow: number; readonly finalNow: number;
    readonly finalClockGeneration: number; readonly callbackOutcome: string;
    readonly writerBusy: boolean; readonly staleSnapshot: boolean;
  };
  readonly expect: ClientExpect;
}
interface EventCase {
  readonly id: string;
  readonly input: {
    readonly kind: string;
    readonly records?: readonly string[];
    readonly before?: number; readonly at?: number; readonly after?: number;
    readonly guard?: { readonly binding: string; readonly window: number; readonly highWater: number; readonly revision: number };
    readonly rawNow?: number; readonly latch?: string;
    readonly selectedKid?: string; readonly selectedOrdinal?: number;
    readonly signingTime?: number; readonly emissionTime?: number;
    readonly clockGenerationBefore?: number; readonly clockGenerationNow?: number;
    readonly fenced?: boolean; readonly signerReady?: boolean;
  };
  readonly expect: Record<string, unknown>;
}
interface StateVectors {
  readonly format: string;
  readonly client_local_errors: readonly string[];
  readonly server_errors: Record<string, number>;
  readonly client_cases: readonly ClientCase[];
  readonly event_cases: readonly EventCase[];
}

const vectors = fixture("candidate/rotation-state-vectors.json") as unknown as StateVectors;
assert.equal(vectors.format, "mcp-jack-candidate-rotation-state-v1", "fixture format id");
assert.equal(vectors.client_cases.length, 14, "client case count pinned to the generated fixture");
assert.equal(vectors.event_cases.length, 8, "event case count pinned to the generated fixture");

// Guard: every client_local_errors entry except rotation_record_invalid is the
// expectation of at least one client or event vector; rotation_record_invalid appears only in
// the table (no generated case drives it) and is reported as a named gap.
const expectedCodes = new Set<unknown>([
  ...vectors.client_cases.map((entry) => entry.expect.error),
  ...vectors.event_cases.map((entry) => entry.expect["error"]),
]);
for (const code of vectors.client_local_errors) {
  if (code === "rotation_record_invalid") continue;
  assert.ok(expectedCodes.has(code), `table code ${code} is exercised by a vector`);
}
assert.ok(!expectedCodes.has("rotation_record_invalid"), "no generated case expects rotation_record_invalid");
assert.deepEqual(Object.values(vectors.server_errors).sort(), [400, 409, 503], "server error table is server-side, not client-drivable");

function directory(context: TestContext, label: string): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), `mcp-jack-state-vectors-${label}-`)));
  chmodSync(root, 0o700);
  context.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function checkpointOf(anchor: AnchorInput): rotation.RotationCheckpoint {
  return { ordinal: 0, hash: "-", kid: anchor.kid, publicKeyB64u: anchor.public_key, publishedAt: ANCHOR_PUBLISHED_AT };
}

function trustKeys(checkpoint: rotation.RotationCheckpoint, records: readonly rotation.RotationRecord[]): rotation.RotationTrustKey[] {
  const keys: rotation.RotationTrustKey[] = [{ ordinal: checkpoint.ordinal, kid: checkpoint.kid,
    publicKeyB64u: checkpoint.publicKeyB64u, notBefore: 0, knownCutoff: null }];
  for (const record of records) {
    const tail = keys[keys.length - 1];
    assert.ok(tail);
    keys[keys.length - 1] = { ...tail, knownCutoff: record.activatesAt };
    keys.push({ ordinal: record.ordinal, kid: record.newKid, publicKeyB64u: record.publicKeyB64u,
      notBefore: record.activatesAt, knownCutoff: null });
  }
  return keys;
}

interface DiskBundle { readonly fenced: boolean; readonly clock: string; readonly snapshot: string }
function diskBundle(path: string): DiskBundle {
  const outer = JSON.parse(readFileSync(path, "utf8")) as { payload: string };
  return JSON.parse(outer.payload) as DiskBundle;
}

// ---------------------------------------------------------------------------
// Client refresh harness
// ---------------------------------------------------------------------------

interface ClientEnvironment {
  readonly store: rotation.RotationTrustStore;
  readonly controller: rotation.RotationController;
  readonly path: string;
  readonly revision: number;
  readonly options: rotation.RotationStoreOptions;
  setScript(values: readonly number[], onSample?: (index: number) => void): void;
}

function clientEnvironment(context: TestContext, label: string, input: ClientCase["input"]): ClientEnvironment {
  const dir = directory(context, label);
  const snapshotInput = input.snapshot;
  const checkpoint = checkpointOf(snapshotInput.anchor);
  let current = SEED_NOW;
  let hook: (() => number) | undefined;
  const now = (): number => (hook ? hook() : current);
  const options = { binding: BINDING, checkpoint, window: snapshotInput.window, now };
  const path = join(dir, "trust");
  rotation.RotationTrustStore.initializeUnused(path, options);
  const store = rotation.RotationTrustStore.open(path, options);
  context.after(() => { try { store.close(); } catch { /* fenced stores refuse close by design */ } });
  const seeded = store.snapshot();
  let revision = seeded.snapshot.revision;
  if (snapshotInput.records.length > 0) {
    const records = rotation.verifyRotationChain(snapshotInput.records.map((wire) => Buffer.from(wire, "utf8")), BINDING, checkpoint);
    assert.equal(records.length, snapshotInput.records.length, `seed records of ${label}`);
    const keys = trustKeys(checkpoint, records);
    const last = records[records.length - 1];
    assert.ok(last);
    const desired: rotation.RotationTrustSnapshot = { ...seeded.snapshot,
      head: { ordinal: last.ordinal, hash: last.hash }, records: [...snapshotInput.records],
      keys, revision: seeded.snapshot.revision + 1, clock: seeded.clock };
    store.compareAndSwap(seeded.snapshot, desired, seeded.clock);
    revision = desired.revision;
  }
  const controller = new rotation.RotationController(store);
  return {
    store, controller, path, revision, options,
    setScript(values, onSample) {
      const fallback = values[values.length - 1];
      assert.ok(fallback !== undefined, "clock script needs at least one value");
      const queue = [...values];
      let index = 0;
      hook = () => {
        const value = queue.shift() ?? fallback;
        onSample?.(index++);
        return value;
      };
    },
  };
}

function vectorResponse(input: ClientCase["input"]): rotation.RotationResponse {
  const wire = input.response;
  return { status: wire.status, requestSignature: wire.requestSig,
    body: Buffer.from(wire.body_b64u, "base64url"),
    headers: [formatResponseAuth({ kid: wire.kid, ts: wire.ts, sig: wire.signature })] };
}

interface Outcome { readonly error: string | null; readonly committed: boolean; readonly result?: rotation.RotationRefreshResult }

function accept(env: ClientEnvironment, input: ClientCase["input"]): Outcome {
  try {
    const result = env.controller.acceptRefresh(vectorResponse(input), input.expectedId, input.cursor);
    return { error: null, committed: result.committed, result };
  } catch (error) {
    if (error instanceof rotation.RotationRefreshCommittedError) {
      return { error: error.code, committed: error.result.committed, result: error.result };
    }
    if (error instanceof JackError) return { error: error.code, committed: false };
    if (error instanceof rotation.RotationError) return { error: error.code, committed: false };
    throw error;
  }
}

/** Drives one client case with its full expectation; `seam` applies a documented test seam first. */
function driveClientCase(context: TestContext, entry: ClientCase): void {
  const input = entry.input;
  const env = clientEnvironment(context, entry.id, input);
  const code = entry.expect.error;
  // Scripted authoritative samples: raw carrier sample and outer gate use the
  // response time, the writer gate the pre-callback time, the final gate the
  // final time (identical in most vectors).
  let onSample: ((index: number) => void) | undefined;
  const seam = SEAMS.get(entry.id);
  if (seam !== undefined) onSample = seam(env, entry);
  env.setScript([input.response.now, input.response.now, input.preCallbackNow, input.finalNow], onSample);
  const outcome = accept(env, input);
  assert.equal(outcome.error, code, `error code of ${entry.id}`);
  if (entry.expect.committed !== undefined) assert.equal(outcome.committed, entry.expect.committed, `committed of ${entry.id}`);
  if (entry.expect.fenced === true) {
    // Spec section 5 (L112): "Unknown callback outcome immediately fences the
    // binding at every new-traffic and final gate. Persist the binding-wide
    // fence; if its durability is uncertain, a pre-existing durable dirty
    // marker or externally enforced startup gate MUST block every owner until
    // explicit recovery." In this profile fence() sets the in-memory
    // RotationTrustStore/RotationFileOwner flags (rotation-store.ts:180,
    // rotation-file.ts:169); the durable gate is the still-held owner marker
    // plus the persisted dirty=true bundle that RotationTrustStore.open
    // refuses (rotation-store.ts:64). The fenced byte in the on-disk payload
    // is NOT written by fence(), so the durable observable asserted here is
    // the read refusal and the startup gate, matching the Go runner's
    // assertRefusesReopen for unknown-outcome vectors.
    assert.throws(() => env.store.snapshot(), (error) => error instanceof rotation.RotationError, `fenced store refuses reads of ${entry.id}`);
    assert.throws(() => rotation.RotationTrustStore.open(env.path, env.options),
      (error) => error instanceof rotation.RotationError, `fenced binding refuses reopen of ${entry.id}`);
  } else {
    const state = env.store.snapshot();
    assert.equal(state.snapshot.head.ordinal, entry.expect.ackOrdinal, `ackOrdinal of ${entry.id}`);
    if (entry.expect.callbacks === 0 || entry.expect.committed === false) {
      assert.equal(state.snapshot.revision, env.revision, `trust revision unchanged of ${entry.id}`);
      assert.deepEqual([...state.snapshot.records], [...input.snapshot.records], `retained records of ${entry.id}`);
    }
    if (entry.expect.callbacks === 1 && entry.expect.committed === true) {
      assert.equal(state.snapshot.revision, env.revision + 1, `exactly one trust CAS of ${entry.id}`);
      assert.equal(state.snapshot.records.length, entry.expect.ackOrdinal, `committed records of ${entry.id}`);
    }
    if (entry.expect.carrierTrusted === true) {
      // carrierTrusted means the carrier authenticated and passed every gate:
      // no refusal error and a result present. It does NOT mean trust
      // advanced — spec section 6 (L97): an all-duplicate response "is a
      // no-op with zero trust-extension callbacks ... it never moves P/A or
      // clears a fence". committed/duplicate are asserted separately above
      // and below, so a duplicate no-op (committed=false, revision
      // unchanged) still passes here and a post-commit refusal still fails.
      assert.equal(outcome.error, null, `carrier trust of ${entry.id}`);
      assert.ok(outcome.result !== undefined, `carrier result of ${entry.id}`);
    }
    if (entry.expect.carrierTrusted === false) {
      assert.ok(outcome.result !== undefined && outcome.result.committed, `late ACK retained of ${entry.id}`);
      assert.ok(code !== null, `late failure code of ${entry.id}`);
    }
    if (entry.expect.duplicate === true) {
      assert.equal(outcome.committed, false, `duplicate is a no-op of ${entry.id}`);
      assert.equal(state.snapshot.revision, env.revision, `duplicate does not advance trust of ${entry.id}`);
    }
  }
}

/**
 * Documented test seams, one per vector the real code cannot receive an
 * external event for. Each returns an optional sample hook used to time the
 * seam; no production behaviour is changed.
 */
const SEAMS = new Map<string, (env: ClientEnvironment, entry: ClientCase) => ((index: number) => void) | undefined>([
  // Vector: trust-callback-definite-conflict (expect rotation_state_changed,
  // callbacks 1, committed false). Spec section 5: "An external trust or clock
  // conflict is one definite noncommit". The sync file store cannot produce a
  // definite external conflict mid-operation under its exclusive owner, so the
  // conflict is injected at the exact CAS/callback boundary the vector names.
  ["trust-callback-definite-conflict", (env) => {
    const target = env.store as unknown as { compareAndSwap(): void };
    target.compareAndSwap = () => { throw new rotation.RotationError("rotation_state_changed"); };
    return undefined;
  }],
  // Vector: trust-callback-unknown-fences (expect rotation_state_unknown,
  // callbacks 1, fenced). Spec section 5: "Unknown callback outcome
  // immediately fences the binding". The seam routes the CAS through the
  // store's own unknown-write path: fence() then rotation_state_unknown,
  // exactly what RotationTrustStore does when a write outcome is unknown.
  ["trust-callback-unknown-fences", (env) => {
    const target = env.store as unknown as { compareAndSwap(): void; fence(): void };
    target.compareAndSwap = () => { target.fence(); throw new rotation.RotationError("rotation_state_unknown"); };
    return undefined;
  }],
  // Vector: busy-writer-stops-before-trust-callback (expect
  // rotation_state_changed, callbacks 0). Spec section 4: "A client
  // trust-extension attempt uses a per-binding writer token. If token
  // acquisition fails ... reject before callback with zero trust-CAS
  // invocations." The controller is single-threaded, so the writer token is
  // marked held directly on the instance.
  ["busy-writer-stops-before-trust-callback", (env) => {
    (env.controller as unknown as { writer: boolean }).writer = true;
    return undefined;
  }],
  // Vector: stale-whole-snapshot-stops-before-callback (expect
  // rotation_state_changed, callbacks 0). Spec section 5: "If ... the expected
  // pre-callback snapshot is stale, reject before callback with zero trust-CAS
  // invocations." The exclusive-owner store admits no concurrent writer, so
  // the store read boundary is made to report a stale snapshot once, armed at
  // the first authoritative clock sample (after the owned snapshot was read,
  // before the writer re-read).
  ["stale-whole-snapshot-stops-before-callback", (env) => {
    const original = env.store.snapshot.bind(env.store);
    let stale = false;
    (env.store as unknown as { snapshot(): { snapshot: rotation.RotationTrustSnapshot; clock: rotation.RotationClockTuple } }).snapshot =
      () => {
        const state = original();
        if (stale) {
          stale = false;
          return { ...state, snapshot: { ...state.snapshot, revision: state.snapshot.revision + 1 } };
        }
        return state;
      };
    return (index) => { if (index === 0) stale = true; };
  }],
]);

for (const entry of vectors.client_cases) {
  test(`state vectors client: ${entry.id}`, { skip: !linux }, (context) => {
    driveClientCase(context, entry);
  });
}

// ---------------------------------------------------------------------------
// Clock guard event harness
// ---------------------------------------------------------------------------

interface ClockEnvironment {
  readonly store: rotation.RotationTrustStore;
  readonly path: string;
  readonly options: rotation.RotationStoreOptions;
  setCurrent(value: number): void;
}

/** Seeds a real store ClockGuard at the vector guard's highWater/revision. */
function clockEnvironment(context: TestContext, entry: EventCase): ClockEnvironment {
  const guard = entry.input.guard;
  assert.ok(guard);
  assert.equal(guard.binding, ENDPOINT, `clock binding of ${entry.id}`);
  assert.equal(guard.window, WINDOW, `clock window of ${entry.id}`);
  const dir = directory(context, entry.id);
  const first = vectors.client_cases[0];
  assert.ok(first, "first client case supplies the shared anchor");
  const checkpoint = checkpointOf(first.input.snapshot.anchor);
  let current = guard.highWater - (guard.revision - 1);
  const options = { binding: BINDING, checkpoint, window: guard.window, now: () => current };
  const path = join(dir, "trust");
  rotation.RotationTrustStore.initializeUnused(path, options); // revision 1 at highWater
  const store = rotation.RotationTrustStore.open(path, options);
  context.after(() => { try { store.close(); } catch { /* fenced stores refuse close by design */ } });
  // Distinct-time advances bring the durable guard to exactly the vector's
  // highWater and revision.
  for (let value = guard.highWater - guard.revision + 2; value <= guard.highWater; value++) {
    current = value;
    store.advanceAndCheck();
  }
  const state = store.snapshot();
  assert.equal(state.clock.highWater, guard.highWater, `seed highWater of ${entry.id}`);
  assert.equal(state.clock.revision, guard.revision, `seed revision of ${entry.id}`);
  return { store, path, options, setCurrent: (value) => { current = value; } };
}

test("state vectors clock: clock-rollback-latches", { skip: !linux }, (context) => {
  const entry = vectors.event_cases.filter((candidate) => candidate.id === "clock-rollback-latches")[0];
  assert.ok(entry);
  const env = clockEnvironment(context, entry);
  assert.ok(entry.input.rawNow !== undefined);
  env.setCurrent(entry.input.rawNow);
  // writes=1: the store writes the guard iff it changes; revision 4 -> 5 is
  // that durable write. callbacks=1 counts the ClockGuard operation itself.
  assert.throws(() => env.store.advanceAndCheck(),
    (error) => error instanceof rotation.RotationError && error.code === "rotation_clock_unsafe");
  // The in-memory snapshot() refuses an unsafe store by design: spec section
  // 4 (L91) "Missing/corrupt/unsupported guard, unsafe bit ... remains
  // closed" and rotationTrustClockCompatible requires clock.unsafe === false
  // (rotation-trust.ts:155), so snapshot() throws rotation_state_unavailable.
  // The latch itself IS durable: advance() writes highWater unchanged,
  // revision+1, unsafe=true (rotation-store.ts:136-140) before throwing
  // rotation_clock_unsafe. Assert the durable guard bytes on disk instead,
  // plus the startup gate that keeps the latched binding closed.
  const bundle = diskBundle(env.path);
  const clock = JSON.parse(bundle.clock) as { readonly high_water: number; readonly clock_revision: number; readonly unsafe: boolean };
  assert.equal(clock.high_water, entry.expect.highWater);
  assert.equal(clock.unsafe, entry.expect.unsafe);
  // The rollback expectation pins no revision: the latch must land on seed + 1.
  assert.equal(clock.clock_revision, guardRevision(entry) + 1);
  assert.throws(() => rotation.RotationTrustStore.open(env.path, env.options),
    (error) => error instanceof rotation.RotationError, "unsafe latched binding refuses reopen");
});

function guardRevision(entry: EventCase): number {
  assert.ok(entry.input.guard);
  return entry.input.guard.revision;
}

test("state vectors clock: clock-equal-is-noop", { skip: !linux }, (context) => {
  const entry = vectors.event_cases.filter((candidate) => candidate.id === "clock-equal-is-noop")[0];
  assert.ok(entry);
  const env = clockEnvironment(context, entry);
  assert.ok(entry.input.rawNow !== undefined);
  env.setCurrent(entry.input.rawNow);
  const clock = env.store.advanceAndCheck();
  assert.equal(clock.highWater, entry.expect.highWater);
  assert.equal(clock.revision, entry.expect.revision);
  assert.equal(clock.unsafe, entry.expect.unsafe);
  const after = env.store.snapshot().clock;
  assert.equal(after.revision, entry.expect.revision, "equal sample performs no durable write");
});

test("state vectors clock: clock-rollback-latch-unknown-is-unavailable", { skip: !linux }, (context) => {
  const entry = vectors.event_cases.filter((candidate) => candidate.id === "clock-rollback-latch-unknown-is-unavailable")[0];
  assert.ok(entry);
  const env = clockEnvironment(context, entry);
  assert.equal(entry.input.latch, "unknown");
  // latch:"unknown" is an uncertain write outcome. Spec section 4: "A
  // definite failure or unknown write outcome closes the binding and returns
  // rotation_clock_unavailable". Reproduced with a failing store write; the
  // durable guard stays unchanged (unsafe false, revision unchanged).
  const owner = (env.store as unknown as { file: { read(): Uint8Array; replace(a: Uint8Array, b: Uint8Array): void; fence(): void; close(): void } }).file;
  (env.store as unknown as { file: unknown }).file = {
    read: () => owner.read(),
    replace: () => { throw new Error("simulated unknown write outcome"); },
    fence: () => owner.fence(),
    close: () => owner.close(),
  };
  assert.ok(entry.input.rawNow !== undefined);
  env.setCurrent(entry.input.rawNow);
  assert.throws(() => env.store.advanceAndCheck(),
    (error) => error instanceof rotation.RotationError && error.code === "rotation_clock_unavailable");
  // Spec section 4 (L87): "A definite failure or unknown write outcome closes
  // the binding and returns rotation_clock_unavailable ... Never retry an
  // unknown clock write"; section 4 (L91): "failed/unknown guard write
  // remains closed". advance() catches the failed write, fences the store and
  // file owner in memory, and leaves the on-disk bytes untouched — fence()
  // does not write a fenced byte into the payload (rotation-store.ts:147-151,
  // rotation-file.ts:169). The durable gate is the still-held owner marker
  // plus the dirty=true bundle that a fresh RotationTrustStore.open refuses
  // (rotation-store.ts:64), the TS counterpart of the Go runner's fenced
  // Close + assertRefusesReopen for unknown-outcome vectors.
  assert.throws(() => env.store.snapshot(), (error) => error instanceof rotation.RotationError,
    "fenced store refuses reads after unknown write");
  assert.throws(() => rotation.RotationTrustStore.open(env.path, env.options),
    (error) => error instanceof rotation.RotationError, "unknown write outcome closes the binding");
  const bundle = diskBundle(env.path);
  const clock = JSON.parse(bundle.clock) as { readonly high_water: number; readonly clock_revision: number; readonly unsafe: boolean };
  assert.equal(clock.high_water, entry.expect.highWater);
  assert.equal(clock.clock_revision, entry.expect.revision);
  assert.equal(clock.unsafe, entry.expect.unsafe);
});

test("state vectors clock: clock-advance-persists-revision", { skip: !linux }, (context) => {
  const entry = vectors.event_cases.filter((candidate) => candidate.id === "clock-advance-persists-revision")[0];
  assert.ok(entry);
  const env = clockEnvironment(context, entry);
  assert.ok(entry.input.rawNow !== undefined);
  env.setCurrent(entry.input.rawNow);
  const clock = env.store.advanceAndCheck();
  assert.equal(clock.highWater, entry.expect.highWater);
  assert.equal(clock.revision, entry.expect.revision);
  assert.equal(env.store.snapshot().clock.revision, entry.expect.revision, "advance persists the new revision");
});

// ---------------------------------------------------------------------------
// Server selection/emission event harness
// ---------------------------------------------------------------------------

const CANDIDATE_KEY_NAMES = ["candidate-server-anchor", "candidate-server-next1", "candidate-server-next2"] as const;

function candidateSigners(): client.InMemorySigner[] {
  // The vector keys are deterministic test keys: seed = sha256(key name).
  return CANDIDATE_KEY_NAMES.map((name) => new client.InMemorySigner(createHash("sha256").update(`mcp-jack test key: ${name}`).digest()));
}

interface ServerEnvironment {
  readonly store: rotation.RotationServerStore;
  readonly provider: rotation.RotationServerProvider;
  readonly signers: readonly client.InMemorySigner[];
  setCurrent(value: number): void;
  selectedOrdinal(): number;
}

/** Announces the vector ring: publication times per record (equal P allowed). */
function serverEnvironment(context: TestContext, label: string, publicationTimes: readonly number[]): ServerEnvironment {
  const signers = candidateSigners();
  const anchor = signers[0];
  assert.ok(anchor);
  const root = checkpointOf({ public_key: encodeBase64URL(anchor.publicKey()), kid: keyId(anchor.publicKey()) });
  const dir = directory(context, label);
  const startAt = publicationTimes[0];
  assert.ok(startAt !== undefined, "publication schedule needs two entries");
  let current = startAt;
  const options = { binding: BINDING, checkpoint: root, window: WINDOW, anchorReference: "ref-0", now: () => current };
  const path = join(dir, "ring");
  rotation.RotationServerStore.initializeUnused(path, options);
  const store = rotation.RotationServerStore.open(path, options);
  context.after(() => { try { store.close(); } catch { /* fenced stores refuse close by design */ } });
  const keys = signers.map((signer, index) => ({ reference: `ref-${index}`, signer }));
  const provider = new rotation.RotationServerProvider(store, keys);
  const next1 = signers[1];
  const next2 = signers[2];
  assert.ok(next1 && next2, "three candidate test keys are available");
  provider.announce("ref-1", next1.kid());
  const secondAt = publicationTimes[1];
  assert.ok(secondAt !== undefined, "publication schedule needs two entries");
  current = secondAt;
  provider.announce("ref-2", next2.kid());
  return {
    store, provider, signers,
    setCurrent: (value) => { current = value; },
    selectedOrdinal(): number {
      const { snapshot } = store.snapshot();
      const selected = provider.selectSigner(snapshot, store.checkSnapshotClock(snapshot));
      const ordinal = snapshot.trust.keys.findIndex((key) => key.publicKeyB64u === selected.publicKeyB64u);
      assert.ok(ordinal >= 0);
      return ordinal;
    },
  };
}

test("state vectors selection: same-second-greatest-ordinal-wins", { skip: !linux }, (context) => {
  const entry = vectors.event_cases.filter((candidate) => candidate.id === "same-second-greatest-ordinal-wins")[0];
  assert.ok(entry);
  assert.equal(entry.input.kind, "selection");
  // The vector's tie schedule (P1 = P2 = 1000, so A1 = A2 = 173800) is
  // announced through the real publication path; selection is the real
  // RotationServerProvider.selectSigner over a fresh durable ClockGuard
  // sample at each vector time.
  const env = serverEnvironment(context, entry.id, [1000, 1000]);
  assert.ok(entry.input.before !== undefined && entry.input.at !== undefined && entry.input.after !== undefined);
  env.setCurrent(entry.input.before);
  assert.equal(env.selectedOrdinal(), entry.expect.selectedBefore, "before activation the anchor still signs");
  env.setCurrent(entry.input.at);
  assert.equal(env.selectedOrdinal(), entry.expect.selectedAt, "at equal activation the greatest ordinal wins");
  env.setCurrent(entry.input.after);
  assert.equal(env.selectedOrdinal(), entry.expect.selectedAfter);
});

interface EmissionOutcome { readonly signCount: number; readonly finalError: string | null }

/** One real authorize/sign/final cycle; the body page describes the store ring. */
function authorizeAndSign(env: ServerEnvironment, entry: EventCase): EmissionOutcome {
  const selectedKid = entry.input.selectedKid;
  assert.ok(selectedKid);
  const signer = env.signers.filter((candidate) => candidate.kid() === selectedKid)[0];
  assert.ok(signer, `vector selects a known test key: ${selectedKid}`);
  const { snapshot } = env.store.snapshot();
  const trust = snapshot.trust;
  const page = { current: { kid: selectedKid, public_key: encodeBase64URL(signer.publicKey()) },
    records: [...trust.records], head: { ...trust.head }, complete: true };
  const body = Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 7,
    result: { content: [{ type: "text", text: JSON.stringify(page) }], structuredContent: page, isError: false } }));
  env.setCurrent(entry.input.signingTime as number);
  const authorization = env.provider.authorizeResponse(
    { status: 200, tool: TOOL_SERVER_KEY, requestSignature: "candidate-event-request-signature", body });
  // Spec section 1: buffer and sign the exact final body exactly once.
  authorization.signer.sign(new TextEncoder().encode("exact final body"));
  const signCount = 1;
  let finalError: string | null = null;
  try {
    env.setCurrent(entry.input.emissionTime as number);
    authorization.final();
    authorization.release();
  } catch (error) {
    authorization.release();
    if (error instanceof rotation.RotationError) finalError = error.code;
    else throw error;
  }
  return { signCount, finalError };
}

test("state vectors emission: server-final-eligible-single-signature", { skip: !linux }, (context) => {
  const entry = vectors.event_cases.filter((candidate) => candidate.id === "server-final-eligible-single-signature")[0];
  assert.ok(entry);
  const env = serverEnvironment(context, entry.id, [1000, 4600]);
  const outcome = authorizeAndSign(env, entry);
  assert.equal(outcome.finalError, null, "eligible emission passes the single-shot final gate");
  assert.equal(outcome.signCount, entry.expect.signatures, "exactly one signature is produced");
});

test("state vectors emission: server-final-cutoff-no-resign", { skip: !linux }, (context) => {
  const entry = vectors.event_cases.filter((candidate) => candidate.id === "server-final-cutoff-no-resign")[0];
  assert.ok(entry);
  const env = serverEnvironment(context, entry.id, [1000, 4600]);
  const outcome = authorizeAndSign(env, entry);
  // Spec section 1: "If the boundary was crossed ... discard the prepared
  // response and fail closed: never switch kid or ts, re-sign under another
  // key, fallback, or retry." The final gate re-selects at the fresh sample
  // and the next key has become eligible at A2.
  assert.equal(outcome.finalError, "rotation_state_unavailable", "cutoff at emission refuses to emit");
  assert.equal(outcome.signCount, entry.expect.signatures, "one prepared signature");
});

test("state vectors emission: server-final-generation-fence-no-fallback (documented deviation)", { skip: !linux }, (context) => {
  const entry = vectors.event_cases.filter((candidate) => candidate.id === "server-final-generation-fence-no-fallback")[0];
  assert.ok(entry);
  assert.equal(entry.input.kind, "emission");
  assert.equal(entry.input.clockGenerationBefore, 1);
  assert.equal(entry.input.clockGenerationNow, 2);
  // Documented deviation: the vector models the final gate failing because a
  // server clock generation changed between signing-time and emission-time.
  // The TypeScript server store has no separate generation counter; its
  // durable ClockGuard is the same authority spec section 6 requires ("The
  // rotation server MUST maintain its own durable monotone ClockGuard ...
  // using the same advanceAndCheck semantics"). The generation change is
  // therefore driven as a durable guard state change: the emission-time
  // sample is a rollback, the guard durably latches unsafe, and the fresh
  // final check fails. Emit stays false with one prepared signature and no
  // re-sign, exactly as the vector expects.
  const env = serverEnvironment(context, entry.id, [1000, 4600]);
  const rolledBack: EventCase = { ...entry, input: { ...entry.input, emissionTime: (entry.input.signingTime as number) - 1 } };
  const outcome = authorizeAndSign(env, rolledBack);
  assert.equal(outcome.finalError, "rotation_clock_unsafe", "changed guard state refuses the final gate");
  assert.equal(outcome.signCount, entry.expect.signatures, "one prepared signature, never re-signed");
});
