/**
 * Shared candidate nonce vectors (spec/fixtures/candidate/nonce-vectors.json)
 * driven against the TypeScript durable nonce store. The byte format is free
 * (spec section 3); the contract is behavioural. State seeding writes abstract
 * live/intent/tombstone rows through package-internal record types; the seeded
 * loader forces highWater >= ts for every row, so capacity vectors cannot seed
 * highWater 0 — a DOCUMENTED DEVIATION. Every verdict is encoded as data below:
 * "driven" (full expectation), "deviation" (driven with documented field
 * deviations) or "excluded" (spec reason quoted); the test fails if the actual
 * outcome disagrees with the recorded verdict.
 */
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import { fileURLToPath } from "node:url";
import { bodyHash, decodeBase64URLFixed, encodeBase64URL } from "../src/encoding.js";
import { DurableNonceStore } from "../src/server/durable-store.js";
import { intentIdOf, pairKeyOf } from "../src/server/durable-format.js";
import type { DurableDocument, DurableMetadata, DurableReceipt } from "../src/server/durable-format.js";
import { JackError } from "../src/errors.js";

const linux = process.platform === "linux";
const DEPLOYMENT = "candidate-test-deployment";
const WINDOW = 30;

type JsonValue = string | number | boolean | null | JsonValue[] | { readonly [key: string]: JsonValue };

function repoRoot(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    if (existsSync(join(dir, "spec", "fixtures"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) throw new Error(`fixture root not found: no spec/fixtures above ${dir}`);
    dir = parent;
  }
}

interface VectorRow {
  readonly key: string;
  readonly intentId: string;
  readonly operationId?: string;
  readonly ts: number;
  readonly retainUntil: number;
}

interface VectorEvent {
  readonly kid: string;
  readonly nonce: string;
  readonly authenticated: boolean;
  readonly ownerGeneration: number;
  readonly window: number;
  readonly captured: { readonly key: string; readonly enrollment: number };
  readonly cryptoSnapshot: { readonly key: string; readonly enrollment: number };
  readonly ts: number;
  readonly entryNow: number;
  readonly intentNow: number;
  readonly finalNow: number;
  readonly intentOutcome: string;
  readonly finalOutcome: string;
  readonly dispatch: boolean;
  readonly authorization?: string;
  readonly reservationFound?: boolean;
}

interface VectorState {
  readonly window: number;
  readonly highWater: number;
  readonly intents: readonly JsonValue[];
  readonly live: readonly VectorRow[];
  readonly tombstones: readonly JsonValue[];
}

interface VectorCase {
  readonly id: string;
  readonly description?: string;
  readonly state?: VectorState;
  readonly event?: VectorEvent;
  readonly sequence?: readonly VectorEvent[];
  readonly expect: Record<string, JsonValue>;
}

const vectors = JSON.parse(
  readFileSync(join(repoRoot(), "spec", "fixtures", "candidate", "nonce-vectors.json"), "utf8"),
) as { readonly cases: readonly VectorCase[] };
assert.equal(vectors.cases.length, 24, "the shared vector set is fixed at 24 cases");

// ---------------------------------------------------------------------------
// Synthetic identities (shared-vector contract).
// ---------------------------------------------------------------------------

function digest(name: string): Buffer {
  return Buffer.from(createHash("sha256").update(name).digest());
}

function syntheticIdentity(name: string): { kid: string; nonce: string; signature: string; signingBytes: string } {
  return {
    kid: encodeBase64URL(digest(`candidate-vector/kid/${name}`)),
    nonce: encodeBase64URL(digest(`candidate-vector/nonce/${name}`).subarray(0, 16)),
    signature: encodeBase64URL(Buffer.concat([digest(`candidate-vector/sig-a/${name}`),
      digest(`candidate-vector/sig-b/${name}`)])),
    signingBytes: `candidate-vector/signing/${name}`,
  };
}

function syntheticOperation(name: string): string {
  return encodeBase64URL(digest(`candidate-vector/operation/${name}`).subarray(0, 16));
}

// ---------------------------------------------------------------------------
// Verdict table: every one of the 24 vectors, encoded as data.
// ---------------------------------------------------------------------------

const EXCLUDED_GENERATION = "Spec section 2: \"captured accepting owner, owner/store generation, immutable W, " +
  "active-key, registered-caller, or enrollment snapshot changed\" maps to 503 state_changed — but the store " +
  "generation changes only at exclusive-owner handoff in Open (Go durable/store.go openStore), never between " +
  "the captured snapshot and a transaction of the same admission, so the mid-admission change this vector " +
  "assumes has no injection point.";

const EXCLUDED_DEFINITE_ABORT = "The vector expects 503 durability_unavailable for a definite final abort, but " +
  "Go durable/admit.go checkSample reports a definite abort with its step's status (503 state_changed or 401 " +
  "timestamp_out_of_window) only after confirmed intent cleanup, and spec section 2 states \"Any failure " +
  "needing intent cleanup is reported with its step's status only after cleanup is confirmed\". The vector " +
  "expectation contradicts both the Go reference and the spec, so it cannot be driven identically.";

interface Verdict {
  readonly kind: "driven" | "deviation" | "excluded";
  readonly reason: string;
  /** Expect fields intentionally not asserted (deviation vectors only). */
  readonly deviations?: readonly string[];
}

function driven(reason: string): Verdict {
  return { kind: "driven", reason };
}

const VERDICTS: Record<string, Verdict> = {
  "same-second-restart-replay": driven("seeded live row IS the after-restart state; H equal, no write"),
  "future-ts-restart-replay": driven("future-but-fresh timestamp stays replayed after restart"),
  "concurrent-same-pair": driven("serialized arrivals: one commit, one unsigned replay"),
  "concurrent-different-request-identity": driven("different signed identity cannot reuse a committed pair"),
  "expiry-equality": driven("retainUntil equality stays live; no H advance, no write"),
  "expiry-plus-one-fresh-timestamp": driven("H advance at 131 purges and frees the slot"),
  "delayed-crypto-final-freshness": driven("intent sample out of window: no intent commit"),
  "delayed-final-after-confirmed-intent": driven("final sample out of window: cleanup, no dispatch"),
  "purge-highwater-rollback": driven("entry 215 below durable H=216 latches unsafe and fences"),
  "window-decrease-refused": driven("W is immutable for the store generation"),
  "window-increase-refused": driven("W is immutable for the store generation"),
  "key-snapshot-change-zero-commit":
    driven("key snapshot change surfaced through the injected validate closure"),
  "enrollment-snapshot-change-zero-commit":
    driven("enrollment snapshot change surfaced through the injected validate closure"),
  "bad-signature-zero-writes":
    driven("pre-authentication failure: the store is never contacted, so zero writes by construction"),
  "commit-then-authorization-refusal":
    driven("store-level: confirmed commit returns a receipt; the 403 is the caller's simulated post-commit " +
      "authorization refusal and the nonce stays consumed"),
  "unknown-final-present":
    driven("unknown final with the live row found: reconcile to a terminal tombstone"),
  "unknown-final-absent": {
    kind: "deviation",
    reason: "fully driven through recovery inspect + reconcile to a terminal tombstone; only the abstract " +
      "model's writes=2 differs (the injected unknown aborts before the final commit, so exactly one write " +
      "occurs, matching Go durable/admit.go update where an unknown transaction write is not confirmed).",
    deviations: ["writes"],
  },
  "no-effects-without-final-commit": {
    kind: "deviation",
    reason: "fully driven through recovery inspect + reconcile to a terminal tombstone; same writes deviation " +
      "as unknown-final-absent.",
    deviations: ["writes"],
  },
  "crash-after-commit-no-dispatch": {
    kind: "deviation",
    reason: "crash is simulated after the confirmed commit (process abandonment); the vector's 503 " +
      "before-dispatch refusal is a server-layer behaviour (milestone 2), not a store outcome. The behavioural " +
      "contract (pair consumed, never auto-redelivered) is fully asserted.",
    deviations: ["status", "code", "writes"],
  },
  "capacity-live-plus-intent": {
    kind: "deviation",
    reason: "the strict loader forces highWater >= ts for every seeded row (spec section 3), so the 4096 " +
      "seeded rows (ts=100) cannot coexist with highWater 0; the state seeds the minimal loader-forced H (a DOCUMENTED DEVIATION) " +
      "and the post-state highWater assertion is dropped.",
    deviations: ["highWater"],
  },
  "capacity-tombstones": {
    kind: "deviation",
    reason: "the vector seeds tombstones as bare {intentId, outcome}; the strict record schema requires full " +
      "receipts, so tombstones are synthesized with the minimal loader-forced H (a DOCUMENTED DEVIATION) and " +
      "the post-state highWater assertion is dropped.",
    deviations: ["highWater"],
  },
  "unknown-intent-absent": {
    kind: "deviation",
    reason: "the intent transaction aborts without committing, so no H advance or confirmed write occurs; the " +
      "abstract model's highWater=100/writes=1 assume the attempted transaction counted, which the Go " +
      "reference (durable/admit.go update) does not do either. Fencing, zero rows and the manual fence are " +
      "fully asserted.",
    deviations: ["highWater", "writes"],
  },
  "generation-change-zero-commit": { kind: "excluded", reason: EXCLUDED_GENERATION },
  "definite-abort-confirmed-cleanup": { kind: "excluded", reason: EXCLUDED_DEFINITE_ABORT },
};

// ---------------------------------------------------------------------------
// Store-level driving.
// ---------------------------------------------------------------------------

interface Outcome {
  readonly status: number;
  readonly code: string;
  readonly liveCount: number;
  readonly intentCount: number;
  readonly tombstoneCount: number;
  readonly highWater: number;
  readonly fenced: boolean;
  readonly writes: number;
}

interface Harness {
  readonly path: string;
  readonly config: { deploymentId: string; window: number; now: () => number;
    injectTransactionFailure: (phase: "intent" | "final") => "commit" | "abort" | undefined };
  queue(value: number): void;
  store: DurableNonceStore | undefined;
}

interface Fault {
  intent?: "commit" | "abort" | undefined;
  final?: "commit" | "abort" | undefined;
}

function makeHarness(path: string, fault: Fault, window: number): Harness {
  const values: number[] = [];
  let last = 0;
  const config = {
    deploymentId: DEPLOYMENT, window,
    now: () => (values.length > 0 ? (last = values.shift() as number) : last),
    injectTransactionFailure: (phase: "intent" | "final") => fault[phase],
  };
  return {
    path, config,
    queue: (value: number): void => { values.push(value); },
    store: undefined,
  };
}

function admissionFor(event: VectorEvent): {
  kid: string; nonce: string; signature: string; signingBytes: string; timestamp: number; window: number;
  validate: (now: number) => boolean;
} {
  const identity = syntheticIdentity(`${event.kid}:${event.nonce}`);
  return {
    kid: identity.kid, nonce: identity.nonce, signature: identity.signature, signingBytes: identity.signingBytes,
    timestamp: event.ts, window: event.window,
    validate: (): boolean => event.captured.key === event.cryptoSnapshot.key &&
      event.captured.enrollment === event.cryptoSnapshot.enrollment,
  };
}

/** Drives one event against the open store; returns the store-level outcome. */
function driveEvent(harness: Harness, event: VectorEvent, fault: Fault): { outcome: Outcome; committed: boolean } {
  const store = harness.store as DurableNonceStore;
  harness.queue(event.entryNow);
  harness.queue(event.intentNow);
  harness.queue(event.finalNow);
  fault.intent = event.intentOutcome === "unknown" ? "abort" : undefined;
  fault.final = event.finalOutcome === "unknown"
    ? (event.reservationFound === true ? "commit" : "abort")
    : undefined;
  const writesBefore = store.diskWrites;
  let committed = false;
  let status = 0;
  let code = "";
  try {
    const reservation = store.reserve(admissionFor(event));
    committed = true;
    reservation.release();
    // A committed nonce is recorded: an immediate replay stays unsigned (no receipt).
    assert.throws(() => store.reserve(admissionFor(event)), (error: unknown) => {
      assert.ok(error instanceof JackError);
      assert.equal((error as JackError).code, "replayed_nonce");
      return true;
    });
  } catch (error) {
    assert.ok(error instanceof JackError, `expected JackError, got ${String(error)}`);
    status = (error as JackError).httpStatus;
    code = (error as JackError).code;
  }
  const counts = store.state().counts;
  return {
    outcome: {
      status: committed ? 200 : status,
      code: committed ? "committed" : code,
      liveCount: counts.live, intentCount: counts.intents, tombstoneCount: counts.tombstones,
      highWater: store.state().meta.highWater,
      fenced: store.isFenced(),
      writes: store.diskWrites - writesBefore,
    },
    committed,
  };
}

function vectorReceipt(row: VectorRow, meta: DurableMetadata): DurableReceipt {
  const identity = syntheticIdentity(row.key);
  const signatureRaw = decodeBase64URLFixed(identity.signature, 64);
  const requestHash = bodyHash(Buffer.from(identity.signingBytes, "utf8"));
  // The mapping contract digests operation ids: feed the raw name in.
  const operationId = syntheticOperation(row.operationId ?? row.intentId);
  // The seeded loader forces ts - W <= highWater <= meta.highWater.
  const highWater = Math.max(Math.min(row.ts, meta.highWater), row.ts - WINDOW);
  return {
    version: 1, deploymentId: meta.deployment, storeGeneration: meta.generation, ownerGeneration: 1,
    intentId: intentIdOf(meta.deployment, decodeBase64URLFixed(identity.kid, 32),
      decodeBase64URLFixed(identity.nonce, 16), signatureRaw, decodeBase64URLFixed(requestHash, 32),
      decodeBase64URLFixed(operationId, 16)),
    operationId, kid: identity.kid, nonce: identity.nonce, signature: identity.signature, requestHash,
    timestamp: row.ts, retainUntil: row.retainUntil, highWater,
  };
}

function byPairKey(a: DurableReceipt, b: DurableReceipt): number {
  const keyA = pairKeyOf(decodeBase64URLFixed(a.kid, 32), decodeBase64URLFixed(a.nonce, 16));
  const keyB = pairKeyOf(decodeBase64URLFixed(b.kid, 32), decodeBase64URLFixed(b.nonce, 16));
  return Buffer.compare(keyA, keyB);
}

function jsonName(entry: JsonValue, fallback: string): string {
  return typeof entry === "object" && entry !== null && !Array.isArray(entry)
    ? String((entry as Record<string, JsonValue>)["intentId"])
    : fallback;
}

function buildDocument(state: VectorState): { document: DurableDocument; highWater: number } {
  const base: DurableMetadata = {
    deployment: DEPLOYMENT,
    storeId: encodeBase64URL(digest("candidate-vector/store").subarray(0, 16)),
    generation: 1, owner: 1, window: state.window, highWater: state.highWater,
    live: 0, intents: 0, tombstones: 0, dirty: false, unsafe: false,
  };
  const liveTimestamps = state.live.map((row) => row.ts);
  // DOCUMENTED DEVIATION: the loader forces H >= ts - W for every seeded row,
  // so the seeded high water is the minimal value satisfying that constraint
  // for the live rows and for the synthesized full-receipt tombstone rows.
  const highWater = Math.max(state.highWater, ...liveTimestamps.map((ts) => ts - WINDOW),
    state.tombstones.length > 0 || state.intents.length > 0 ? 100 - WINDOW : 0);
  const seeded: DurableMetadata = { ...base, highWater };
  const live = state.live.map((row) => vectorReceipt(row, seeded)).sort(byPairKey);
  const tombstones = state.tombstones.map((entry, index) =>
    vectorReceipt({ key: `kid-${jsonName(entry, `unknown-${index}`)}:nonce-${jsonName(entry, `unknown-${index}`)}`,
      intentId: jsonName(entry, `unknown-${index}`), ts: 100, retainUntil: 130 }, seeded))
    .sort(byPairKey);
  const intents = state.intents.map((entry, index) =>
    vectorReceipt({ key: `kid-${jsonName(entry, `intent-${index}`)}:nonce-${jsonName(entry, `intent-${index}`)}`,
      intentId: jsonName(entry, `intent-${index}`), ts: 100, retainUntil: 130 }, seeded))
    .sort(byPairKey);
  return {
    document: { meta: { ...seeded, live: live.length, intents: intents.length,
      tombstones: tombstones.length }, live, intents, tombstones },
    highWater,
  };
}

function simulateCrash(path: string): void {
  unlinkSync(path + ".owner");
}

function unavailableCode(error: unknown): boolean {
  return error instanceof JackError && error.code === "durability_unavailable";
}

test("shared nonce vectors: verdict table drives every case", { skip: !linux }, (context) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mcp-jack-nonce-vectors-")));
  chmodSync(root, 0o700);
  context.after(() => rmSync(root, { recursive: true, force: true }));

  for (const vector of vectors.cases) {
    const verdict = VERDICTS[vector.id];
    assert.ok(verdict, `vector ${vector.id} has no recorded verdict`);
    if (verdict.kind === "excluded") {
      assert.ok(verdict.reason.length > 40, `excluded vector ${vector.id} needs a spec-quoted reason`);
      continue;
    }
    const path = join(root, vector.id.replace(/[^a-zA-Z0-9-]/g, "-"));
    const events = vector.sequence ?? [vector.event as VectorEvent];
    const fault: Fault = {};
    // The store window is the seeded state window: the window vectors send a different request window.
    const harness = makeHarness(path, fault, vector.state?.window ?? WINDOW);
    let seededHighWater: number;
    if (vector.state === undefined) {
      // Sequence vectors have no seeded state: an empty initialized store.
      harness.queue(events[0]?.entryNow ?? 0);
      DurableNonceStore.initializeUnused(path, harness.config);
      harness.queue(events[0]?.entryNow ?? 0);
      seededHighWater = events[0]?.entryNow ?? 0;
    } else {
      const seeded = buildDocument(vector.state);
      DurableNonceStore.seedDocumentForTest(path, seeded.document);
      // Startup sample: never below the seeded (possibly deviated) high water.
      harness.queue(seeded.highWater);
      seededHighWater = seeded.highWater;
    }
    harness.store = DurableNonceStore.open(path, harness.config);

    const actual: Outcome[] = [];
    let committedTotal = 0;
    for (const event of events) {
      if (!event.authenticated) {
        // Pre-authentication refusal: the store is never contacted.
        actual.push({ status: 401, code: "bad_signature", liveCount: 0, intentCount: 0, tombstoneCount: 0,
          highWater: seededHighWater, fenced: false, writes: 0 });
        continue;
      }
      const step = driveEvent(harness, event, fault);
      committedTotal += step.committed ? 1 : 0;
      // The caller-level authorization refusal after a confirmed commit (a native tool answering 403).
      if (event.authorization === "refused" && step.committed) {
        actual.push({ ...step.outcome, status: 403, code: "authorization_refused" });
        continue;
      }
      actual.push(step.outcome);
    }

    const expect = vector.expect;
    const deviations = verdict.deviations ?? [];
    const statuses = (expect["statuses"] as readonly JsonValue[] | undefined) ??
      [[expect["status"], expect["code"]]];
    statuses.forEach((pair, index) => {
      const [status, code] = pair as [number, string];
      const outcome = actual[index] as Outcome;
      assert.equal(outcome.status, status, `vector ${vector.id} step ${index}: status`);
      assert.equal(outcome.code, code, `vector ${vector.id} step ${index}: code`);
    });
    if (typeof expect["confirmedCommits"] === "number") {
      assert.equal(committedTotal, expect["confirmedCommits"], `vector ${vector.id}: confirmedCommits`);
    }
    const final = actual[actual.length - 1] as Outcome;
    if (!deviations.includes("highWater")) {
      assert.equal(final.highWater, expect["highWater"], `vector ${vector.id}: highWater`);
    }
    if (expect["tombstoneOutcome"] === undefined) {
      // Counts are asserted pre-reconciliation; reconciled vectors assert below.
      assert.equal(final.liveCount, expect["liveCount"], `vector ${vector.id}: liveCount`);
      assert.equal(final.intentCount, expect["intentCount"], `vector ${vector.id}: intentCount`);
      assert.equal(final.tombstoneCount, expect["tombstoneCount"], `vector ${vector.id}: tombstoneCount`);
    }
    if (!deviations.includes("writes") && typeof expect["writes"] === "number") {
      assert.equal(final.writes, expect["writes"], `vector ${vector.id}: writes`);
    }
    if (expect["fenced"] === true) {
      assert.equal(final.fenced, true, `vector ${vector.id}: fenced`);
    }
    if (typeof expect["tombstoneOutcome"] === "string") {
      // Unknown outcomes reconcile through recovery inspect + reconcile to terminal tombstones.
      simulateCrash(path);
      assert.throws(() => DurableNonceStore.open(path, harness.config), unavailableCode,
        `vector ${vector.id}: reconciled store must refuse reopen`);
      const snapshot = DurableNonceStore.inspectRecovery(path, harness.config);
      const row = snapshot.live[0] ?? snapshot.intents[0];
      assert.ok(row, `vector ${vector.id}: recovery must find the surviving row`);
      assert.equal(snapshot.dirty, true, `vector ${vector.id}: recovery state keeps the dirty gate`);
      DurableNonceStore.reconcileUnknown(path, harness.config, snapshot.hash, row as DurableReceipt);
      const after = DurableNonceStore.inspectRecovery(path, harness.config);
      assert.equal(after.tombstones.length, expect["tombstoneCount"], `vector ${vector.id}: reconciled tombstones`);
      assert.equal(after.live.length + after.intents.length, 0, `vector ${vector.id}: no unresolved row remains`);
    }
    if (expect["reconciliation"] === "manual_fence") {
      // Unknown intent creation: reconciliation is manual, the fence stays.
      simulateCrash(path);
      assert.throws(() => DurableNonceStore.open(path, harness.config), unavailableCode,
        `vector ${vector.id}: manually fenced store must refuse reopen`);
      const snapshot = DurableNonceStore.inspectRecovery(path, harness.config);
      assert.equal(snapshot.live.length + snapshot.intents.length + snapshot.tombstones.length, 0,
        `vector ${vector.id}: nothing committed, nothing to reconcile`);
    }
    if (vector.id === "crash-after-commit-no-dispatch") {
      // Crash after the confirmed reservation: the pair is consumed, never auto-redelivered.
      simulateCrash(path);
      assert.throws(() => DurableNonceStore.open(path, harness.config), unavailableCode,
        "a crashed owner blocks reopen until operator recovery");
      const snapshot = DurableNonceStore.inspectRecovery(path, harness.config);
      assert.equal(snapshot.live.length, 1, "the committed pair is consumed across the crash");
      assert.equal(snapshot.dirty, true);
    }
    if (vector.id === "capacity-live-plus-intent") {
      assert.equal(vector.state?.live.length, 4096, "no live row was evicted");
    }
    if (vector.id === "commit-then-authorization-refusal") {
      const store = harness.store as DurableNonceStore;
      // The 403 is simulated at the caller level; the nonce stays consumed either way.
      assert.equal(store.state().counts.live, 1);
      assert.throws(() => store.reserve(admissionFor(events[0] as VectorEvent)),
        (error: unknown) => error instanceof JackError && error.code === "replayed_nonce");
    }
  }
});
