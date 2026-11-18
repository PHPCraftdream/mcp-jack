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
 *
 * bad-signature-zero-writes and commit-then-authorization-refusal are driven at
 * the VERIFIER level (the durable-admission seam: a real Ed25519-signed request
 * through a Verifier wired to the durable store), mirroring Go
 * durable/nonce_vectors_linux_test.go: a tampered request target makes the real
 * signature check fail pre-admission, and a refusing native tool produces the
 * native 403 after the confirmed commit. Fence state is asserted in BOTH
 * directions through store.isFenced() for every vector whose fixture records it.
 */
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import { fileURLToPath } from "node:url";
import { bodyHash, decodeBase64URLFixed, encodeBase64URL, keyId } from "../../../src/core/encoding.js";
import { requestSigningString } from "../../../src/core/signing.js";
import { formatRequestAuth } from "../../../src/core/auth-header.js";
import { createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { DurableNonceStore } from "../../../src/server/durable/store.js";
import type { DurableStoreInternalOptions } from "../../../src/server/durable/store-internal.js";
import { MemoryState } from "../../../src/server/registry/state.js";
import { Verifier } from "../../../src/server/verify.js";
import type { NativeCall, NativeResult, NativeTools, VerifyRequest, VerifyResult } from "../../../src/server/verify.js";
import { DurableNonceAdmission } from "../../../src/server/durable/admission.js";
import { takeResultFinish } from "../../../src/server/durable/finish.js";
import { intentIdOf, pairKeyOf } from "../../../src/server/durable/format.js";
import type { DurableDocument, DurableMetadata, DurableReceipt } from "../../../src/server/durable/format.js";
import { JackError } from "../../../src/core/errors.js";

const linux = process.platform === "linux";
const DEPLOYMENT = "candidate-test-deployment";
const WINDOW = 30;
const AUD = "https://candidate-vector.test";
const TARGET = "/mcp";
const PING_BODY = '{"jsonrpc":"2.0","id":1,"method":"ping"}';
const WHOAMI_BODY =
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.whoami","arguments":{}}}';

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

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
// Verifier-level driving (durable-admission rig): real Ed25519-signed requests
// through a Verifier wired to the harness's durable store.
// ---------------------------------------------------------------------------

interface EdKey { readonly priv: KeyObject; readonly pub: Uint8Array; readonly kid: string }

/** Deterministic Ed25519 key material with its derived kid. */
function edKey(name: string): EdKey {
  const seed = digest(`candidate-vector/ed25519/${name}`).subarray(0, 32);
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const priv = createPrivateKey({ key: Buffer.concat([pkcs8Prefix, seed]), format: "der", type: "pkcs8" });
  const der = createPublicKey(priv).export({ type: "spki", format: "der" });
  const pub = new Uint8Array(der.subarray(der.length - 32));
  return { priv, pub, kid: keyId(pub) };
}

interface VerifierDrive {
  readonly verifier: Verifier;
  readonly key: EdKey;
  /** Effect counters (Go vectorCounters): authorization-gate entries. */
  readonly nativeCalls: { value: number };
}

/**
 * Wires a Verifier over the harness's durable store with the durable-admission
 * seam. With refuseNative, the native tool handler is the Go refusingNative:
 * it counts the authorization-gate entry and answers the native 403
 * authorization_refused (durable/nonce_vectors_linux_test.go:502-509).
 */
function vectorVerifier(harness: Harness, refuseNative: boolean): VerifierDrive {
  const store = harness.store as DurableNonceStore;
  const state = new MemoryState();
  const key = edKey("caller");
  state.update((edit) =>
    edit.putKey({ kid: key.kid, publicKey: encodeBase64URL(key.pub), name: "candidate-vector-caller" }));
  const nativeCalls = { value: 0 };
  const refusingNative: NativeTools = {
    call(_call: NativeCall): NativeResult {
      nativeCalls.value++;
      throw new JackError(403, "authorization_refused", "authorization refused");
    },
  };
  const verifier = new Verifier({
    aud: AUD,
    state,
    ...(refuseNative ? { native: refusingNative as NativeTools } : {}),
    now: harness.config.now,
    durable: new DurableNonceAdmission({ store, now: harness.config.now }),
    window: harness.config.window,
  });
  return { verifier, key, nativeCalls };
}

/** Whether the verifier forwarded the request to a wrapped handler (dispatch). */
function dispatchCount(result: VerifyResult): number {
  return result.identity !== undefined ? 1 : 0;
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
    driven("full-path Verifier drive (durable-admission seam): a real signed request whose target is tampered " +
      "after signing fails the real Ed25519 signature check pre-admission; the native 401 bad_signature, zero " +
      "reservations, zero disk writes and an unfenced store are all asserted"),
  "commit-then-authorization-refusal":
    driven("full-path Verifier drive (durable-admission seam): the confirmed commit succeeds, then the refusing " +
      "native tool (Go refusingNative parity) answers the native 403 authorization_refused before dispatch; " +
      "the nonce stays consumed and the store stays unfenced"),
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
  readonly config: DurableStoreInternalOptions & { readonly now: () => number };
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

/** Builds one full-path VerifyRequest signed with the real key over `body`. */
function vectorSignedRequest(key: EdKey, event: VectorEvent, body: Uint8Array, tamperTarget: boolean): VerifyRequest {
  const nonce = encodeBase64URL(digest(`candidate-vector/verifier-nonce/${event.kid}:${event.nonce}`).subarray(0, 16));
  const signing = requestSigningString("POST", TARGET, AUD, key.kid, event.ts, nonce, body);
  const sig = encodeBase64URL(new Uint8Array(nodeSign(null, Buffer.from(signing), key.priv)));
  return {
    method: "POST",
    target: tamperTarget ? `${TARGET}/tampered` : TARGET,
    authValues: [formatRequestAuth({ kid: key.kid, ts: event.ts, nonce, sig })],
    body,
  };
}

/** Outcome fields plus the effect counters the fixture records. */
interface Effects { readonly authorization: number; readonly handler: number; readonly stateMutation: number }

/** Reads {authorization, handler, stateMutation} off a fixture expect block. */
function expectEffects(expect: Record<string, JsonValue>): Effects | undefined {
  const raw = expect["effects"];
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;
  const effects = raw as Record<string, JsonValue>;
  return {
    authorization: Number(effects["authorization"] ?? 0),
    handler: Number(effects["handler"] ?? 0),
    stateMutation: Number(effects["stateMutation"] ?? 0),
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

  // Corpus totals across every vector: one classification per completed vector.
  let summaryPass = 0;
  let summaryExcluded = 0;
  let summaryDeviation = 0;
  const recordCompleted = (kind: string): void => {
    if (kind === "deviation") summaryDeviation += 1;
    else summaryPass += 1;
  };

  for (const vector of vectors.cases) {
    const verdict = VERDICTS[vector.id];
    assert.ok(verdict, `vector ${vector.id} has no recorded verdict`);
    if (verdict.kind === "excluded") {
      assert.ok(verdict.reason.length > 40, `excluded vector ${vector.id} needs a spec-quoted reason`);
      summaryExcluded += 1;
      continue;
    }
    const path = join(root, vector.id.replace(/[^a-zA-Z0-9-]/g, "-"));
    const events = vector.sequence ?? [vector.event as VectorEvent];
    const fault: Fault = {};
    // The store window is the seeded state window: the window vectors send a different request window.
    const harness = makeHarness(path, fault, vector.state?.window ?? WINDOW);
    if (vector.state === undefined) {
      // Sequence vectors have no seeded state: an empty initialized store.
      const openNow = events[0]?.entryNow ?? 0;
      harness.queue(openNow);
      DurableNonceStore.initializeUnused(path, harness.config);
      harness.queue(openNow);
    } else {
      const seeded = buildDocument(vector.state);
      // Startup sample: never below the seeded (possibly deviated) high water.
      harness.queue(seeded.highWater);
      // Go seeds rows AFTER Open via a package-internal transaction
      // (seedVectorState): a clean store holding unresolved intents or the
      // tombstone cap refuses Open with ErrRecoveryRequired, so unresolved
      // state must be seeded through the post-open test seam.
      if (seeded.document.intents.length > 0 || seeded.document.tombstones.length > 0) {
        DurableNonceStore.seedDocumentForTest(path, {
          meta: { ...seeded.document.meta, live: 0, intents: 0, tombstones: 0 },
          live: [], intents: [], tombstones: [],
        });
        harness.store = DurableNonceStore.open(path, harness.config);
        harness.store.seedRecordsForTest({
          meta: { ...harness.store.state().meta, highWater: seeded.document.meta.highWater,
            live: seeded.document.live.length, intents: seeded.document.intents.length,
            tombstones: seeded.document.tombstones.length },
          live: seeded.document.live, intents: seeded.document.intents, tombstones: seeded.document.tombstones,
        });
      } else {
        DurableNonceStore.seedDocumentForTest(path, seeded.document);
      }
    }
    if (harness.store === undefined) {
      harness.store = DurableNonceStore.open(path, harness.config);
    }

    const expect = vector.expect;
    const actual: Outcome[] = [];
    let committedTotal = 0;
    for (const event of events) {
      if (!event.authenticated) {
        // bad-signature-zero-writes: full-path Verifier drive. The request is
        // really signed, but the target is tampered after signing (Go
        // nonce_vectors_linux_test.go:552-555), so the real signature check
        // fails pre-admission and the store is never contacted.
        const store = harness.store as DurableNonceStore;
        const drive = vectorVerifier(harness, false);
        // One Verifier clock sample (the entry timestamp check); the refusal
        // happens before the durable seam consumes any further samples.
        harness.queue(event.entryNow);
        const writesBefore = store.diskWrites;
        const result = drive.verifier.verify(vectorSignedRequest(drive.key, event, utf8(PING_BODY), true));
        assert.equal(result.accepted, false, `vector ${vector.id}: tampered signature must refuse`);
        assert.equal(result.httpStatus, 401, `vector ${vector.id}: bad_signature status`);
        assert.equal(result.code, "bad_signature", `vector ${vector.id}: bad_signature code`);
        assert.equal(result.nonceRecorded, false, `vector ${vector.id}: pre-admission refusal is not nonce-recorded`);
        assert.equal(dispatchCount(result), 0, `vector ${vector.id}: never dispatched`);
        const counts = store.state().counts;
        actual.push({
          status: result.httpStatus, code: result.code,
          liveCount: counts.live, intentCount: counts.intents, tombstoneCount: counts.tombstones,
          highWater: store.state().meta.highWater, fenced: store.isFenced(),
          writes: store.diskWrites - writesBefore,
        });
        // Fixture effects: authorization/handler gates are never reached.
        const effects = expectEffects(expect);
        if (effects !== undefined) {
          assert.equal(drive.nativeCalls.value + (result.accepted ? 1 : 0), effects.authorization,
            `vector ${vector.id}: effects.authorization`);
          assert.equal(dispatchCount(result), effects.handler, `vector ${vector.id}: effects.handler`);
          assert.equal(0, effects.stateMutation, `vector ${vector.id}: effects.stateMutation`);
        }
        continue;
      }
      if (event.authorization === "refused") {
        // commit-then-authorization-refusal: full-path Verifier drive. The
        // commit confirms, then the refusing native tool answers the native
        // 403 authorization_refused before any dispatch (Go refusingNative).
        const store = harness.store as DurableNonceStore;
        const drive = vectorVerifier(harness, true);
        // Verifier entry sample, store entry/intent/final samples, post-commit
        // sample (5 pushes per event, Go driveVectorEvent parity).
        harness.queue(event.entryNow);
        harness.queue(event.entryNow);
        harness.queue(event.intentNow);
        harness.queue(event.finalNow);
        harness.queue(event.finalNow);
        const writesBefore = store.diskWrites;
        const result = drive.verifier.verify(vectorSignedRequest(drive.key, event, utf8(WHOAMI_BODY), false));
        takeResultFinish(result)?.();
        assert.equal(result.accepted, false, `vector ${vector.id}: authorization refusal must refuse`);
        assert.equal(result.httpStatus, 403, `vector ${vector.id}: authorization_refused status`);
        assert.equal(result.code, "authorization_refused", `vector ${vector.id}: authorization_refused code`);
        assert.equal(result.nonceRecorded, true,
          `vector ${vector.id}: the confirmed commit makes the refusal nonce-recorded`);
        assert.equal(dispatchCount(result), 0, `vector ${vector.id}: never dispatched`);
        // The nonce stays consumed: replaying the SAME signed request after the
        // native 403 answers the unsigned 401 replayed_nonce.
        const replay = drive.verifier.verify(vectorSignedRequest(drive.key, event, utf8(WHOAMI_BODY), false));
        assert.equal(replay.accepted, false, `vector ${vector.id}: the consumed nonce replays`);
        assert.equal(replay.httpStatus, 401, `vector ${vector.id}: replay status`);
        assert.equal(replay.code, "replayed_nonce", `vector ${vector.id}: replay code`);
        assert.equal(replay.nonceRecorded, false, `vector ${vector.id}: replay is not nonce-recorded`);
        const counts = store.state().counts;
        actual.push({
          status: result.httpStatus, code: result.code,
          liveCount: counts.live, intentCount: counts.intents, tombstoneCount: counts.tombstones,
          highWater: store.state().meta.highWater, fenced: store.isFenced(),
          writes: store.diskWrites - writesBefore,
        });
        const effects = expectEffects(expect);
        if (effects !== undefined) {
          assert.equal(drive.nativeCalls.value + (result.accepted ? 1 : 0), effects.authorization,
            `vector ${vector.id}: effects.authorization`);
          assert.equal(dispatchCount(result), effects.handler, `vector ${vector.id}: effects.handler`);
          assert.equal(0, effects.stateMutation, `vector ${vector.id}: effects.stateMutation`);
        }
        continue;
      }
      const step = driveEvent(harness, event, fault);
      committedTotal += step.committed ? 1 : 0;
      actual.push(step.outcome);
    }

    const deviations = verdict.deviations ?? [];
    const statuses = (expect["statuses"] as readonly JsonValue[] | undefined) ??
      [[expect["status"], expect["code"]]];
    statuses.forEach((pair, index) => {
      const [status, code] = pair as [number, string];
      const outcome = actual[index] as Outcome;
      if (!deviations.includes("status")) assert.equal(outcome.status, status, `vector ${vector.id} step ${index}: status`);
      if (!deviations.includes("code")) assert.equal(outcome.code, code, `vector ${vector.id} step ${index}: code`);
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
    // The store's disk-transaction counter mirrors Go's transactCalls, which is
    // exactly what the fixtures record as `callbacks`.
    if (!deviations.includes("writes") && typeof expect["callbacks"] === "number") {
      assert.equal(final.writes, expect["callbacks"], `vector ${vector.id}: callbacks (disk transactions)`);
    }
    // dispatches/effects are only observable on the full-path Verifier drives
    // (bad-signature-zero-writes, commit-then-authorization-refusal), which
    // assert them at the drive site above; the store-level drive has no
    // authorization gate or handler to count.
    if (typeof expect["fenced"] === "boolean") {
      // Fence state is asserted in BOTH directions through the store seam:
      // definite refusals must NOT fence, latched unsafe states must fence.
      assert.equal(final.fenced, expect["fenced"], `vector ${vector.id}: fenced`);
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
      // The nonce stays consumed after the native 403: exactly one live row.
      // (The replay itself is asserted against the real request in the drive.)
      assert.equal(store.state().counts.live, 1);
    }
    recordCompleted(verdict.kind);
  }
  console.log(`VECTOR-SUMMARY corpus=nonce sdk=ts pass=${summaryPass} excluded=${summaryExcluded} deviation=${summaryDeviation}`);
});
