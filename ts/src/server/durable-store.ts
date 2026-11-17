/**
 * Durable authenticated nonce store for Node (candidate profile,
 * spec/candidate/durable-nonces.md), behaviourally mirroring the Go reference
 * in durable/. Linux-gated like the rotation stores: exclusive lifetime owner
 * via an owner marker file, one sealed document rewritten atomically
 * (temp + fsync + rename) per transaction, strict load on open, durable
 * high-water mark with an unsafe latch, bounded purge, unknown-outcome
 * tombstones and explicit recovery inspect/reconcile. Callbacks (clock,
 * validator) are never invoked inside a commit; the final commit is never
 * retried; an unknown commit outcome fences the owner.
 */
import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, fsyncSync, openSync, renameSync, statSync, unlinkSync,
  writeSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { RotationFileOwner } from "../rotation-file.js";
import { bodyHash, decodeBase64URLFixed } from "../encoding.js";
import { JackError } from "../errors.js";
import { RotationError } from "../rotation-record.js";
import {
  DURABLE_MAX_COMBINED, DURABLE_MAX_PURGE, DURABLE_MAX_TIMESTAMP, DURABLE_MAX_TOMBSTONES, DURABLE_FORMAT_VERSION,
  decodeDocument, durableAdmissionError, durableUnavailable, encodeDocument, findSorted, insertSorted, intentIdOf,
  pairKeyOf, removeSorted, sortKeyOf, validateReceipt,
} from "./durable-format.js";
import type { DurableDocument, DurableMetadata, DurableReceipt, DurableRecordKind } from "./durable-format.js";

/** Go ErrRecoveryRequired: explicit recovery required; a restart never clears it. */
function recoveryRequired(): JackError {
  return new JackError(503, "durability_unavailable", "durable: recovery required");
}

/** Go ErrInvalidStore: the file does not match the given deployment/window options. */
function invalidStore(): Error {
  return new Error("durable: invalid store");
}

/** Deployment binding and injected clock; invalid options refuse initialization. */
export interface DurableStoreOptions {
  readonly deploymentId: string;
  /** Immutable window W in seconds, 1..120 (spec section 2). */
  readonly window: number;
  /** Raw clock; defaults to wall time. Injected by tests. */
  readonly now?: () => number;
  /**
   * Test/recovery fault seam: called before each intent/final commit.
   * "commit" reports unknown AFTER a successful commit; "abort" reports
   * unknown without committing. Returning undefined commits normally.
   */
  readonly injectTransactionFailure?: (phase: "intent" | "final") => "commit" | "abort" | undefined;
  /** Test-only seam: operation id to allocate; Go retries a collision once (durable/admit.go). */
  readonly injectOperationId?: () => string;
}

/** One authenticated admission (post-signature; spec section 2 ordering). */
export interface DurableNonceAdmission {
  readonly kid: string;
  readonly nonce: string;
  readonly signature: string;
  /** Exact UTF-8 v1 request signing bytes S. */
  readonly signingBytes: string;
  readonly timestamp: number;
  /** Immutable configured window; must equal the store's W. */
  readonly window: number;
  /** Snapshot/validity revalidation inside every authoritative sample. */
  readonly validate: (now: number) => boolean;
}

/** Confirmed reservation plus its serving lease; the pair stays consumed. */
export interface DurableNonceReservation {
  readonly receipt: DurableReceipt;
  /** Idempotent lease release; the reservation itself is never released. */
  release(): void;
}

/** Owned recovery diagnostics; not an admission receipt or reopen permission. */
export interface DurableRecoverySnapshot {
  readonly deployment: string;
  readonly storeId: string;
  readonly generation: number;
  readonly owner: number;
  readonly window: number;
  readonly highWater: number;
  readonly dirty: boolean;
  readonly unsafe: boolean;
  readonly live: readonly DurableReceipt[];
  readonly intents: readonly DurableReceipt[];
  readonly tombstones: readonly DurableReceipt[];
  /** Binds the full logical graph; not a MAC and not rollback-proof evidence. */
  readonly hash: string;
}

const SNAP_DOMAIN = "mcp-jack/durable-nonce/recovery-snapshot/v1\n";

/** Ordered record groups, mirroring the Go bucket order. */
const GROUPS: readonly { readonly name: "live" | "intents" | "tombstones"; readonly kind: DurableRecordKind }[] =
  [{ name: "live", kind: "live" }, { name: "intents", kind: "intent" }, { name: "tombstones", kind: "tombstone" }];

function normalized(options: DurableStoreOptions): { deploymentId: string; window: number; now: () => number;
  injectTransactionFailure: DurableStoreOptions["injectTransactionFailure"];
  injectOperationId: DurableStoreOptions["injectOperationId"] } {
  const bytes = Buffer.byteLength(options.deploymentId ?? "", "utf8");
  if (bytes === 0 || bytes > 1024 || !Number.isSafeInteger(options.window) || options.window < 1 || options.window > 120) {
    throw durableUnavailable();
  }
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  return { deploymentId: options.deploymentId, window: options.window, now,
    injectTransactionFailure: options.injectTransactionFailure,
    injectOperationId: options.injectOperationId };
}

/** Snapshot hash: length-framed fields over the full logical graph. */
function snapshotHash(doc: DurableDocument): string {
  const hash = createHash("sha256");
  hash.update(SNAP_DOMAIN, "ascii");
  const field = (value: Uint8Array | string): void => {
    const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length);
    hash.update(bytes);
  };
  const meta = { deployment: doc.meta.deployment, store_id: doc.meta.storeId, generation: doc.meta.generation,
    owner: doc.meta.owner, window: doc.meta.window, high_water: doc.meta.highWater,
    dirty: doc.meta.dirty, unsafe: doc.meta.unsafe };
  field(JSON.stringify(meta));
  for (const group of GROUPS) {
    field(group.name);
    const count = Buffer.alloc(4);
    count.writeUInt32BE(doc[group.name].length);
    hash.update(count);
    for (const row of doc[group.name]) {
      field(pairKeyOf(decodeBase64URLFixed(row.kid, 32), decodeBase64URLFixed(row.nonce, 16)));
      field(row.intentId);
      field(row.operationId);
    }
  }
  return Buffer.from(hash.digest()).toString("base64url");
}

function receiptsEqual(a: DurableReceipt, b: DurableReceipt): boolean {
  return a.intentId === b.intentId && a.operationId === b.operationId && a.kid === b.kid && a.nonce === b.nonce &&
    a.signature === b.signature && a.requestHash === b.requestHash && a.timestamp === b.timestamp &&
    a.retainUntil === b.retainUntil && a.highWater === b.highWater && a.storeGeneration === b.storeGeneration &&
    a.ownerGeneration === b.ownerGeneration && a.deploymentId === b.deploymentId && a.version === b.version;
}

function withMeta(work: WorkingDoc, changes: Partial<DurableMetadata>): void {
  work.meta = { ...work.meta, ...changes };
}

/** Read-only document view used by lookups. */
export interface DocView {
  readonly meta: DurableMetadata;
  readonly live: readonly DurableReceipt[];
  readonly intents: readonly DurableReceipt[];
  readonly tombstones: readonly DurableReceipt[];
}

/** Mutable working copy handed to one transaction callback (fields reassigned, never aliased). */
interface WorkingDoc extends DocView {
  meta: DurableMetadata;
  live: DurableReceipt[];
  intents: DurableReceipt[];
  tombstones: DurableReceipt[];
}

function cloneDoc(doc: DocView): WorkingDoc {
  return { meta: doc.meta, live: [...doc.live], intents: [...doc.intents], tombstones: [...doc.tombstones] };
}

/**
 * Closed-store I/O for recovery: whole-file read and atomic replace
 * (temp + fsync + rename + directory fsync), mirroring the rotation-file
 * discipline. No owner marker is taken; the caller refuses while one exists.
 */
function replaceClosed(path: string, bytes: Uint8Array): void {
  const temporary = join(dirname(path), `.${basename(path)}.${randomBytes(16).toString("hex")}.tmp`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    let position = 0;
    while (position < bytes.length) {
      const count = writeSync(fd, bytes, position, bytes.length - position, position);
      if (count === 0) throw new Error("durable: short write");
      position += count;
    }
    if (statSync(temporary).size !== bytes.length) throw new Error("durable: size mismatch");
    fsyncSync(fd);
  } catch (error) {
    try { unlinkSync(temporary); } catch { /* Unknown artifact stays fenced. */ }
    throw error;
  } finally {
    closeSync(fd);
  }
  renameSync(temporary, path);
  const dir = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(dir); } finally { closeSync(dir); }
}

export class DurableNonceStore {
  private fenced = false;
  private closing = false;
  private closed = false;
  private leases = 0;
  private samples = 0;
  private writes = 0;

  private constructor(private readonly file: RotationFileOwner, private readonly path: string,
    private readonly options: { deploymentId: string; window: number; now: () => number;
      injectTransactionFailure: DurableStoreOptions["injectTransactionFailure"];
      injectOperationId: DurableStoreOptions["injectOperationId"] },
    private doc: DurableDocument, private bytes: Uint8Array) {}

  /** Clock samples taken since open (test instrumentation). */
  get clockSamples(): number { return this.samples; }

  /** Committed disk rewrites since open (test instrumentation). */
  get diskWrites(): number { return this.writes; }

  /**
   * Explicit out-of-band initialization for a provably unused deployment
   * (spec section 3). Never replaces an existing store; the dirty marker is
   * confirmed before the first clock callback.
   */
  static initializeUnused(path: string, input: DurableStoreOptions): void {
    const options = normalized(input);
    const doc: DurableDocument = {
      meta: { deployment: options.deploymentId, storeId: randomBytes(16).toString("base64url"), generation: 1,
        owner: 1, window: options.window, highWater: 0, live: 0, intents: 0, tombstones: 0, dirty: true, unsafe: false },
      live: [], intents: [], tombstones: [],
    };
    const initial = encodeDocument(doc);
    let file: RotationFileOwner;
    try {
      file = RotationFileOwner.createUnusedOwner(path, initial);
    } catch {
      throw durableUnavailable();
    }
    try {
      const now = options.now();
      if (!Number.isSafeInteger(now) || now < 0 || now > DURABLE_MAX_TIMESTAMP) throw new Error("durable: clock");
      const ready: DurableDocument = { meta: { ...doc.meta, highWater: now, dirty: false },
        live: [], intents: [], tombstones: [] };
      file.replace(initial, encodeDocument(ready));
      file.close();
    } catch {
      file.fence();
      throw durableUnavailable();
    }
  }

  /**
   * Opens only an existing clean store; dirty/unsafe startup stays closed
   * until explicit recovery. Bumps the owner generation and re-establishes the
   * dirty epoch before the startup clock sample (spec section 3).
   */
  static open(path: string, input: DurableStoreOptions): DurableNonceStore {
    const options = normalized(input);
    let file: RotationFileOwner;
    try {
      file = RotationFileOwner.open(path);
    } catch {
      throw durableUnavailable();
    }
    let mutation = false;
    try {
      const bytes = file.read();
      const loaded = decodeDocument(bytes);
      if (loaded.meta.deployment !== options.deploymentId || loaded.meta.window !== options.window ||
        loaded.meta.dirty || loaded.meta.unsafe) {
        throw durableUnavailable();
      }
      // Go readStoreSnapshot (durable/snapshot.go): a CLEAN store that still
      // holds unresolved intents or sits at the tombstone cap refuses with
      // ErrRecoveryRequired; only recovery inspect/reconcile may load it.
      if (loaded.meta.intents !== 0 || loaded.meta.tombstones >= DURABLE_MAX_TOMBSTONES) {
        throw recoveryRequired();
      }
      const marked: DurableDocument = {
        meta: { ...loaded.meta, owner: loaded.meta.owner + 1, dirty: true },
        live: loaded.live, intents: loaded.intents, tombstones: loaded.tombstones };
      const nextBytes = encodeDocument(marked);
      file.replace(bytes, nextBytes);
      mutation = true;
      const store = new DurableNonceStore(file, path, options, marked, nextBytes);
      store.startupClock();
      return store;
    } catch (error) {
      if (mutation) file.fence();
      try { file.close(); } catch { /* Unknown/dirty marker remains a startup gate. */ }
      if (error instanceof JackError) throw error;
      throw durableUnavailable();
    }
  }

  /** First confirm the dirty marker, then observe the startup clock (Go openStore). */
  private startupClock(): void {
    const now = this.sample();
    if (!Number.isSafeInteger(now) || now < 0 || now > DURABLE_MAX_TIMESTAMP || now < this.doc.meta.highWater) {
      const latched: DurableDocument = { meta: { ...this.doc.meta, unsafe: true },
        live: this.doc.live, intents: this.doc.intents, tombstones: this.doc.tombstones };
      this.commit(latched);
      throw durableAdmissionError(503, "clock_unsafe");
    }
    this.commit({ meta: { ...this.doc.meta, highWater: now },
      live: this.doc.live, intents: this.doc.intents, tombstones: this.doc.tombstones });
  }

  // -------------------------------------------------------------------------
  // Transaction machinery (mirrors durable/transaction.go).
  // -------------------------------------------------------------------------

  /**
   * One atomic document rewrite. A callback rejection is a definite abort with
   * no write; any other failure (including injected unknowns) fences the
   * owner and reports durability_unavailable.
   */
  private transact(phase: "intent" | "final" | "recovery",
    apply: (work: WorkingDoc) => JackError | undefined): void {
    if (this.fenced || this.closing || this.closed) throw durableUnavailable();
    const work = cloneDoc(this.doc);
    const rejection = apply(work);
    if (rejection !== undefined) {
      // Only unavailable/clock_unsafe rejections fence (Go update()).
      if (rejection.code === "durability_unavailable" || rejection.code === "clock_unsafe") this.fenced = true;
      throw rejection;
    }
    const injection = phase === "recovery" ? undefined : this.options.injectTransactionFailure?.(phase);
    if (injection === "abort") {
      this.fenced = true;
      throw durableUnavailable();
    }
    this.commit({ meta: work.meta, live: work.live, intents: work.intents, tombstones: work.tombstones });
    if (injection === "commit") {
      this.fenced = true;
      throw durableUnavailable();
    }
  }

  /** One committed rewrite of the whole bounded document. */
  private commit(next: DurableDocument): void {
    const nextBytes = encodeDocument(next);
    try {
      this.file.replace(this.bytes, nextBytes);
    } catch {
      this.fenced = true;
      throw durableUnavailable();
    }
    this.writes++;
    this.doc = next;
    this.bytes = nextBytes;
  }

  /** Replay/intent lookup (Go replayLookup): live duplicate, unresolved intent or tombstone. */
  private lookup(doc: DocView, key: string, now: number): JackError | undefined {
    const live = findSorted(doc.live, key);
    if (live !== undefined && now <= live.retainUntil) {
      return durableAdmissionError(401, "replayed_nonce");
    }
    if (findSorted(doc.intents, key) !== undefined || findSorted(doc.tombstones, key) !== undefined) {
      return durableUnavailable();
    }
    return undefined;
  }

  /**
   * Bounded expiry purge with durable H advancement (Go purgeExpired): the
   * exact pair shares the 128-row batch cap and is never dropped beyond it;
   * no absence decision precedes the H receipt.
   */
  private purge(work: WorkingDoc, now: number, key: string): void {
    if (now < work.meta.highWater) throw new Error("durable: purge below high water");
    withMeta(work, { highWater: now });
    const expired = work.live
      .filter((row) => row.retainUntil < now)
      .sort((a, b) => a.retainUntil - b.retainUntil || (sortKeyOf(a) < sortKeyOf(b) ? -1 : 1));
    const batch: string[] = [];
    const exact = expired.find((row) => sortKeyOf(row) === key);
    if (exact !== undefined) batch.push(sortKeyOf(exact));
    for (const row of expired) {
      if (batch.length >= DURABLE_MAX_PURGE) break;
      const rowKey = sortKeyOf(row);
      if (rowKey !== key && !batch.includes(rowKey)) batch.push(rowKey);
    }
    for (const rowKey of batch) {
      work.live = removeSorted(work.live, rowKey);
      withMeta(work, { live: work.meta.live - 1 });
    }
  }

  /** One raw clock sample plus H/freshness/validate checks (Go checkSample). */
  private checkSample(request: DurableNonceAdmission, prepared: DurableReceipt | undefined, now: number): void {
    if (this.fenced || this.closing || this.closed) throw durableUnavailable();
    if (!Number.isSafeInteger(now) || now < 0 || now > DURABLE_MAX_TIMESTAMP || now < this.doc.meta.highWater) {
      this.transact("recovery", (work) => {
        if (prepared !== undefined) {
          const key = sortKeyOf(prepared);
          const exact = findSorted(work.intents, key);
          if (exact === undefined || !receiptsEqual(exact, prepared)) return durableUnavailable();
          work.intents = removeSorted(work.intents, key);
          withMeta(work, { intents: work.meta.intents - 1 });
        }
        withMeta(work, { unsafe: true });
        return undefined;
      });
      this.fenced = true;
      throw durableAdmissionError(503, "clock_unsafe");
    }
    let rejection: JackError | undefined;
    if (!request.validate(now)) {
      rejection = durableAdmissionError(503, "state_changed");
    } else {
      const difference = now - request.timestamp;
      if (difference > request.window || -difference > request.window) {
        rejection = durableAdmissionError(401, "timestamp_out_of_window");
      }
    }
    if (rejection !== undefined && prepared !== undefined) {
      // Confirmed intent cleanup before reporting the step's status.
      this.transact("recovery", (work) => {
        const key = sortKeyOf(prepared);
        if (findSorted(work.intents, key) === undefined) return durableUnavailable();
        work.intents = removeSorted(work.intents, key);
        withMeta(work, { intents: work.meta.intents - 1 });
        return undefined;
      });
    }
    if (rejection !== undefined) throw rejection;
  }

  /**
   * The reservation wrapper (Go Reserve, durable/admit.go:33-46): ANY
   * unexpected non-JackError failure inside the transaction (a throwing
   * injected clock, a plain Error from validation/purge/insertion) fences the
   * store BEFORE reporting, and surfaces as the same durability_unavailable
   * the adapter maps unknown failures to. Definite rejections (JackError)
   * keep today's behaviour: only their unavailable/clock_unsafe codes fence
   * in place, so the committed state stays consistent with the fence.
   */
  reserve(request: DurableNonceAdmission): DurableNonceReservation {
    try {
      return this.reserveLocked(request);
    } catch (error) {
      if (error instanceof JackError) throw error;
      this.fenced = true;
      throw durableUnavailable();
    }
  }

  /**
   * The reservation path (Go reserveLocked): entry sample, replay lookup,
   * intent transaction, final sample and final transaction. Exactly three
   * clock samples per admission. Unresolved commit outcomes fence the store.
   */
  private reserveLocked(request: DurableNonceAdmission): DurableNonceReservation {
    if (this.fenced || this.closing || this.closed) throw durableUnavailable();
    if (request.window !== this.doc.meta.window) throw durableAdmissionError(503, "state_changed");
    if (!Number.isSafeInteger(request.timestamp) || request.timestamp < 0 ||
      request.timestamp > DURABLE_MAX_TIMESTAMP - this.doc.meta.window) {
      throw durableAdmissionError(401, "timestamp_out_of_window");
    }
    let kidRaw: Uint8Array;
    let nonceRaw: Uint8Array;
    let signatureRaw: Uint8Array;
    try {
      kidRaw = decodeBase64URLFixed(request.kid, 32);
      nonceRaw = decodeBase64URLFixed(request.nonce, 16);
      signatureRaw = decodeBase64URLFixed(request.signature, 64);
    } catch {
      this.fenced = true;
      throw durableUnavailable();
    }
    const key = pairKeyOf(kidRaw, nonceRaw).toString("latin1");
    const entryNow = this.sample();
    this.checkSample(request, undefined, entryNow);
    // Replay lookup at the entry sample: a read; a live duplicate is unsigned and writes nothing.
    const replay = this.lookup(this.doc, key, entryNow);
    if (replay !== undefined) {
      if (replay.code === "durability_unavailable") this.fenced = true;
      throw replay;
    }
    // Go retries a colliding operation id once (durable/admit.go: two rand
    // attempts) before fencing: spec section 1 says allocate a new id on
    // collision, before any intent commit. A second collision still fences.
    let operationId = "";
    let unique = false;
    for (let attempt = 0; attempt < 2; attempt++) {
      operationId = this.options.injectOperationId !== undefined
        ? this.options.injectOperationId()
        : randomBytes(16).toString("base64url");
      unique = !this.operationTaken(operationId);
      if (unique) break;
    }
    if (!unique) {
      this.fenced = true;
      throw durableUnavailable();
    }
    const requestHash = bodyHash(Buffer.from(request.signingBytes, "utf8"));
    const intentId = intentIdOf(this.doc.meta.deployment, kidRaw, nonceRaw, signatureRaw,
      decodeBase64URLFixed(requestHash, 32), decodeBase64URLFixed(operationId, 16));
    const intentNow = this.sample();
    this.checkSample(request, undefined, intentNow);
    const prepared: DurableReceipt = {
      version: DURABLE_FORMAT_VERSION, deploymentId: this.doc.meta.deployment,
      storeGeneration: this.doc.meta.generation, ownerGeneration: this.doc.meta.owner,
      intentId, operationId, kid: request.kid, nonce: request.nonce, signature: request.signature,
      requestHash, timestamp: request.timestamp, retainUntil: request.timestamp + request.window, highWater: intentNow,
    };
    this.transact("intent", (work) => {
      const replayed = this.lookup(work, key, intentNow);
      if (replayed !== undefined) return replayed;
      this.purge(work, intentNow, key);
      // The intent sample advanced H first (spec section 3), so the prepared row is checked against it.
      validateReceipt(prepared, work.meta);
      if (work.meta.live + work.meta.intents >= DURABLE_MAX_COMBINED ||
        work.meta.tombstones >= DURABLE_MAX_TOMBSTONES) {
        return durableAdmissionError(503, "capacity_exhausted");
      }
      if (this.operationTakenIn(work, operationId)) return durableUnavailable();
      work.intents = insertSorted(work.intents, prepared);
      withMeta(work, { intents: work.meta.intents + 1 });
      return undefined;
    });
    const finalNow = this.sample();
    this.checkSample(request, prepared, finalNow);
    const committed: DurableReceipt = { ...prepared, highWater: finalNow };
    this.transact("final", (work) => {
      const exact = findSorted(work.intents, key);
      if (exact === undefined || !receiptsEqual(exact, prepared)) return durableUnavailable();
      if (work.meta.intents === 0 || work.meta.live >= DURABLE_MAX_COMBINED) return durableUnavailable();
      withMeta(work, { highWater: finalNow });
      validateReceipt(committed, work.meta);
      work.intents = removeSorted(work.intents, key);
      work.live = insertSorted(work.live, committed);
      withMeta(work, { intents: work.meta.intents - 1, live: work.meta.live + 1 });
      return undefined;
    });
    this.leases++;
    let released = false;
    return {
      receipt: committed,
      release: (): void => {
        if (released) return;
        released = true;
        this.leases--;
      },
    };
  }

  private sample(): number {
    this.samples++;
    return this.options.now();
  }

  private operationTaken(operationId: string): boolean {
    return GROUPS.some((group) => this.doc[group.name].some((row) => row.operationId === operationId));
  }

  private operationTakenIn(work: DocView, operationId: string): boolean {
    return GROUPS.some((group) => work[group.name].some((row) => row.operationId === operationId));
  }

  /** Refuse further operations; an already-dirty marker closes the next startup. */
  fence(): void { this.fenced = true; }

  /**
   * Stops admission and clears dirty only when not fenced and no unresolved
   * state remains (Go Close). Outstanding leases refuse before anything
   * changes (a synchronous close cannot wait); retry after they drain. The
   * owner marker is released either way (Go releases the bbolt lock, Rust its
   * marker): a fenced store stays fail-closed through its persisted dirty
   * epoch and reports recovery-required.
   */
  close(): void {
    if (this.closed) return;
    if (this.leases > 0) throw durableUnavailable();
    this.closing = true;
    let failure: JackError | undefined;
    if (!this.fenced && (this.doc.meta.intents !== 0 ||
      this.doc.meta.tombstones >= DURABLE_MAX_TOMBSTONES || this.doc.meta.unsafe)) {
      this.fenced = true;
    }
    if (this.fenced) {
      failure = recoveryRequired();
    } else {
      try {
        this.commit({ meta: { ...this.doc.meta, dirty: false },
          live: this.doc.live, intents: this.doc.intents, tombstones: this.doc.tombstones });
      } catch {
        this.fenced = true;
        failure = durableUnavailable();
      }
    }
    try {
      this.file.release();
    } catch {
      this.fenced = true;
      failure ??= durableUnavailable();
    }
    this.closed = true;
    this.closing = false;
    if (failure !== undefined) throw failure;
  }

  /** Whether the owner is durably fenced (test/diagnostic view). */
  isFenced(): boolean { return this.fenced; }

  /** Committed in-memory view for diagnostics and tests (not a fresh read). */
  state(): DocView & { readonly counts: { live: number; intents: number; tombstones: number } } {
    return { meta: this.doc.meta, live: this.doc.live, intents: this.doc.intents, tombstones: this.doc.tombstones,
      counts: { live: this.doc.live.length, intents: this.doc.intents.length, tombstones: this.doc.tombstones.length } };
  }

  // -------------------------------------------------------------------------
  // Recovery operations (durable/recovery_inspect.go, recovery_reconcile.go).
  // -------------------------------------------------------------------------

  /**
   * Test/recovery seeding seam: writes one exact abstract document (live,
   * intent and tombstone rows) into a closed store path. Shared-vector and
   * restart tests seed state through package-internal record types here.
   */
  static seedDocumentForTest(path: string, doc: DurableDocument): void {
    replaceClosed(path, encodeDocument(doc));
  }

  /**
   * TEST-ONLY seam (mirrors Go seedVectorState / Rust seed_records): writes
   * one exact abstract document (live, intent and tombstone rows) into an
   * ALREADY-OPEN store as a single atomic owner-checked rewrite. Go seeds rows
   * after Open through package-internal transactions; never call from
   * production code paths.
   */
  seedRecordsForTest(doc: DurableDocument): void {
    const nextBytes = encodeDocument(doc);
    this.file.replace(this.bytes, nextBytes);
    this.writes++;
    this.doc = doc;
    this.bytes = nextBytes;
  }

  /** Read-only recovery inspection of a closed store. The exclusive owner
   * marker is taken even for inspection (Go InspectRecovery: "the exclusive
   * owner lock is required even for inspection") and the file is read through
   * the same private-file checks the open path uses. No clock callbacks and no
   * metadata change; serving admission is not opened.
   */
  static inspectRecovery(path: string, input: DurableStoreOptions): DurableRecoverySnapshot {
    const options = normalized(input);
    let file: RotationFileOwner;
    try {
      file = RotationFileOwner.open(path);
    } catch {
      // A live owner or an unusable private path reports unavailable (Go ErrUnavailable).
      throw durableUnavailable();
    }
    try {
      const doc = decodeDocument(file.read());
      // Go loadRecoverySnapshot: a deployment or window mismatch is ErrInvalidStore.
      if (doc.meta.deployment !== options.deploymentId || doc.meta.window !== options.window) {
        throw invalidStore();
      }
      const snapshot: DurableRecoverySnapshot = {
        deployment: doc.meta.deployment, storeId: doc.meta.storeId, generation: doc.meta.generation,
        owner: doc.meta.owner, window: doc.meta.window, highWater: doc.meta.highWater,
        dirty: doc.meta.dirty, unsafe: doc.meta.unsafe,
        live: doc.live, intents: doc.intents, tombstones: doc.tombstones, hash: snapshotHash(doc),
      };
      file.close();
      return snapshot;
    } catch (error) {
      try { file.close(); } catch { /* Close failure leaves the marker: mirrors Go ErrUnavailable. */ }
      throw error;
    }
  }

  /**
   * Explicit out-of-band reconciliation of one unknown-outcome operation on a
   * closed dirty store: the exact snapshot/receipt moves to a terminal
   * tombstone. A missing record is not proof of abort and does not clear the
   * startup fence (Go reconcileUnknown).
   */
  static reconcileUnknown(path: string, input: DurableStoreOptions, expectedHash: string,
    receipt: DurableReceipt): void {
    const options = normalized(input);
    let file: RotationFileOwner;
    try {
      file = RotationFileOwner.open(path);
    } catch {
      // A live owner or an unusable private path reports unavailable (Go ErrUnavailable).
      throw durableUnavailable();
    }
    try {
      const bytes = file.read();
      const doc = decodeDocument(bytes);
      // Go loadRecoverySnapshot: a deployment or window mismatch is ErrInvalidStore.
      if (doc.meta.deployment !== options.deploymentId || doc.meta.window !== options.window) {
        throw invalidStore();
      }
      if (!doc.meta.dirty || snapshotHash(doc) !== expectedHash) {
        throw recoveryRequired();
      }
      const key = pairKeyOf(decodeBase64URLFixed(receipt.kid, 32), decodeBase64URLFixed(receipt.nonce, 16))
        .toString("latin1");
      const work = cloneDoc(doc);
      let found = false;
      for (const group of GROUPS) {
        const row = findSorted(work[group.name], key);
        if (row === undefined) continue;
        found = true;
        if (!receiptsEqual(row, receipt)) {
          throw recoveryRequired();
        }
        if (group.kind === "tombstone") break; // already terminal
        if (work.meta.tombstones >= DURABLE_MAX_TOMBSTONES) {
          throw recoveryRequired();
        }
        work[group.name] = removeSorted(work[group.name], key);
        work.tombstones = insertSorted(work.tombstones, row);
        withMeta(work, { tombstones: work.meta.tombstones + 1,
          live: group.kind === "live" ? work.meta.live - 1 : work.meta.live,
          intents: group.kind === "intent" ? work.meta.intents - 1 : work.meta.intents });
        break;
      }
      if (!found) {
        // A missing record is not proof of abort.
        throw recoveryRequired();
      }
      // Atomic replace under the held exclusive owner (byte-CAS against the
      // bytes just read); rotation I/O failure reports unavailable.
      try {
        file.replace(bytes, encodeDocument({ meta: work.meta, live: work.live, intents: work.intents,
          tombstones: work.tombstones }));
      } catch (error) {
        throw error instanceof RotationError ? durableUnavailable() : error;
      }
      file.close();
    } catch (error) {
      try { file.close(); } catch { /* Close failure leaves the marker: mirrors Go ErrUnavailable. */ }
      throw error;
    }
  }
}
