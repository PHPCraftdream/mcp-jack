import { randomBytes } from "node:crypto";
import { bodyHash } from "./encoding.js";
import { RotationFileOwner } from "./rotation-file.js";
import { RotationError, ROTATION_MAX_ORDINAL, ROTATION_MAX_TIMESTAMP } from "./rotation-record.js";
import { anchorSnapshot, clockBytes, encodedSnapshot, invalidStore, pack, readClock, unpack } from "./rotation-store-format.js";
import type { RotationStoreOptions, StoreBundle } from "./rotation-store-format.js";
import { rotationTrustClockCompatible, validateRotationTrustSnapshot } from "./rotation-trust.js";
import type { RotationClockTuple, RotationTrustSnapshot } from "./rotation-trust.js";

export type { RotationStoreOptions } from "./rotation-store-format.js";
type NormalizedOptions = RotationStoreOptions & { readonly now: () => number };

function normalized(input: RotationStoreOptions): { options: NormalizedOptions; anchor: RotationTrustSnapshot; profile: string } {
  try {
    const anchor = anchorSnapshot(input);
    const now = input.now;
    if (now !== undefined && typeof now !== "function") invalidStore();
    const options = Object.freeze({ binding: anchor.binding, window: anchor.window, checkpoint: anchor.checkpoint,
      now: now ?? (() => Math.floor(Date.now() / 1000)) });
    return { options, anchor, profile: bodyHash(Buffer.from(encodedSnapshot(anchor, options), "utf8")) };
  } catch {
    return invalidStore();
  }
}

/** Concrete private Linux profile; sync callbacks/I/O должны быть bounded и не reentrant. */
export class RotationTrustStore {
  private fenced = false;
  private closed = false;
  private busy = false;

  private constructor(private readonly file: RotationFileOwner, private readonly options: NormalizedOptions,
    private readonly profile: string, private readonly storeId: string, private readonly owner: number) {}

  static initializeUnused(path: string, input: RotationStoreOptions): void {
    const { options, anchor, profile } = normalized(input);
    const id = randomBytes(16);
    if (id.every((byte) => byte === 0)) invalidStore();
    const base: StoreBundle = { storeId: id.toString("base64url"), profile, owner: 1, dirty: true, fenced: false,
      clockBytes: clockBytes(anchor.clock), snapshotBytes: encodedSnapshot(anchor, options) };
    const first = pack(base);
    // Marker/dirty state подтверждены до первого clock callback.
    const file = RotationFileOwner.createUnusedOwner(path, first);
    try {
      const now = options.now();
      if (!Number.isSafeInteger(now) || now < 0 || now > ROTATION_MAX_TIMESTAMP) invalidStore();
      const clock = Object.freeze({ ...anchor.clock, highWater: now, revision: 1 });
      file.replace(first, pack({ ...base, dirty: false, clockBytes: clockBytes(clock),
        snapshotBytes: encodedSnapshot({ ...anchor, clock }, options) }));
      file.close();
    } catch {
      file.fence();
      throw new RotationError("rotation_state_unknown");
    }
  }

  static open(path: string, input: RotationStoreOptions): RotationTrustStore {
    const { options, profile } = normalized(input);
    const file = RotationFileOwner.open(path);
    let mutation = false;
    try {
      const bytes = file.read();
      const state = unpack(bytes, options, profile);
      if (state.bundle.dirty || state.bundle.fenced || !rotationTrustClockCompatible(state.snapshot, state.clock) || state.bundle.owner === ROTATION_MAX_ORDINAL) invalidStore();
      const bundle = { ...state.bundle, owner: state.bundle.owner + 1, dirty: true };
      mutation = true;
      file.replace(bytes, pack(bundle));
      const store = new RotationTrustStore(file, options, profile, bundle.storeId, bundle.owner);
      store.advanceAndCheck();
      return store;
    } catch (error) {
      if (mutation) file.fence();
      try { file.close(); } catch { /* Unknown/dirty marker остаётся startup gate. */ }
      if (error instanceof RotationError) throw error;
      return invalidStore();
    }
  }

  private begin(code: string): void {
    if (this.closed || this.fenced) throw new RotationError(code);
    if (this.busy) {
      this.fence();
      throw new RotationError(code);
    }
    this.busy = true;
  }

  private load(): { bytes: Uint8Array; bundle: StoreBundle; clock: RotationClockTuple; snapshot: RotationTrustSnapshot } {
    const bytes = this.file.read();
    const state = unpack(bytes, this.options, this.profile);
    if (state.bundle.storeId !== this.storeId || state.bundle.owner !== this.owner || !state.bundle.dirty || state.bundle.fenced) invalidStore();
    return { bytes, ...state };
  }

  private sample(): number {
    try { return this.options.now(); }
    catch { this.fence(); throw new RotationError("rotation_clock_unavailable"); }
  }

  rawClock(): number {
    this.begin("rotation_clock_unavailable");
    try {
      const now = this.sample();
      if (this.fenced) throw new RotationError("rotation_clock_unavailable");
      return now;
    } finally { this.busy = false; }
  }

  /** Committed read, не fresh ClockGuard operation или ACK. */
  snapshot(): { readonly snapshot: RotationTrustSnapshot; readonly clock: RotationClockTuple } {
    this.begin("rotation_state_unavailable");
    try {
      const state = this.load();
      if (!rotationTrustClockCompatible(state.snapshot, state.clock)) invalidStore();
      return Object.freeze({ snapshot: state.snapshot, clock: state.clock });
    } catch {
      this.fence();
      return invalidStore();
    } finally { this.busy = false; }
  }

  advanceAndCheck(): RotationClockTuple { return this.advance(); }

  checkSnapshotClock(expected: RotationTrustSnapshot): RotationClockTuple {
    return this.advance(encodedSnapshot(expected, this.options));
  }

  private advance(expected?: string): RotationClockTuple {
    this.begin("rotation_clock_unavailable");
    try {
      const state = this.load();
      let clock = state.clock;
      if (!clock.unsafe) {
        const now = this.sample();
        if (this.fenced) throw new Error("owner fenced during clock callback");
        const unsafe = !Number.isSafeInteger(now) || now < 0 || now > ROTATION_MAX_TIMESTAMP || now < clock.highWater;
        if (unsafe || now !== clock.highWater) {
          if (clock.revision === ROTATION_MAX_ORDINAL) throw new Error("clock revision exhausted");
          clock = Object.freeze({ ...clock, highWater: unsafe ? clock.highWater : now, revision: clock.revision + 1, unsafe });
          this.file.replace(state.bytes, pack({ ...state.bundle, clockBytes: clockBytes(clock) }));
        }
      }
      if (this.fenced) throw new Error("owner fenced during clock operation");
      if (clock.unsafe) throw new RotationError("rotation_clock_unsafe");
      if (expected !== undefined && expected !== state.bundle.snapshotBytes) throw new RotationError("rotation_state_changed");
      return clock;
    } catch (error) {
      if (error instanceof RotationError && (error.code === "rotation_clock_unsafe" || error.code === "rotation_state_changed")) throw error;
      this.fence();
      throw new RotationError("rotation_clock_unavailable");
    } finally { this.busy = false; }
  }

  /** Exact snapshot/current-clock CAS; logical ClockGuard bytes не меняются. */
  compareAndSwap(expected: RotationTrustSnapshot, desired: RotationTrustSnapshot, clock: RotationClockTuple): void {
    const previousValue = validateRotationTrustSnapshot(expected, this.options.binding, this.options.window, this.options.checkpoint);
    const nextValue = validateRotationTrustSnapshot(desired, this.options.binding, this.options.window, this.options.checkpoint);
    const previous = encodedSnapshot(previousValue, this.options);
    const next = encodedSnapshot(nextValue, this.options);
    let captured: RotationClockTuple;
    try { captured = readClock(clockBytes(clock), this.options); }
    catch { throw new RotationError("rotation_state_changed"); }
    const capturedClock = clockBytes(captured);
    if (previousValue.revision === ROTATION_MAX_ORDINAL || nextValue.revision !== previousValue.revision + 1 || previousValue.fenced || nextValue.fenced ||
      !rotationTrustClockCompatible(previousValue, captured) || clockBytes(nextValue.clock) !== capturedClock || nextValue.records.length <= previousValue.records.length ||
      previousValue.records.some((wire, index) => nextValue.records[index] !== wire)) throw new RotationError("rotation_state_changed");
    this.begin("rotation_state_unavailable");
    try {
      const state = this.load();
      if (state.clock.unsafe || state.bundle.snapshotBytes !== previous || state.bundle.clockBytes !== capturedClock) throw new RotationError("rotation_state_changed");
      this.file.replace(state.bytes, pack({ ...state.bundle, snapshotBytes: next }));
      if (this.fenced) throw new Error("owner fenced after commit");
    } catch (error) {
      if (error instanceof RotationError && error.code === "rotation_state_changed") throw error;
      this.fence();
      throw new RotationError("rotation_state_unknown");
    } finally { this.busy = false; }
  }

  fence(): void { this.fenced = true; this.file.fence(); }

  /** Sync storage ops уже завершены; сетевые callers должны пройти final gate отдельно. */
  close(): void {
    if (this.closed) return;
    if (this.busy || this.fenced) { this.fence(); return invalidStore(); }
    this.busy = true;
    try {
      const state = this.load();
      if (!rotationTrustClockCompatible(state.snapshot, state.clock)) invalidStore();
      this.file.replace(state.bytes, pack({ ...state.bundle, dirty: false }));
      this.file.close();
      this.closed = true;
    } catch {
      this.fence();
      invalidStore();
    } finally { this.busy = false; }
  }
}
