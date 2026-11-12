import { randomBytes } from "node:crypto";
import { RotationFileOwner } from "./rotation-file.js";
import { RotationError, ROTATION_MAX_ORDINAL, ROTATION_MAX_TIMESTAMP } from "./rotation-record.js";
import { validateRotationServerPublication, validateRotationServerSnapshot } from "./rotation-server-state.js";
import type { RotationServerSnapshot } from "./rotation-server-state.js";
import { anchorServerSnapshot, encodedServer, packServer, serverProfile, unpackServer } from "./rotation-server-store-format.js";
import type { RotationServerStoreOptions } from "./rotation-server-store-format.js";
import { clockBytes, invalidStore, readClock } from "./rotation-store-format.js";
import type { RotationStoreOptions, StoreBundle } from "./rotation-store-format.js";
import { rotationTrustClockCompatible } from "./rotation-trust.js";
import type { RotationClockTuple } from "./rotation-trust.js";

export type { RotationServerStoreOptions } from "./rotation-server-store-format.js";
type NormalizedOptions = RotationStoreOptions & { readonly now: () => number };

function normalized(input: RotationServerStoreOptions): { options: NormalizedOptions; anchor: RotationServerSnapshot; profile: string } {
  try {
    const anchor = anchorServerSnapshot(input);
    const now = input.now;
    if (now !== undefined && typeof now !== "function") invalidStore();
    const options = Object.freeze({ binding: anchor.trust.binding, window: anchor.trust.window, checkpoint: anchor.trust.checkpoint,
      now: now ?? (() => Math.floor(Date.now() / 1000)) });
    return { options, anchor, profile: serverProfile(anchor, options) };
  } catch {
    return invalidStore();
  }
}

/**
 * Concrete private Linux server ring store: exclusive owner, независимый monotone ClockGuard,
 * exact whole-ring CAS одной fixed-P публикации. Sync callbacks/I/O должны быть bounded и не reentrant.
 * Не выбирает signer, не авторизует ответы и не восстанавливает dirty/unknown state.
 */
export class RotationServerStore {
  private fenced = false;
  private closing = false;
  private closed = false;
  private busy = false;
  private leases = 0;

  private constructor(private readonly file: RotationFileOwner, private readonly options: NormalizedOptions,
    private readonly profile: string, private readonly storeId: string, private readonly owner: number) {}

  static initializeUnused(path: string, input: RotationServerStoreOptions): void {
    const { options, anchor, profile } = normalized(input);
    const id = randomBytes(16);
    if (id.every((byte) => byte === 0)) invalidStore();
    const base: StoreBundle = { storeId: id.toString("base64url"), profile, owner: 1, dirty: true, fenced: false,
      clockBytes: clockBytes(anchor.trust.clock), snapshotBytes: encodedServer(anchor, options) };
    const first = packServer(base);
    // Marker/dirty state подтверждены до первого clock callback.
    const file = RotationFileOwner.createUnusedOwner(path, first);
    try {
      const now = options.now();
      if (!Number.isSafeInteger(now) || now < 0 || now > ROTATION_MAX_TIMESTAMP) invalidStore();
      const clock = Object.freeze({ ...anchor.trust.clock, highWater: now, revision: 1 });
      const ready = Object.freeze({ ...anchor, trust: Object.freeze({ ...anchor.trust, clock }) });
      file.replace(first, packServer({ ...base, dirty: false, clockBytes: clockBytes(clock), snapshotBytes: encodedServer(ready, options) }));
      file.close();
    } catch {
      file.fence();
      throw new RotationError("rotation_state_unknown");
    }
  }

  /** Не очищает dirty/fenced/unsafe: recovery требует отдельного supported evidence contract. */
  static open(path: string, input: RotationServerStoreOptions): RotationServerStore {
    const { options, profile } = normalized(input);
    const file = RotationFileOwner.open(path);
    let mutation = false;
    try {
      const bytes = file.read();
      const state = unpackServer(bytes, options, profile);
      if (state.bundle.dirty || state.bundle.fenced || !rotationTrustClockCompatible(state.snapshot.trust, state.clock) || state.bundle.owner === ROTATION_MAX_ORDINAL) invalidStore();
      const bundle = { ...state.bundle, owner: state.bundle.owner + 1, dirty: true };
      mutation = true;
      file.replace(bytes, packServer(bundle));
      const store = new RotationServerStore(file, options, profile, bundle.storeId, bundle.owner);
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
    if (this.closed || this.closing || this.fenced) throw new RotationError(code);
    if (this.busy) {
      this.fence();
      throw new RotationError(code);
    }
    this.busy = true;
  }

  private load(): { bytes: Uint8Array; bundle: StoreBundle; clock: RotationClockTuple; snapshot: RotationServerSnapshot } {
    const bytes = this.file.read();
    const state = unpackServer(bytes, this.options, this.profile);
    if (state.bundle.storeId !== this.storeId || state.bundle.owner !== this.owner || !state.bundle.dirty || state.bundle.fenced) invalidStore();
    return { bytes, ...state };
  }

  private sample(): number {
    try { return this.options.now(); }
    catch { this.fence(); throw new RotationError("rotation_clock_unavailable"); }
  }

  /** Только sample для outer checks, не durable time authority. */
  rawClock(): number {
    this.begin("rotation_clock_unavailable");
    try {
      const now = this.sample();
      if (this.fenced) throw new RotationError("rotation_clock_unavailable");
      return now;
    } finally { this.busy = false; }
  }

  /** Committed read, не fresh ClockGuard operation. */
  snapshot(): { readonly snapshot: RotationServerSnapshot; readonly clock: RotationClockTuple } {
    this.begin("rotation_state_unavailable");
    try {
      const state = this.load();
      if (!rotationTrustClockCompatible(state.snapshot.trust, state.clock)) invalidStore();
      return Object.freeze({ snapshot: state.snapshot, clock: state.clock });
    } catch {
      this.fence();
      return invalidStore();
    } finally { this.busy = false; }
  }

  /** Единственная операция, меняющая authoritative H/revision/unsafe. */
  advanceAndCheck(): RotationClockTuple { return this.advance(); }

  /** Exact ring плюс свежий server ClockGuard. */
  checkSnapshotClock(expected: RotationServerSnapshot): RotationClockTuple {
    const { binding, window, checkpoint } = this.options;
    return this.advance(encodedServer(validateRotationServerSnapshot(expected, binding, window, checkpoint), this.options));
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
          this.file.replace(state.bytes, packServer({ ...state.bundle, clockBytes: clockBytes(clock) }));
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

  /** Exact ring/current-clock CAS одной fixed-P публикации; logical ClockGuard bytes не меняются. */
  compareAndSwap(expected: RotationServerSnapshot, desired: RotationServerSnapshot, clock: RotationClockTuple): void {
    const { binding, window, checkpoint } = this.options;
    const previousValue = validateRotationServerSnapshot(expected, binding, window, checkpoint);
    const nextValue = validateRotationServerSnapshot(desired, binding, window, checkpoint);
    let captured: RotationClockTuple;
    try { captured = readClock(clockBytes(clock), this.options); }
    catch { throw new RotationError("rotation_state_changed"); }
    const capturedClock = clockBytes(captured);
    if (clockBytes(nextValue.trust.clock) !== capturedClock) throw new RotationError("rotation_state_changed");
    validateRotationServerPublication(previousValue, nextValue, binding, window, checkpoint);
    const previous = encodedServer(previousValue, this.options);
    const next = encodedServer(nextValue, this.options);
    this.begin("rotation_state_unavailable");
    try {
      const state = this.load();
      if (state.clock.unsafe || state.bundle.snapshotBytes !== previous || state.bundle.clockBytes !== capturedClock) throw new RotationError("rotation_state_changed");
      this.file.replace(state.bytes, packServer({ ...state.bundle, snapshotBytes: next }));
      if (this.fenced) throw new Error("owner fenced after commit");
    } catch (error) {
      if (error instanceof RotationError && error.code === "rotation_state_changed") throw error;
      this.fence();
      throw new RotationError("rotation_state_unknown");
    } finally { this.busy = false; }
  }

  /** Удерживает dirty epoch до физического завершения response write; release идемпотентен. */
  acquireServingLease(): () => void {
    if (this.closed || this.closing || this.fenced) throw new RotationError("rotation_state_unavailable");
    this.leases++;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.leases--;
    };
  }

  fence(): void { this.fenced = true; this.file.fence(); }

  /**
   * Новые операции и final gates отказывают сразу. Пока есть serving leases, close() не завершается
   * и не fences: caller освобождает leases и вызывает close() повторно.
   */
  close(): void {
    if (this.closed) return;
    if (this.busy || this.fenced) { this.fence(); return invalidStore(); }
    this.closing = true;
    if (this.leases > 0) throw new RotationError("rotation_state_unavailable");
    this.busy = true;
    try {
      const state = this.load();
      if (!rotationTrustClockCompatible(state.snapshot.trust, state.clock)) invalidStore();
      this.file.replace(state.bytes, packServer({ ...state.bundle, dirty: false }));
      this.file.close();
      this.closed = true;
    } catch {
      this.fence();
      invalidStore();
    } finally { this.busy = false; }
  }
}
