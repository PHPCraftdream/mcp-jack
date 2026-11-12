import { parseResponseAuth } from "./auth-header.js";
import { verifyRotationCarrier } from "./client/rotation-auth.js";
import type { RotationCarrier, RotationResponseKey } from "./client/rotation-auth.js";
import { Code, JackError } from "./errors.js";
import { ROTATION_MAX_RETAINED_KEYS } from "./rotation-chain.js";
import { decodeRotationResult } from "./rotation-result.js";
import { extendedRefreshSnapshot, prepareRefreshExtension } from "./rotation-refresh-state.js";
import { encodeRotationTrustSnapshot } from "./rotation-trust-json.js";
import type { RotationCursor } from "./rotation-page.js";
import { RotationError, ROTATION_MAX_ORDINAL, ROTATION_MAX_TIMESTAMP } from "./rotation-record.js";
import { RotationTrustStore } from "./rotation-store.js";
import type { RotationTrustSnapshot } from "./rotation-trust.js";

export interface RotationResponse {
  readonly status: number;
  readonly headers: readonly string[];
  readonly requestSignature: string;
  readonly body: Uint8Array;
}

export interface RotationRefreshResult {
  readonly head: RotationCursor;
  readonly terminal: RotationCursor;
  readonly complete: boolean;
  readonly committed: boolean;
  readonly revision: number;
}

type Profile = Pick<RotationTrustSnapshot, "binding" | "window" | "checkpoint">;

function refuse(code: string): never {
  throw new JackError(0, code, "rotation response refused");
}

function mapped(error: unknown, fallback: string): never {
  return refuse(error instanceof JackError || error instanceof RotationError ? error.code : fallback);
}

function matchesProfile(snapshot: RotationTrustSnapshot, profile: Profile): boolean {
  const a = snapshot.checkpoint;
  const b = profile.checkpoint;
  return snapshot.binding.endpoint === profile.binding.endpoint && snapshot.binding.aud === profile.binding.aud &&
    snapshot.window === profile.window && a.ordinal === b.ordinal && a.hash === b.hash && a.kid === b.kid &&
    a.publicKeyB64u === b.publicKeyB64u && a.publishedAt === b.publishedAt;
}

function knownKeys(snapshot: RotationTrustSnapshot): ReadonlyMap<string, RotationResponseKey> {
  return new Map<string, RotationResponseKey>(snapshot.keys.map((key) => [key.kid, { publicKeyB64u: key.publicKeyB64u, notBefore: key.notBefore,
    ...(key.knownCutoff === null ? {} : { knownCutoff: key.knownCutoff }) }]));
}

/** Reference: Go client/rotation/controller.go; store lifecycle остаётся у caller. */
export class RotationController {
  private readonly profile: Profile;
  private writer = false;

  constructor(private readonly store: RotationTrustStore) {
    try {
      const initial = store.snapshot().snapshot;
      store.checkSnapshotClock(initial);
      this.profile = Object.freeze({ binding: initial.binding, window: initial.window, checkpoint: initial.checkpoint });
    } catch (error) {
      mapped(error, "rotation_state_unknown");
    }
  }

  private state(): RotationTrustSnapshot {
    const snapshot = this.store.snapshot().snapshot;
    if (!matchesProfile(snapshot, this.profile)) refuse("rotation_state_unknown");
    return snapshot;
  }

  /** После authoritative sample — только bounded scalar/interval arithmetic. */
  private timeValid(snapshot: RotationTrustSnapshot, carrier: RotationCarrier, now: number): void {
    if (!Number.isSafeInteger(now) || now < 0 || now > ROTATION_MAX_TIMESTAMP) refuse("rotation_clock_unavailable");
    if (!Number.isSafeInteger(carrier.timestamp) || carrier.timestamp < 0 || carrier.timestamp > ROTATION_MAX_TIMESTAMP ||
      Math.abs(now - carrier.timestamp) > snapshot.window) refuse(Code.TIMESTAMP_OUT_OF_WINDOW);
    const key = snapshot.keys.find((value) => value.kid === carrier.kid);
    if (key === undefined) refuse(Code.UNKNOWN_SERVER_KEY);
    if (carrier.timestamp < key.notBefore || (key.knownCutoff !== null &&
      (carrier.timestamp >= key.knownCutoff || now >= key.knownCutoff))) refuse("rotation_key_interval");
    if (snapshot.revision < 1 || snapshot.revision > ROTATION_MAX_ORDINAL || snapshot.keys.length > ROTATION_MAX_RETAINED_KEYS) refuse("rotation_state_changed");
    let pending = 0;
    let retired = 0;
    for (const retained of snapshot.keys) {
      if (retained.notBefore > now) pending++;
      else if (retained.knownCutoff !== null && retained.knownCutoff <= now) retired++;
    }
    if (pending > 128 || retired > 1024) refuse("rotation_state_changed");
  }

  private equal(left: RotationTrustSnapshot, right: RotationTrustSnapshot): boolean {
    const a = encodeRotationTrustSnapshot(left, this.profile.binding, this.profile.window, this.profile.checkpoint);
    const b = encodeRotationTrustSnapshot(right, this.profile.binding, this.profile.window, this.profile.checkpoint);
    return Buffer.from(a).equals(b);
  }

  private final(snapshot: RotationTrustSnapshot, carrier: RotationCarrier): void {
    const clock = this.store.checkSnapshotClock(snapshot);
    this.timeValid(snapshot, carrier, clock.highWater);
  }

  private outer(input: RotationResponse): { readonly status: number; readonly body: Uint8Array; readonly snapshot: RotationTrustSnapshot; readonly carrier: RotationCarrier } {
    const snapshot = this.state();
    const headers = [...input.headers];
    const auth = parseResponseAuth(headers);
    const known = knownKeys(snapshot);
    // Unknown carrier не даёт читать body или вызывать даже preliminary clock.
    if (!known.has(auth.kid)) refuse(Code.UNKNOWN_SERVER_KEY);
    const source = input.body;
    if (!(source instanceof Uint8Array) || source.length > 1024 * 1024) refuse("rotation_result_invalid");
    const body = Buffer.from(source);
    const status = input.status;
    const requestSignature = input.requestSignature;
    const raw = this.store.rawClock();
    const carrier = verifyRotationCarrier(known, status, headers, requestSignature, body, raw, snapshot.window);
    const clock = this.store.checkSnapshotClock(snapshot);
    this.timeValid(snapshot, carrier, clock.highWater);
    return { status, body, snapshot, carrier };
  }

  /** Explicit single-page success; late final error не откатывает уже подтверждённый ACK. */
  acceptRefresh(input: RotationResponse, expectedId: string | number, cursor: RotationCursor): RotationRefreshResult {
    try {
      const owned = this.outer(input);
      if (owned.status !== 200) refuse("rotation_result_invalid");
      const requested = Object.freeze({ ordinal: cursor.ordinal, hash: cursor.hash });
      const page = decodeRotationResult(owned.body, expectedId);
      const key = owned.snapshot.keys.find((value) => value.kid === owned.carrier.kid);
      if (key === undefined || page.current.kid !== owned.carrier.kid || page.current.publicKeyB64u !== key.publicKeyB64u) refuse("rotation_result_invalid");
      const prepared = prepareRefreshExtension(owned.snapshot, page, requested, owned.carrier.timestamp);
      const result: RotationRefreshResult = Object.freeze({ head: prepared.framing.head, terminal: prepared.framing.terminal,
        complete: prepared.framing.complete, committed: false, revision: owned.snapshot.revision });
      if (prepared.extension.length === 0) {
        this.final(owned.snapshot, owned.carrier);
        return result;
      }
      if (this.writer) refuse("rotation_state_changed");
      this.writer = true;
      try {
        if (!this.equal(this.state(), owned.snapshot)) refuse("rotation_state_changed");
        const clock = this.store.checkSnapshotClock(owned.snapshot);
        this.timeValid(owned.snapshot, owned.carrier, clock.highWater);
        const first = prepared.extension[0];
        if (first === undefined) refuse("rotation_state_unknown");
        if (clock.highWater >= first.activatesAt) refuse("rotation_bridge_expired");
        const desired = extendedRefreshSnapshot(owned.snapshot, prepared.extension, clock);
        this.store.compareAndSwap(owned.snapshot, desired, clock);
        const committed = Object.freeze({ ...result, committed: true, revision: desired.revision });
        this.final(desired, owned.carrier);
        return committed;
      } finally {
        this.writer = false;
      }
    } catch (error) {
      return mapped(error, "rotation_state_unknown");
    }
  }

  /** Owned exact body только после final clock/snapshot/interval gate; без fetch/retry. */
  verifyResponse(input: RotationResponse): Uint8Array {
    try {
      const owned = this.outer(input);
      this.final(owned.snapshot, owned.carrier);
      return owned.body;
    } catch (error) {
      return mapped(error, "rotation_state_unknown");
    }
  }
}
