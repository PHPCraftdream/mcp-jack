import { validatePublicKey } from "../../core/ed25519.js";
import { encodeBase64URL, keyId } from "../../core/encoding.js";
import { ROTATION_MAX_RETAINED_KEYS } from "../wire/chain.js";
import type { RotationCheckpoint } from "../wire/chain.js";
import { RotationError, ROTATION_GRACE_SECONDS, ROTATION_MAX_ORDINAL, ROTATION_MAX_TIMESTAMP } from "../wire/record.js";
import type { RotationRecord } from "../wire/record.js";
import { createRotationRecord } from "../wire/sign.js";
import type { RotationSigner } from "../wire/sign.js";
import type { RotationServerSnapshot } from "../snapshot/server-state.js";
import { ROTATION_MAX_SIGNER_REFERENCE_BYTES } from "../snapshot/server-state.js";
import type { RotationServerStore } from "./store.js";
import type { RotationClockTuple, RotationTrustKey } from "../snapshot/trust.js";
import { parseCandidateJsonRaw } from "../../core/json-raw.js";
import { decodeRotationResult, ROTATION_MAX_BODY_BYTES } from "../wire/result.js";
import type { DecodedRotationResult } from "../wire/result.js";
import { TOOL_SERVER_KEY } from "../../server/verify.js";

const MAX_PENDING = 128;
/** @internal Test only. */
export const MAX_RETIRED = 1024;
/** @internal Test only. Every key but the newest eventually retires; serving refuses above MAX_RETIRED retired keys. */
export const MAX_ANNOUNCE_RING_KEYS = MAX_RETIRED + 1;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Preconfigured signer handle: the reference does not replace public key verification. */
export interface RotationServerKey {
  readonly reference: string;
  readonly signer: RotationSigner;
}

/** Only after the exact durable ACK; this is not HTTP delivery. */
export interface RotationPublication {
  readonly record: RotationRecord;
  readonly revision: number;
}

/** Pinned signer identity: the public key is copied and does not change with the callback. */
export interface PinnedRotationSigner extends RotationSigner {
  readonly publicKeyB64u: string;
}

/** Owned copy of the response body; the payload is not a source of key authority (Go server.ResponseKeyRequest). */
export interface RotationResponseKeyRequest {
  readonly status: number;
  readonly tool: string;
  readonly requestSignature: string;
  readonly body: Uint8Array;
}

/** identity/time/lease are pinned before building the response; final is single-shot (Go server.ResponseKeyAuthorization). */
export interface RotationResponseAuthorization {
  readonly signer: PinnedRotationSigner;
  readonly timestamp: number;
  /** Single-shot final gate: fresh completion sample and re-selection; failure throws RotationError. */
  readonly final: () => void;
  /** Idempotent release; the caller invokes it after building or rejecting the response. */
  readonly release: () => void;
}

function unavailable(): never {
  throw new RotationError("rotation_state_unavailable");
}

function identity(reference: string, kid: string): string {
  return JSON.stringify([reference, kid]);
}

function pin(input: RotationServerKey): PinnedRotationSigner {
  try {
    const reference = input.reference;
    const signer = input.signer;
    if (typeof reference !== "string" || reference.length === 0 || Buffer.byteLength(reference, "utf8") > ROTATION_MAX_SIGNER_REFERENCE_BYTES ||
      Buffer.from(reference, "utf8").toString("utf8") !== reference || typeof signer?.publicKey !== "function" || typeof signer.sign !== "function") unavailable();
    const publicKey = Uint8Array.from(signer.publicKey());
    if (publicKey.length !== 32 || validatePublicKey(publicKey) !== null) unavailable();
    return Object.freeze({ publicKeyB64u: encodeBase64URL(publicKey), publicKey: () => Uint8Array.from(publicKey),
      sign: (message: Uint8Array) => signer.sign(message) });
  } catch {
    return unavailable();
  }
}

/**
 * Binds the concrete server store to a preconfigured signing inventory: signer selection,
 * explicit publication of one next key. Inventory is set only out-of-band; custody and lifecycle
 * of signer handles belong to the caller. Signer callbacks must be bounded and non-reentrant.
 * authorizeResponse — signer selection + final gate for response signing (Go ResponseKeyProvider), no fallback.
 */
export class RotationServerProvider {
  private readonly keys = new Map<string, PinnedRotationSigner>();
  private publishing = false;
  private announceRingKeys = MAX_ANNOUNCE_RING_KEYS;

  /** Does not create state or authorize publication; fails if the ring is not ready to serve. */
  constructor(private readonly store: RotationServerStore, keys: readonly RotationServerKey[]) {
    if (!Array.isArray(keys) || keys.length === 0 || keys.length > ROTATION_MAX_RETAINED_KEYS) unavailable();
    for (const key of keys) {
      const pinned = pin(key);
      const id = identity(key.reference, keyId(pinned.publicKey()));
      if (this.keys.has(id)) unavailable();
      this.keys.set(id, pinned);
    }
    this.ready();
  }

  /** Readiness: committed ring, fresh ClockGuard, and all pending/current handles available. */
  ready(): void {
    const release = this.store.acquireServingLease();
    try {
      const { snapshot } = this.store.snapshot();
      this.selectSigner(snapshot, this.store.checkSnapshotClock(snapshot));
    } finally {
      release();
    }
  }

  /** @internal Test only: lowers the announce bound so a test need not build a real 1025-key ring. */
  setAnnounceRingKeysForTests(bound: number): void {
    if (typeof bound !== "number" || !Number.isSafeInteger(bound) || bound < 2 || bound > MAX_ANNOUNCE_RING_KEYS) unavailable();
    this.announceRingKeys = bound;
  }

  /**
   * Requires handles of all pending keys and the current signer; retired handles are optional. Selects
   * the eligible key with the highest ordinal and does not fall back. The snapshot is already fully verified;
   * after a fresh clock sample only interval arithmetic remains.
   */
  selectSigner(snapshot: RotationServerSnapshot, clock: RotationClockTuple): PinnedRotationSigner {
    let selected: PinnedRotationSigner | undefined;
    let pending = 0;
    let retired = 0;
    for (const [index, key] of snapshot.trust.keys.entries()) {
      const eligible = key.notBefore <= clock.highWater && (key.knownCutoff === null || clock.highWater < key.knownCutoff);
      const isPending = key.notBefore > clock.highWater;
      if (isPending) pending++;
      if (key.knownCutoff !== null && key.knownCutoff <= clock.highWater) retired++;
      if (pending > MAX_PENDING || retired > MAX_RETIRED) unavailable();
      if (!eligible && !isPending) continue;
      const reference = snapshot.signerReferences[index];
      const signer = reference === undefined ? undefined : this.keys.get(identity(reference.reference, key.kid));
      if (signer === undefined || signer.publicKeyB64u !== key.publicKeyB64u) unavailable();
      if (eligible) selected = signer;
    }
    if (selected === undefined) unavailable();
    return selected;
  }

  /** The 5.1 successor activation of `kid`, or undefined when none is known yet. */
  successorActivation(kid: string): number | undefined {
    const { snapshot } = this.store.snapshot();
    const key = snapshot.trust.keys.find((entry) => entry.kid === kid);
    if (key === undefined) return undefined;
    const cutoff = key.knownCutoff;
    return typeof cutoff === "number" && Number.isSafeInteger(cutoff) && cutoff >= 0 ? cutoff : undefined;
  }

  /**
   * One explicit authorization for the preconfigured next handle. P is pinned by a single fresh
   * sample; failure, conflict, or unknown is not retried automatically.
   */
  announce(reference: string, kid: string): RotationPublication {
    if (this.publishing) return unavailable();
    this.publishing = true;
    try {
      const next = this.keys.get(identity(reference, kid));
      if (next === undefined) unavailable();
      const release = this.store.acquireServingLease();
      try {
        return this.publish(next, reference, kid);
      } finally {
        release();
      }
    } finally {
      this.publishing = false;
    }
  }

  /**
   * Signer selection and fresh clock sample happen before computing the response signature; the serving lease is held
   * until release and no network I/O runs under it. Final is single-shot: a second fresh
   * sample must select the same signer, otherwise the signature is discarded (Go writeAuthorized).
   * No fallback, retry, or signed response on failure.
   */
  authorizeResponse(input: RotationResponseKeyRequest): RotationResponseAuthorization {
    const page = this.decodeNativeResponse(input);
    const release = this.store.acquireServingLease();
    let ready = false;
    try {
      const { snapshot } = this.store.snapshot();
      const clock = this.store.checkSnapshotClock(snapshot);
      const signer = this.selectSigner(snapshot, clock);
      if (!this.matchesNativeResponse(page, snapshot, signer)) return unavailable();
      let finalized = false;
      let released = false;
      ready = true;
      return Object.freeze({
        signer,
        timestamp: clock.highWater,
        release: (): void => {
          if (released) return;
          released = true;
          release();
        },
        final: (): void => {
          if (released || finalized) unavailable();
          finalized = true;
          const fresh = this.store.checkSnapshotClock(snapshot);
          if (fresh.highWater < clock.highWater || fresh.highWater - clock.highWater > snapshot.trust.window) unavailable();
          const current = this.selectSigner(snapshot, fresh);
          if (current.publicKeyB64u !== signer.publicKeyB64u || released) unavailable();
        },
      });
    } finally {
      if (!ready) release();
    }
  }

  /** Full envelope/parity parse before the signing-time clock; payload is not key authority (Go decodeNativeResponse). */
  private decodeNativeResponse(input: RotationResponseKeyRequest): DecodedRotationResult | undefined {
    if (input.tool !== TOOL_SERVER_KEY || input.status !== 200) return undefined;
    if (!(input.body instanceof Uint8Array) || input.body.length > ROTATION_MAX_BODY_BYTES) return unavailable();
    try {
      const root = parseCandidateJsonRaw(utf8.decode(input.body));
      const members = root.members;
      if (typeof root.value !== "object" || root.value === null || Array.isArray(root.value) || members === undefined) return unavailable();
      const id = members.get("id");
      if (id === undefined || (typeof id.value !== "string" && typeof id.value !== "number")) return unavailable();
      return decodeRotationResult(input.body, id.value);
    } catch {
      return unavailable();
    }
  }

  /** The wire-response page must describe exactly this snapshot and the selected signer (Go matchesNativeResponse). */
  private matchesNativeResponse(page: DecodedRotationResult | undefined, snapshot: RotationServerSnapshot, signer: PinnedRotationSigner): boolean {
    if (page === undefined) return true;
    const trust = snapshot.trust;
    if (page.current.publicKeyB64u !== signer.publicKeyB64u || page.current.kid !== this.snapshotSignerKid(snapshot, signer) ||
      page.head.ordinal !== trust.head.ordinal || page.head.hash !== trust.head.hash) return false;
    if (page.records.length === 0) return page.complete;
    const first = page.records[0];
    for (let start = 0; start < trust.records.length; start++) {
      if (trust.records[start] !== first) continue;
      const end = start + page.records.length;
      if (end > trust.records.length || page.complete !== (end === trust.records.length)) return false;
      for (let index = 0; index < page.records.length; index++) {
        if (trust.records[start + index] !== page.records[index]) return false;
      }
      return true;
    }
    return false;
  }

  private snapshotSignerKid(snapshot: RotationServerSnapshot, signer: PinnedRotationSigner): string {
    const key = snapshot.trust.keys.find((entry) => entry.publicKeyB64u === signer.publicKeyB64u);
    return key === undefined ? "" : key.kid;
  }

  private publish(next: PinnedRotationSigner, reference: string, kid: string): RotationPublication {
    const { snapshot } = this.store.snapshot();
    const trust = snapshot.trust;
    const last = trust.keys[trust.keys.length - 1];
    const tail = snapshot.signerReferences[snapshot.signerReferences.length - 1];
    if (last === undefined || tail === undefined || trust.head.ordinal === ROTATION_MAX_ORDINAL || trust.revision === ROTATION_MAX_ORDINAL ||
      trust.keys.length >= ROTATION_MAX_RETAINED_KEYS || trust.keys.length >= this.announceRingKeys) unavailable();
    if (trust.keys.some((key) => key.kid === kid || key.publicKeyB64u === next.publicKeyB64u)) unavailable();
    const old = this.keys.get(identity(tail.reference, last.kid));
    if (old === undefined || old.publicKeyB64u !== last.publicKeyB64u) unavailable();
    const previous: RotationCheckpoint = last.ordinal === trust.checkpoint.ordinal ? trust.checkpoint
      : { ordinal: last.ordinal, hash: trust.head.hash, kid: last.kid, publicKeyB64u: last.publicKeyB64u, publishedAt: last.notBefore - ROTATION_GRACE_SECONDS };
    const clock = this.store.checkSnapshotClock(snapshot);
    if (clock.highWater > ROTATION_MAX_TIMESTAMP - ROTATION_GRACE_SECONDS) unavailable();
    this.selectSigner(snapshot, clock);
    if (trust.keys.filter((key) => key.notBefore > clock.highWater).length >= MAX_PENDING) unavailable();
    let record: RotationRecord;
    try {
      record = createRotationRecord(trust.binding, previous, old, next, clock.highWater);
    } catch {
      return unavailable();
    }
    const keys: RotationTrustKey[] = trust.keys.map((key, index) => index === trust.keys.length - 1 ? { ...key, knownCutoff: record.activatesAt } : key);
    keys.push({ ordinal: record.ordinal, kid: record.newKid, publicKeyB64u: record.publicKeyB64u, notBefore: record.activatesAt, knownCutoff: null });
    const desired: RotationServerSnapshot = { formatVersion: 1,
      signerReferences: [...snapshot.signerReferences, { kid, reference }],
      trust: { ...trust, head: { ordinal: record.ordinal, hash: record.hash }, records: [...trust.records, record.wire], keys,
        revision: trust.revision + 1, clock } };
    this.store.compareAndSwap(snapshot, desired, clock);
    return Object.freeze({ record, revision: desired.trust.revision });
  }
}
