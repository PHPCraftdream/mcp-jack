import { validatePublicKey } from "./ed25519.js";
import { encodeBase64URL, keyId } from "./encoding.js";
import { ROTATION_MAX_RETAINED_KEYS } from "./rotation-chain.js";
import type { RotationCheckpoint } from "./rotation-chain.js";
import { RotationError, ROTATION_GRACE_SECONDS, ROTATION_MAX_ORDINAL, ROTATION_MAX_TIMESTAMP } from "./rotation-record.js";
import type { RotationRecord } from "./rotation-record.js";
import { createRotationRecord } from "./rotation-sign.js";
import type { RotationSigner } from "./rotation-sign.js";
import type { RotationServerSnapshot } from "./rotation-server-state.js";
import { ROTATION_MAX_SIGNER_REFERENCE_BYTES } from "./rotation-server-state.js";
import type { RotationServerStore } from "./rotation-server-store.js";
import type { RotationClockTuple, RotationTrustKey } from "./rotation-trust.js";

const MAX_PENDING = 128;
const MAX_RETIRED = 1024;

/** Заранее настроенный handle подписанта: reference не заменяет проверку публичного ключа. */
export interface RotationServerKey {
  readonly reference: string;
  readonly signer: RotationSigner;
}

/** Только после exact durable ACK; это не HTTP delivery. */
export interface RotationPublication {
  readonly record: RotationRecord;
  readonly revision: number;
}

/** Pinned identity подписанта: публичный ключ скопирован и не меняется вместе с callback. */
export interface PinnedRotationSigner extends RotationSigner {
  readonly publicKeyB64u: string;
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
 * Связывает concrete server store с заранее настроенным inventory подписанием: выбор подписанта,
 * явная публикация одного next key. Inventory задаётся только out-of-band; custody и lifecycle
 * signer handles принадлежат caller. Signer callbacks должны быть bounded и не reentrant.
 */
export class RotationServerProvider {
  private readonly keys = new Map<string, PinnedRotationSigner>();
  private publishing = false;

  /** Не создаёт state и не разрешает publication; отказывает, если ring не готов к serving. */
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

  /** Readiness: committed ring, свежий ClockGuard и все pending/current handles доступны. */
  ready(): void {
    const release = this.store.acquireServingLease();
    try {
      const { snapshot } = this.store.snapshot();
      this.selectSigner(snapshot, this.store.checkSnapshotClock(snapshot));
    } finally {
      release();
    }
  }

  /**
   * Требует handles всех pending keys и текущего signer; retired handles необязательны. Выбирает
   * eligible key с наибольшим ordinal и не делает fallback. Snapshot уже полностью проверен;
   * после fresh clock sample остаётся только interval arithmetic.
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

  /**
   * Одна explicit authorization для заранее настроенного next handle. P фиксируется одним fresh
   * sample; отказ, конфликт или unknown не повторяются автоматически.
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

  private publish(next: PinnedRotationSigner, reference: string, kid: string): RotationPublication {
    const { snapshot } = this.store.snapshot();
    const trust = snapshot.trust;
    const last = trust.keys[trust.keys.length - 1];
    const tail = snapshot.signerReferences[snapshot.signerReferences.length - 1];
    if (last === undefined || tail === undefined || trust.head.ordinal === ROTATION_MAX_ORDINAL || trust.revision === ROTATION_MAX_ORDINAL ||
      trust.keys.length >= ROTATION_MAX_RETAINED_KEYS) unavailable();
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
