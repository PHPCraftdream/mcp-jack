/**
 * Role-opposite software user-key foundation. The original raw-key classes
 * and entry points remain available: client keys sign without retaining a
 * seed, server identities are public-only, and the legacy issuance handoff is
 * separate from the server identity. Strict portable envelopes and bound
 * client credentials are additive named exports from user-key-transfer.ts;
 * they do not alter the raw methods or add a private-export method to a client
 * signer or server identity.
 */
import { createPrivateKey, createPublicKey, randomBytes, sign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { keyId } from "./encoding.js";
import { validatePublicKey } from "./ed25519.js";

// The same fixed Ed25519 PKCS#8 DER prefix already used by client/signer.ts and
// server/fetch.ts, duplicated on purpose so both roles can use this module
// without importing client internals.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** Shared internal seed handling: builds the Ed25519 private KeyObject and derives the 32-byte public key from one 32-byte seed (same construction as client/signer.ts). */
function importSeed(seed: Uint8Array): { priv: KeyObject; pub: Uint8Array } {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" });
  // SPKI DER is 44 bytes total for Ed25519: a fixed 12-byte header followed by the 32-byte raw key.
  const der = createPublicKey(priv).export({ type: "spki", format: "der" });
  return { priv, pub: new Uint8Array(der.subarray(der.length - 32)) };
}

/** The client side of a user key: retains a private KeyObject for signing for as long as the object lives and never retains the seed bytes; exposes only the public identity; satisfies the client package's Signer interface structurally (sign/publicKey/kid), so no adapter and no new Signer method are needed and non-extractable signer implementations stay usable. */
export class ClientUserKey {
  #priv: KeyObject;
  #pub: Uint8Array;
  #kid: string;

  /** Imports a client user key from exactly 32 seed bytes; the seed bytes are copied into the key object at construction and the seed itself is NOT retained, so no private export exists. Later mutation of the argument does not affect the key. */
  constructor(seed: Uint8Array) {
    // Runtime guard for JS callers; never echo the value.
    if (!(seed instanceof Uint8Array)) {
      throw new Error("jack user-key: seed must be a Uint8Array");
    }
    if (seed.length !== 32) {
      throw new Error(`jack user-key: seed must be exactly 32 bytes, got ${seed.length}`);
    }
    const derived = importSeed(new Uint8Array(seed));
    this.#priv = derived.priv;
    this.#pub = derived.pub;
    this.#kid = keyId(this.#pub);
  }

  /** Returns the 64-byte Ed25519 signature of message over the exact message bytes. */
  sign(message: Uint8Array): Uint8Array {
    return new Uint8Array(sign(null, Buffer.from(message), this.#priv));
  }

  /** Returns a fresh 32-byte copy of the raw public key each call. */
  publicKey(): Uint8Array {
    return new Uint8Array(this.#pub);
  }

  /** Returns keyId(publicKey()) as computed at construction: base64url(SHA-256(public key)). */
  kid(): string {
    return this.#kid;
  }
}

/** Creates a client user key from node:crypto CSPRNG bytes. */
export function generateClientUserKey(): ClientUserKey {
  return new ClientUserKey(randomBytes(32));
}

/** The server side of a user key: imports a strictly validated public identity only and exposes no private access — no sign, no seed, no private export, and no way to recover a private key from it. */
export class ServerUserKey {
  #pub: Uint8Array;
  #kid: string;

  /** Imports a public user key; validity is delegated to the SDK's existing Ed25519 oracle (validatePublicKey), so any invalid input arrives as the SDK's JackError KEY_REJECTED. */
  constructor(publicKey: Uint8Array) {
    // Runtime guard for JS callers; never echo the value.
    if (!(publicKey instanceof Uint8Array)) {
      throw new Error("jack user-key: public key must be a Uint8Array");
    }
    // Copy before validating: admission and the stored identity always refer to the same owned bytes, so external mutation cannot substitute unchecked bytes between validation and storage.
    const owned = new Uint8Array(publicKey);
    const err = validatePublicKey(owned);
    if (err !== null) {
      throw err;
    }
    this.#pub = owned;
    this.#kid = keyId(this.#pub);
  }

  /** Returns a fresh 32-byte copy of the raw public key each call. */
  publicKey(): Uint8Array {
    return new Uint8Array(this.#pub);
  }

  /** Returns keyId(publicKey()) as computed at construction: base64url(SHA-256(public key)). */
  kid(): string {
    return this.#kid;
  }
}

/**
 * The issuance-only explicit private handoff/export surface, deliberately
 * separate from ServerUserKey: `exportSeed()` is the one explicit private
 * export. It returns a FRESH plaintext copy of the 32-byte seed each call —
 * the secret is NOT consumed by the call, so every call yields the same
 * secret. This is the plaintext secret for handing the issued key to the
 * client out of band. As with all JavaScript secrets, JavaScript cannot
 * zeroize: the engine and GC keep uncontrolled copies and the bytes stay
 * readable until collected, so this is NOT hardened storage. Default
 * serialization and inspection of this object must not reveal the secret
 * (the seed lives in a private field).
 */
export class UserKeyHandoff {
  #seed: Uint8Array;

  /** Imports exactly 32 seed bytes and copies them into the owned private snapshot; later mutation of the argument does not affect the handoff. */
  constructor(seed: Uint8Array) {
    // Runtime guard for JS callers; never echo the value.
    if (!(seed instanceof Uint8Array)) {
      throw new Error("jack user-key: seed must be a Uint8Array");
    }
    const owned = new Uint8Array(seed);
    if (owned.length !== 32) {
      throw new Error(`jack user-key: seed must be exactly 32 bytes, got ${owned.length}`);
    }
    this.#seed = owned;
  }

  /** Explicit private export: a FRESH copy of the 32-byte seed each call; the stored secret is not consumed. */
  exportSeed(): Uint8Array {
    return new Uint8Array(this.#seed);
  }
}

/** One locally issued key pair: `server` is the public-only identity to retain (e.g. registry material; never any private key), `handoff` is the private handoff surface whose exportSeed() returns a fresh copy of the seed on every call (the secret is not consumed) for delivery to the client out of band. */
export interface IssuedUserKey {
  readonly server: ServerUserKey;
  readonly handoff: UserKeyHandoff;
}

/** Server-LOCAL issuance of a fresh user key pair; the SDK performs no network issuance and the transport for handing the issued key to the client is the deployer's responsibility. The returned server object is public-only. */
export function issueUserKey(): IssuedUserKey {
  const handoff = new UserKeyHandoff(randomBytes(32));
  const { pub } = importSeed(handoff.exportSeed());
  return { server: new ServerUserKey(pub), handoff };
}
