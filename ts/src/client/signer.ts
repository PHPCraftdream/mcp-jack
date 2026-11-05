/** Ed25519 request signer abstraction; InMemorySigner signs with an in-process private key (port of Go client/signer.go). */
import { createPrivateKey, createPublicKey, randomBytes, sign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { keyId } from "../encoding.js";

/** The fixed Ed25519 PKCS#8 DER prefix; appending the 32-byte seed yields a valid private key. */
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** Signer produces Ed25519 signatures over the exact message bytes. KID must equal keyId(publicKey()) (spec 01 section 2). */
export interface Signer {
  /** Returns the 64-byte Ed25519 signature of message. */
  sign(message: Uint8Array): Uint8Array;
  /** Returns the 32-byte raw Ed25519 public key. */
  publicKey(): Uint8Array;
  /** Returns keyId(publicKey()). */
  kid(): string;
}

/** InMemorySigner signs with an in-process Ed25519 private key derived from a 32-byte seed. */
export class InMemorySigner implements Signer {
  #priv: KeyObject;
  #pub: Uint8Array;
  #kid: string;

  constructor(seed: Uint8Array) {
    if (seed.length !== 32) {
      throw new Error(`jack client: signer seed must be exactly 32 bytes, got ${seed.length}`);
    }
    this.#priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" });
    // SPKI DER is a fixed 44-byte header followed by the 32-byte raw key.
    const der = createPublicKey(this.#priv).export({ type: "spki", format: "der" });
    this.#pub = new Uint8Array(der.subarray(der.length - 32));
    this.#kid = keyId(this.#pub);
  }

  /** Returns the Ed25519 signature of message. */
  sign(message: Uint8Array): Uint8Array {
    return new Uint8Array(sign(null, Buffer.from(message), this.#priv));
  }

  /** Returns a fresh copy of the 32-byte public key each call. */
  publicKey(): Uint8Array {
    return new Uint8Array(this.#pub);
  }

  /** Returns the key identifier of the public key. */
  kid(): string {
    return this.#kid;
  }
}

/** Creates a signer from a cryptographically random seed. */
export function generateSigner(): InMemorySigner {
  return new InMemorySigner(randomBytes(32));
}
