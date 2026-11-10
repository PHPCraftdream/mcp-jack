import type { Signer } from "./client/signer.js";
import { validatePublicKey, verify } from "./ed25519.js";
import { decodeBase64URLFixed, encodeBase64URL, keyId } from "./encoding.js";
import { rotationBindingError } from "./rotation-binding.js";
import type { RotationCheckpoint } from "./rotation-chain.js";
import { parseRotationRecord, RotationError, ROTATION_DOMAIN, ROTATION_GRACE_SECONDS, ROTATION_MAX_ORDINAL, ROTATION_MAX_TIMESTAMP } from "./rotation-record.js";
import type { RotationBinding, RotationRecord } from "./rotation-record.js";

/** Достаточны public key и signing capability; private export не требуется. */
export type RotationSigner = Pick<Signer, "publicKey" | "sign">;

function reject(code: string): never {
  throw new RotationError(code);
}

function publicSnapshot(signer: RotationSigner): Uint8Array {
  let publicKey: Uint8Array;
  try {
    const supplied = signer.publicKey();
    if (!(supplied instanceof Uint8Array) || supplied.length !== 32) reject("signer");
    publicKey = Uint8Array.from(supplied);
  } catch {
    return reject("signer");
  }
  if (validatePublicKey(publicKey) !== null) reject("signer_key");
  return publicKey;
}

function signature(signer: RotationSigner, message: string): Uint8Array {
  try {
    const supplied = signer.sign(Buffer.from(message, "ascii"));
    if (!(supplied instanceof Uint8Array) || supplied.length !== 64) reject("signer");
    return Uint8Array.from(supplied);
  } catch {
    return reject("signer");
  }
}

/** Создаёт exact record без публикации, trust mutation, persistence или retry. */
export function createRotationRecord(
  binding: RotationBinding,
  previous: RotationCheckpoint,
  oldSigner: RotationSigner,
  nextSigner: RotationSigner,
  publishedAt: number,
): RotationRecord {
  // Provider callbacks не могут изменить входы после проверок.
  const capturedBinding = Object.freeze({ endpoint: binding.endpoint, aud: binding.aud });
  const checkpoint = Object.freeze({ ...previous });
  const bindingError = rotationBindingError(capturedBinding);
  if (bindingError !== undefined) reject(bindingError);
  if (!Number.isSafeInteger(checkpoint.ordinal) || checkpoint.ordinal < 0 || checkpoint.ordinal >= ROTATION_MAX_ORDINAL) reject("ordinal");
  if (!Number.isSafeInteger(publishedAt) || publishedAt < 0 || publishedAt > ROTATION_MAX_TIMESTAMP - ROTATION_GRACE_SECONDS) reject("timestamp");
  if (!Number.isSafeInteger(checkpoint.publishedAt) || checkpoint.publishedAt < 0 || checkpoint.publishedAt > ROTATION_MAX_TIMESTAMP || publishedAt < checkpoint.publishedAt) reject("publication_order");
  if (checkpoint.ordinal === 0) {
    if (checkpoint.hash !== "-") reject("previous_hash");
  } else {
    try { decodeBase64URLFixed(checkpoint.hash, 32); } catch { reject("previous_hash"); }
  }
  const oldPublic = publicSnapshot(oldSigner);
  const nextPublic = publicSnapshot(nextSigner);
  const oldKid = keyId(oldPublic);
  const newKid = keyId(nextPublic);
  if (oldKid !== checkpoint.kid || encodeBase64URL(oldPublic) !== checkpoint.publicKeyB64u) reject("anchor_key_id");
  if (oldKid === newKid) reject("key_reuse");
  const body = [
    ROTATION_DOMAIN,
    encodeBase64URL(Buffer.from(capturedBinding.endpoint, "utf8")),
    encodeBase64URL(Buffer.from(capturedBinding.aud, "utf8")),
    String(checkpoint.ordinal + 1),
    checkpoint.hash,
    oldKid,
    newKid,
    encodeBase64URL(nextPublic),
    String(publishedAt),
    String(publishedAt + ROTATION_GRACE_SECONDS),
  ].join("\n");
  const nextMessage = `${ROTATION_DOMAIN}/next-proof\n${body}`;
  const nextProof = signature(nextSigner, nextMessage);
  if (!verify(nextPublic, Buffer.from(nextMessage, "ascii"), nextProof)) reject("new_proof");
  const nextProofText = encodeBase64URL(nextProof);
  // OLD вызывается только после проверки NEXT possession proof.
  const oldMessage = `${ROTATION_DOMAIN}/authorize\n${body}\n${nextProofText}`;
  const oldProof = signature(oldSigner, oldMessage);
  if (!verify(oldPublic, Buffer.from(oldMessage, "ascii"), oldProof)) reject("old_authorization");
  const wire = Buffer.from(`${body}\n${nextProofText}\n${encodeBase64URL(oldProof)}`, "ascii");
  return parseRotationRecord(wire, capturedBinding, new Map([[oldKid, encodeBase64URL(oldPublic)]]));
}
