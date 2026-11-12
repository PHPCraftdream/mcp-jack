import { parseResponseAuth } from "../auth-header.js";
import { decodeBase64URLFixed, keyId } from "../encoding.js";
import { validatePublicKey } from "../ed25519.js";
import { Code, JackError } from "../errors.js";
import { RotationError, ROTATION_MAX_TIMESTAMP } from "../rotation-record.js";
import { verifyResponse } from "./auth.js";

/** Только independently trusted/ACKed snapshot, не данные response payload. */
export interface RotationResponseKey {
  readonly publicKeyB64u: string;
  readonly notBefore: number;
  readonly knownCutoff?: number;
}

/** Crypto/interval metadata, не durable ClockGuard readiness или trust ACK. */
export interface RotationCarrier {
  readonly kid: string;
  readonly timestamp: number;
}

function timestamp(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= ROTATION_MAX_TIMESTAMP;
}

/**
 * Unknown kid → freshness → signature → known interval; body не парсится.
 * Transport обязан ограничить/удерживать exact bytes. Caller затем выполняет
 * durable ClockGuard до decode и final interval/bridge/revision/whole-state CAS.
 * Нет fetch, retry, discovery или изменения static credentials.
 */
export function verifyRotationCarrier(
  known: ReadonlyMap<string, RotationResponseKey>,
  status: number,
  headers: readonly string[],
  requestSig: string,
  body: Uint8Array,
  now: number,
  windowSeconds: number,
): RotationCarrier {
  if (!Number.isSafeInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > 120) throw new RotationError("rotation_state_unknown");
  let auth;
  try {
    auth = parseResponseAuth(headers);
  } catch (error) {
    if (error instanceof JackError) throw new JackError(0, error.code, error.message);
    throw error;
  }
  const key = known.get(auth.kid);
  if (key === undefined) throw new JackError(0, Code.UNKNOWN_SERVER_KEY, "response signed by an unacknowledged key");
  let publicKey: Uint8Array;
  try {
    publicKey = decodeBase64URLFixed(key.publicKeyB64u, 32);
  } catch {
    throw new RotationError("rotation_state_unknown");
  }
  const lower = key.notBefore;
  const upper = key.knownCutoff;
  if (keyId(publicKey) !== auth.kid || validatePublicKey(publicKey) !== null || !timestamp(lower) || (upper !== undefined && (!timestamp(upper) || upper < lower))) throw new RotationError("rotation_state_unknown");
  // Invalid local clock не превращается в NaN freshness bypass; caller обязан latch/fence.
  if (!timestamp(now)) throw new RotationError("rotation_clock_unavailable");
  verifyResponse(publicKey, status, headers, requestSig, body, now, windowSeconds);
  if (auth.ts < lower || (upper !== undefined && (auth.ts >= upper || now >= upper))) throw new RotationError("rotation_key_interval");
  return Object.freeze({ kid: auth.kid, timestamp: auth.ts });
}
