/** Client-side request signing and response verification (spec 01 sections 3-5; port of Go client/auth.go, following the spec where it disagrees with Go). */
import { randomBytes } from "node:crypto";
import { parseResponseAuth, formatRequestAuth } from "../auth-header.js";
import { BadBase64UrlError, decodeBase64URLFixed, encodeBase64URL, keyId } from "../encoding.js";
import { Code, JackError } from "../errors.js";
import { requestSigningString, responseSigningString } from "../signing.js";
import { verify } from "../ed25519.js";
import type { Signer } from "./signer.js";

/** Clock returning unix seconds. */
export type Clock = () => number;

/** NonceSource returns the 16 random nonce bytes for one request; it throws to report failure (Go returns an error). */
export type NonceSource = () => Uint8Array | Promise<Uint8Array>;

/** Default timestamp acceptance window in seconds (spec 01 section 4 step 6). */
export const DEFAULT_WINDOW_SECONDS = 30;

/** Required nonce length (spec 01 section 2). */
export const NONCE_SIZE = 16;

/** RandomNonce: 16 bytes from node:crypto randomBytes. */
export function randomNonce(): Uint8Array {
  return new Uint8Array(randomBytes(NONCE_SIZE));
}

/** Whether s contains an ASCII control character; the signing target must not embed line breaks (spec 01 section 3.1). */
function hasControl(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) {
      return true;
    }
  }
  return false;
}

/** SignRequest builds the signed Jack-Auth header value for one request (spec 01 sections 3 and 3.1). */
export function signRequest(signer: Signer, aud: string, method: string, target: string, body: Uint8Array, nonce: Uint8Array, now: number): string {
  if (nonce.length !== NONCE_SIZE) {
    throw new Error(`jack client: nonce must be exactly ${NONCE_SIZE} bytes, got ${nonce.length}`);
  }
  if (method === "" || hasControl(method)) {
    throw new Error("jack client: empty or control-character HTTP method");
  }
  if (target === "" || hasControl(target)) {
    throw new Error("jack client: empty or control-character target");
  }
  const kid = signer.kid();
  const nonceB64 = encodeBase64URL(nonce);
  const sig = signer.sign(new TextEncoder().encode(requestSigningString(method, target, aud, kid, now, nonceB64, body)));
  return formatRequestAuth({ kid, ts: now, nonce: nonceB64, sig: encodeBase64URL(sig) });
}

/**
 * VerifyResponse is the client-side mirror of spec 01 section 5: it checks
 * that the response was signed by the pinned server key, over the request
 * signature, within the window. Client-side failures carry httpStatus 0
 * (these codes are never sent over HTTP; Go's VerifyResponse remaps them to 0 the same way).
 */
export function verifyResponse(serverKey: Uint8Array, status: number, headerValues: readonly string[], requestSig: string, body: Uint8Array, now: number, windowSeconds: number): void {
  if (serverKey.length !== 32) {
    // Configuration misuse, not a protocol rejection.
    throw new Error(`jack client: pinned server key must be exactly 32 bytes, got ${serverKey.length}`);
  }
  const window = windowSeconds <= 0 ? DEFAULT_WINDOW_SECONDS : windowSeconds;

  let auth;
  try {
    auth = parseResponseAuth(headerValues);
  } catch (err) {
    if (err instanceof JackError) {
      // Same code, no HTTP status: the check happens on the client side.
      throw new JackError(0, err.code, err.message);
    }
    throw err;
  }
  if (auth.kid !== keyId(serverKey)) {
    throw new JackError(0, Code.UNKNOWN_SERVER_KEY, "response signed by an unpinned key");
  }
  if (Math.abs(now - auth.ts) > window) {
    throw new JackError(0, Code.TIMESTAMP_OUT_OF_WINDOW, "response timestamp outside the acceptance window");
  }
  let sig: Uint8Array;
  try {
    sig = decodeBase64URLFixed(auth.sig, 64);
  } catch (err) {
    if (err instanceof BadBase64UrlError) {
      // The parser already enforces a canonical 64-byte sig, so any error
      // here can only be a signature mismatch, not a malformed header.
      throw new JackError(0, Code.BAD_SIGNATURE, "malformed response signature");
    }
    throw err;
  }
  const msg = new TextEncoder().encode(responseSigningString(status, requestSig, auth.kid, auth.ts, body));
  if (!verify(serverKey, msg, sig)) {
    throw new JackError(0, Code.BAD_SIGNATURE, "response signature does not verify");
  }
}
