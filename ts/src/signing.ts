/** Signing-string construction (spec 01 sections 3.1 and 5, spec 03 section 3.1): UTF-8 lines joined with LF, no trailing LF. */
import { bodyHash } from "./encoding.js";

// The signing string is signed/verified over its UTF-8 encoding (TextEncoder);
// these builders stay string-level like Go.

/** RequestSigningString: the eight-line v1 request signing string "mcp-jack/v1/request", method, target, aud, kid, ts, nonce, body-hash (spec 01 section 3.1). */
export function requestSigningString(method: string, target: string, aud: string, kid: string, ts: number, nonce: string, body: Uint8Array): string {
  return [
    "mcp-jack/v1/request",
    method,
    target,
    aud,
    kid,
    String(ts),
    nonce,
    bodyHash(body),
  ].join("\n");
}

/** ResponseSigningString: the six-line v1 response signing string "mcp-jack/v1/response", status (decimal), request-sig, kid, ts, body-hash (spec 01 section 5). */
export function responseSigningString(status: number, requestSig: string, kid: string, ts: number, body: Uint8Array): string {
  return [
    "mcp-jack/v1/response",
    String(status),
    requestSig,
    kid,
    String(ts),
    bodyHash(body),
  ].join("\n");
}

/** RotateProofString: the five-line rotate proof string "mcp-jack/v1/rotate", aud, old kid, new kid, ts (spec 03 section 3.1). */
export function rotateProofString(aud: string, oldKid: string, newKid: string, ts: number): string {
  return ["mcp-jack/v1/rotate", aud, oldKid, newKid, String(ts)].join("\n");
}
