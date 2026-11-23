import { validatePublicKey } from "../../core/ed25519.js";
import { encodeBase64URL, keyId } from "../../core/encoding.js";
import { decodeBase64UrlStrict } from "../crypto/primitives.js";
import type { AcceptedWebhookKey } from "../crypto/signatures.js";
import { parseCidr } from "../ssrf/tables.js";

/** The first failed check for an individual JWK (spec 06 R7.3). */
export type JwkRejectionReason =
  | "kty" | "crv" | "x_encoding" | "x_length" | "x_key"
  | "kid_missing" | "kid_mismatch" | "alg" | "use";

/** A validated signing key or the reason its JWK was refused. */
export type JwkValidation =
  | { readonly ok: true; readonly key: AcceptedWebhookKey }
  | { readonly ok: false; readonly reason: JwkRejectionReason };

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" ? (value as Record<string, unknown>) : null;
}

/** Validates an Ed25519 webhook JWK in the R7.3 check order. */
export function validateJwk(jwk: unknown): JwkValidation {
  const entry = record(jwk);
  if (entry === null || entry.kty !== "OKP") return { ok: false, reason: "kty" };
  if (entry.crv !== "Ed25519") return { ok: false, reason: "crv" };
  const raw = typeof entry.x === "string" ? decodeBase64UrlStrict(entry.x) : null;
  if (raw === null) return { ok: false, reason: "x_encoding" };
  if (raw.length !== 32) return { ok: false, reason: "x_length" };
  if (validatePublicKey(raw) !== null) return { ok: false, reason: "x_key" };
  const kid = entry.kid;
  if (typeof kid !== "string" || kid.length === 0) return { ok: false, reason: "kid_missing" };
  if (kid !== keyId(raw)) return { ok: false, reason: "kid_mismatch" };
  if (entry.alg !== undefined && entry.alg !== "EdDSA") return { ok: false, reason: "alg" };
  if (entry.use !== undefined && entry.use !== "sig") return { ok: false, reason: "use" };
  const x = encodeBase64URL(raw);
  return { ok: true, key: { kid, kty: "OKP", crv: "Ed25519", x, publicKey: x, raw } };
}

/** A refused member of a signing-key set, with its kid when it is a string. */
export interface RejectedJwk {
  readonly kid: string | null;
  readonly reason: string;
}

/** Validates a key set, excludes the MCP server key, then drops all occurrences of duplicate kids. */
export function acceptJwkSet(
  signingKeys: unknown,
  { mcpServerKid = null, mcpServerPublicKey = null }: {
    readonly mcpServerKid?: string | null;
    readonly mcpServerPublicKey?: string | null;
  } = {},
): { readonly accepted: readonly AcceptedWebhookKey[]; readonly rejected: readonly RejectedJwk[] } {
  const keys = (signingKeys as { readonly keys?: unknown } | null | undefined)?.keys;
  const entries: readonly unknown[] = Array.isArray(keys) ? keys : [];
  const valid: AcceptedWebhookKey[] = [];
  const rejected: RejectedJwk[] = [];
  for (const jwk of entries) {
    const verdict = validateJwk(jwk);
    if (verdict.ok) {
      valid.push(verdict.key);
    } else {
      const kid = (jwk as { readonly kid?: unknown } | null | undefined)?.kid;
      rejected.push({ kid: typeof kid === "string" ? kid : null, reason: verdict.reason });
    }
  }
  const surviving: AcceptedWebhookKey[] = [];
  const counts = new Map<string, number>();
  for (const key of valid) {
    if (key.kid === mcpServerKid || key.publicKey === mcpServerPublicKey) {
      rejected.push({ kid: key.kid, reason: "mcp_server_key" });
    } else {
      surviving.push(key);
      counts.set(key.kid, (counts.get(key.kid) ?? 0) + 1);
    }
  }
  const accepted: AcceptedWebhookKey[] = [];
  for (const key of surviving) {
    if ((counts.get(key.kid) ?? 0) > 1) rejected.push({ kid: key.kid, reason: "duplicate_kid" });
    else accepted.push(key);
  }
  return { accepted, rejected };
}

/** An advisory egress CIDR in its original spelling (spec 06 R7.5). */
export interface EgressRange {
  readonly cidr: string;
  readonly family: "ipv4" | "ipv6";
  readonly prefix: number;
}

/** Validates the advisory egress CIDRs, retaining the malformed entries separately (spec 06 R7.5). */
export function parseCidrList(values: unknown): {
  readonly accepted: readonly EgressRange[];
  readonly rejected: readonly { readonly value: unknown; readonly reason: "malformed_cidr" }[];
} {
  const accepted: EgressRange[] = [];
  const rejected: { readonly value: unknown; readonly reason: "malformed_cidr" }[] = [];
  const entries: readonly unknown[] = Array.isArray(values) ? values : [];
  for (const value of entries) {
    const parsed = parseCidr(value);
    if (parsed.ok && typeof value === "string") {
      accepted.push({ cidr: value, family: parsed.family, prefix: parsed.prefix });
    } else {
      rejected.push({ value, reason: "malformed_cidr" });
    }
  }
  return { accepted, rejected };
}
