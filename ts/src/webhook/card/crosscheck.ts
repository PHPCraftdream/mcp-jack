import { validateJwk } from "./jwk.js";
import type { AcceptedWebhookKey } from "../crypto/signatures.js";

function member(value: unknown, name: string): unknown {
  return (value as Record<string, unknown> | null | undefined)?.[name];
}

function canonicalKeySet(values: readonly unknown[]): string | null {
  const list: readonly unknown[] = Array.isArray(values) ? values : [];
  const records: Pick<AcceptedWebhookKey, "kty" | "crv" | "x" | "kid">[] = [];
  for (const entry of list) {
    const verdict = validateJwk(entry);
    if (!verdict.ok) return null;
    const { kty, crv, x, kid } = verdict.key;
    records.push({ kty, crv, x, kid });
  }
  records.sort((left, right) => (left.kid < right.kid ? -1 : left.kid > right.kid ? 1 : 0));
  return JSON.stringify(records);
}

/** Validates and compares card and tool signing keys when the R7.6 cross-check is required. */
export function crossCheckWebhookKey({ keys = [], toolResult = null, require = false }: {
  readonly keys?: readonly unknown[];
  readonly toolResult?: unknown;
  readonly require?: boolean;
} = {}):
  | { readonly ok: true }
  | { readonly ok: false; readonly code: "webhook_key_mismatch" | "webhook_key_missing" } {
  if (require !== true) return { ok: true };
  const published = member(member(member(toolResult, "webhook_key"), "signing_keys"), "keys");
  if (!Array.isArray(published)) return { ok: false, code: "webhook_key_missing" };
  const card = canonicalKeySet(keys);
  const tool = canonicalKeySet(published);
  if (card === null || tool === null || card !== tool) return { ok: false, code: "webhook_key_mismatch" };
  return { ok: true };
}
