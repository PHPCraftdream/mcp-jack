import { sha256Bytes } from "../crypto/primitives.js";
import { checkCallbackUrl } from "../ssrf/url.js";
import type { CallbackUrlCheck } from "../ssrf/url.js";

const SUBSCRIPTION_DOMAIN = "mcp-jack/webhook1/subscription";

/** Serializes JSON values using the RFC 8785 subset in spec 06 R8.3. */
export function jcs(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("jcs cannot serialize a non-finite number");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (typeof value === "object") {
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype === Object.prototype || prototype === null) {
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record).sort();
      return `{${keys.map((key) => `${JSON.stringify(key)}:${jcs(record[key])}`).join(",")}}`;
    }
  }
  throw new Error(`jcs cannot serialize a ${typeof value}`);
}

/** The derived subscription key or the reason it could not be derived. */
export type SubscriptionKeyResult =
  | {
      readonly ok: true;
      readonly id: string;
      readonly canonical_url: string;
      readonly canonical_arguments: string;
      readonly jcs_input: string;
    }
  | { readonly ok: false; readonly code: "invalid_arguments"; readonly reason: string }
  | {
      readonly ok: false;
      readonly code: "scheme_not_https" | "invalid_callback_url" | "not_a_hostname";
      readonly reason?: string;
    };

/** The four input components of a subscription key (spec 06 R8.1). */
export interface SubscriptionKeyInput {
  readonly principal: string;
  readonly url: string;
  readonly name: string;
  readonly arguments?: unknown;
}

/** Validates and canonicalizes the key components and derives the subscription id (spec 06 R8.2-R8.4). */
export function subscriptionKey(input: SubscriptionKeyInput): SubscriptionKeyResult {
  const { principal, url, name } = input;
  if (typeof principal !== "string") return { ok: false, code: "invalid_arguments", reason: "principal" };
  if (typeof name !== "string") return { ok: false, code: "invalid_arguments", reason: "name" };
  const checked = checkCallbackUrl(url);
  if (!checked.ok) return checked;

  const value = input.arguments ?? null;
  let canonicalArguments: string;
  let jcsInput: string;
  try {
    canonicalArguments = jcs(value);
    jcsInput = jcs([SUBSCRIPTION_DOMAIN, principal, checked.canonical, name, value]);
  } catch {
    return { ok: false, code: "invalid_arguments", reason: "arguments" };
  }

  const digest = sha256Bytes(new TextEncoder().encode(jcsInput));
  const hex = Array.from(digest.subarray(0, 8), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return {
    ok: true,
    id: `sub_${hex}`,
    canonical_url: checked.canonical,
    canonical_arguments: canonicalArguments,
    jcs_input: jcsInput,
  };
}

/** Checks a callback URL and returns its canonical form or refusal (spec 06 R8.2). */
export function canonicalUrl(value: unknown): CallbackUrlCheck {
  return checkCallbackUrl(value);
}
