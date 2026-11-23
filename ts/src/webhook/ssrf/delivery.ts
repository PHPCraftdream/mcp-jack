/** Delivery-time SSRF checking of spec 06 section 6 (R6.8-R6.11); pure, deterministic, no resolver, no I/O. */
import { classifyAddress, classifyWithRanges } from "./address.js";
import { checkCallbackUrl } from "./url.js";

/**
 * The refusal code of a delivery check: the callback URL failure codes restated for delivery, plus
 * `redirect_refused` (R6.10), `no_answer` and `blocked_address` (R6.8) and `dns_rebinding` (R6.9).
 */
export type DeliveryFailureCode =
  | "scheme_not_https"
  | "invalid_callback_url"
  | "not_a_hostname"
  | "redirect_refused"
  | "no_answer"
  | "blocked_address"
  | "dns_rebinding";

/**
 * One delivery decision: `allow` names the address to connect to, the `Host` header value and the
 * TLS SNI name (null for an IP literal); `reject` names the failure code and an optional reason.
 * For URL failures, the reason is present only when the URL check returned one.
 */
export type DeliveryDecision =
  | {
      readonly decision: "allow";
      readonly reason: string;
      readonly connect: {
        readonly address: string;
        readonly hostHeader: string;
        readonly sni: string | null;
      };
    }
  | { readonly decision: "reject"; readonly code: DeliveryFailureCode; readonly reason?: string };

/**
 * The input of a delivery check: the callback URL, the resolver answers, the recheck answers, the
 * operator override ranges and the redirect status when a `3xx` was seen.
 */
export interface DeliveryCheckInput {
  readonly url: string;
  readonly answers?: readonly string[];
  readonly recheck?: readonly string[];
  readonly allowedRanges?: readonly string[];
  readonly redirect?: number | null;
}

/**
 * Decides one delivery attempt: the URL is checked first and a failure carries its own code, a
 * redirect status is always refused, an IP-literal host is its own single candidate and a name uses
 * the resolver answers, an empty answer list is `no_answer`, every candidate is classified in
 * resolver order with the operator override applied and the first rejection decides, and a recheck
 * answer whose address differs from the connected one is `dns_rebinding` (R6.8-R6.11).
 */
export function checkDelivery(input: DeliveryCheckInput): DeliveryDecision {
  const checked = checkCallbackUrl(input.url);
  if (!checked.ok) {
    return checked.reason === undefined
      ? { decision: "reject", code: checked.code }
      : { decision: "reject", code: checked.code, reason: checked.reason };
  }
  const redirect = input.redirect ?? null;
  if (redirect !== null) return { decision: "reject", code: "redirect_refused", reason: `status_${redirect}` };
  const literal = checked.hostKind !== "name";
  const candidates: readonly string[] = literal ? [checked.hostValue] : (input.answers ?? []);
  if (candidates.length === 0) return { decision: "reject", code: "no_answer", reason: "no_records" };
  const allowedRanges = input.allowedRanges ?? [];
  let address: string | null = null;
  let reason = "";
  for (const candidate of candidates) {
    const verdict = classifyWithRanges(candidate, allowedRanges);
    if (verdict.decision !== "allow") return { decision: "reject", code: "blocked_address", reason: verdict.reason };
    if (address === null) {
      address = verdict.address;
      reason = verdict.reason;
    }
  }
  // An allow verdict always carries its normalized address and the candidates are non-empty, so this
  // guard only covers the empty answer list already refused as no_answer.
  if (address === null) return { decision: "reject", code: "no_answer", reason: "no_records" };
  const recheck = input.recheck ?? [];
  if (recheck.length > 0) {
    const next = classifyAddress(recheck[0] ?? "");
    if (next.address !== address) return { decision: "reject", code: "dns_rebinding", reason: "address_changed" };
  }
  const suffix = checked.port === 443 ? "" : `:${checked.port}`;
  return {
    decision: "allow",
    reason,
    connect: {
      address,
      hostHeader: `${checked.host}${suffix}`,
      sni: literal ? null : checked.hostValue,
    },
  };
}
