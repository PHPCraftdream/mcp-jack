const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
const ISO_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/;
const MONTH_DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/** The control envelope types of spec 06 R1.3. */
export type WebhookEnvelopeType = "gap" | "terminated" | "verification";

/** A validated body; a null type denotes an EventOccurrence. */
export interface ParsedEnvelope {
  readonly type: WebhookEnvelopeType | null;
  readonly message: Record<string, unknown>;
}

/** A validated envelope or its R3.18 rejection code. */
export type EnvelopeParse =
  | { readonly ok: true; readonly envelope: ParsedEnvelope }
  | { readonly ok: false; readonly code: "malformed_body" | "unknown_envelope_type" };

function hasOwn(object: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmpty(value: unknown): boolean {
  return typeof value === "string" && value.length > 0;
}

function isEnvelopeCursor(value: unknown): boolean {
  // R1.3 accepts any string or null, without the R8.9 lifecycle restrictions.
  return typeof value === "string" || value === null;
}

/** Checks the R1.3 timestamp profile, including calendar, clock and offset ranges. */
export function isEnvelopeTimestamp(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const match = ISO_TIMESTAMP.exec(value);
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (month < 1 || month > 12) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthDays = month === 2 && leap ? 29 : MONTH_DAYS[month - 1];
  if (monthDays === undefined || day < 1 || day > monthDays) return false;
  if (hour > 23 || minute > 59 || second > 59) return false;
  return match[7] === undefined || (Number(match[7]) <= 23 && Number(match[8]) <= 59);
}

function fieldsOk(type: WebhookEnvelopeType | null, message: Record<string, unknown>): boolean {
  if (type === "verification") {
    return typeof message.challenge === "string" && NONCE_RE.test(message.challenge);
  }
  if (type === "gap") {
    return hasOwn(message, "cursor") && isEnvelopeCursor(message.cursor);
  }
  if (type === "terminated") {
    const { error } = message;
    if (!isObject(error)) return false;
    if (!Number.isInteger(error.code) || typeof error.message !== "string") return false;
    return !hasOwn(error, "data") || isObject(error.data);
  }
  if (!hasOwn(message, "data") || !isObject(message.data)) return false;
  if (hasOwn(message, "cursor") && !isEnvelopeCursor(message.cursor)) return false;
  return nonEmpty(message.eventId) && nonEmpty(message.name) && isEnvelopeTimestamp(message.timestamp);
}

/** Parses and validates a raw UTF-8 webhook body (spec 06 R1.3, R3.18). */
export function parseWebhookBody(raw: Uint8Array): EnvelopeParse {
  let message: unknown;
  try {
    message = JSON.parse(Buffer.from(raw).toString("utf8"));
  } catch {
    return { ok: false, code: "malformed_body" };
  }
  if (!isObject(message)) return { ok: false, code: "malformed_body" };
  let type: WebhookEnvelopeType | null = null;
  if (hasOwn(message, "type")) {
    const value = message.type;
    if (value !== "gap" && value !== "terminated" && value !== "verification") {
      return { ok: false, code: "unknown_envelope_type" };
    }
    type = value;
  }
  if (!fieldsOk(type, message)) return { ok: false, code: "malformed_body" };
  return { ok: true, envelope: { type, message } };
}
