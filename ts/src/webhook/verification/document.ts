import { checkDelivery } from "../ssrf/delivery.js";
import { checkCallbackUrl } from "../ssrf/url.js";
import { pathCovers } from "./allowlist.js";

const MAX_RECEIVERS = 64;
const MAX_RECEIVER_PATH = 1024;
const MAX_BODY_BYTES = 8192;
const DEFAULT_DOC_TTL = 300;
const CONTROL_OR_MARK_RE = /[?#\u0000-\u001f\u007f]/;

/** The receiver document path at the callback's origin (R5.9). */
export const WELL_KNOWN_PATH = "/.well-known/mcp-webhook-receiver.json";

/** The result of parsing a receiver document (R5.9). */
export type ReceiverDoc =
  | { readonly ok: true; readonly receivers: readonly string[] }
  | { readonly ok: false; readonly code: "invalid_document"; readonly reason: string };

/** Parses the JSON document and rejects it on the first invalid receiver path (R5.9). */
export function parseReceiverDoc(text: string): ReceiverDoc {
  const bad = (reason: string): ReceiverDoc => ({ ok: false, code: "invalid_document", reason });
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return bad("json");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return bad("receivers");
  const receivers = (parsed as { readonly receivers?: unknown }).receivers;
  if (!Array.isArray(receivers)) return bad("receivers");
  if (receivers.length < 1 || receivers.length > MAX_RECEIVERS) return bad("count");
  const entries: readonly unknown[] = receivers;
  const paths: string[] = [];
  for (const entry of entries) {
    if (typeof entry !== "string" || entry.length > MAX_RECEIVER_PATH || !entry.startsWith("/") ||
        CONTROL_OR_MARK_RE.test(entry)) {
      return bad("entry");
    }
    if (entry.split("/").some((segment) => segment === "." || segment === "..")) return bad("segment");
    paths.push(entry);
  }
  return { ok: true, receivers: paths };
}

/** The outcome of checking the HTTP response and its receiver document (R5.9). */
export type ReceiverDocFetch =
  | { readonly ok: true; readonly receivers: readonly string[] }
  | { readonly ok: false; readonly code: "document_fetch_failed"; readonly reason: string };

/** Checks HTTP status, body type and byte size, then parses the receiver document (R5.9). */
export function checkReceiverDocFetch(input: {
  readonly status?: number;
  readonly bodyText?: string;
  readonly maxBodyBytes?: number;
}): ReceiverDocFetch {
  const { status, bodyText, maxBodyBytes = MAX_BODY_BYTES } = input;
  return checkFetch(status, bodyText, maxBodyBytes);
}

/** Applies the delivery-time SSRF policy before checking the receiver document response (R5.9, R5.12). */
export function receiverDocRequest(input: {
  readonly url: string;
  readonly answers?: readonly string[];
  readonly allowedRanges?: readonly string[];
  readonly recheck?: readonly string[];
  readonly redirect?: number | null;
  readonly status?: number;
  readonly bodyText?: string;
}): { readonly ok: true; readonly receivers: readonly string[] } |
  { readonly ok: false; readonly code: string; readonly reason: string } {
  const delivery = checkDelivery(input);
  if (delivery.decision === "reject") return { ok: false, code: delivery.code, reason: delivery.reason ?? delivery.code };
  return checkFetch(input.status, input.bodyText, MAX_BODY_BYTES);
}

/** Returns the first receiver entry that covers the path, without decoding or normalization (R5.10). */
export function receiverDocCovers(doc: unknown, urlPath: string): {
  readonly covered: boolean;
  readonly entry: string | null;
} {
  for (const entry of receiversOf(doc)) {
    if (typeof entry === "string" && pathCovers(entry, urlPath)) return { covered: true, entry };
  }
  return { covered: false, entry: null };
}

/** Returns the receiver document URL at the callback origin, or null if the URL is refused (R5.9). */
export function wellKnownUrl(canonicalUrl: string): string | null {
  const checked = checkCallbackUrl(canonicalUrl);
  if (!checked.ok) return null;
  const port = checked.port === 443 ? "" : `:${checked.port}`;
  return `https://${checked.host}${port}${WELL_KNOWN_PATH}`;
}

/** Caps a valid document cache TTL at 300 seconds and uses 300 seconds when it is invalid or absent (R5.9). */
export function docCacheTtl(maxAgeSeconds?: number): number {
  return typeof maxAgeSeconds === "number" && Number.isFinite(maxAgeSeconds) && maxAgeSeconds >= 0
    ? Math.min(maxAgeSeconds, DEFAULT_DOC_TTL)
    : DEFAULT_DOC_TTL;
}

function checkFetch(status: number | undefined, bodyText: string | undefined, maxBodyBytes: number): ReceiverDocFetch {
  const bad = (reason: string): ReceiverDocFetch => ({ ok: false, code: "document_fetch_failed", reason });
  if (!Number.isInteger(status)) return bad("status");
  if (status !== 200) return bad(`status_${status}`);
  if (typeof bodyText !== "string") return bad("body");
  if (Buffer.byteLength(bodyText, "utf8") > maxBodyBytes) return bad("too_large");
  const parsed = parseReceiverDoc(bodyText);
  return parsed.ok ? parsed : bad(parsed.reason);
}

function receiversOf(doc: unknown): readonly unknown[] {
  if (Array.isArray(doc)) return doc;
  if (doc === null || typeof doc !== "object") return [];
  const receivers = (doc as { readonly receivers?: unknown }).receivers;
  return Array.isArray(receivers) ? receivers : [];
}
