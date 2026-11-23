/** Callback URL checking of spec 06 R5.11 and section 6 (R6.1-R6.3); hand-parsed, no URL class, no I/O. */
import { parseHost } from "./address.js";

const PORT_TEXT = /^[0-9]+$/;

/** The refusal code of a callback URL check. */
export type CallbackUrlCode = "scheme_not_https" | "invalid_callback_url" | "not_a_hostname";

/** A callback URL parsed into its canonical form, or its refusal code and optional reason (R6.1-R6.3). */
export type CallbackUrlCheck =
  | {
      readonly ok: true;
      readonly scheme: "https";
      readonly host: string;
      readonly port: number;
      readonly path: string;
      readonly query: string;
      readonly canonical: string;
      readonly hostKind: "ipv4" | "ipv6" | "name";
      readonly hostValue: string;
    }
  | { readonly ok: false; readonly code: CallbackUrlCode; readonly reason?: string };

/**
 * Parses and validates a callback URL into its canonical form: https only, no userinfo, fragment or
 * forbidden byte, a present host in 1-65535 with an optional port, and a path without `.` or `..`
 * segments. Bytes are checked as given, never normalized (R5.11, R6.1-R6.3).
 */
export function checkCallbackUrl(value: unknown): CallbackUrlCheck {
  const text = typeof value === "string" ? value : "";
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x21 || code === 0x7f || code > 0x7e) return urlBad("character");
  }
  const marker = text.indexOf("://");
  if (marker === -1) return { ok: false, code: "scheme_not_https" };
  if (text.slice(0, marker).toLowerCase() !== "https") return { ok: false, code: "scheme_not_https" };
  const rest = text.slice(marker + 3);
  let end = rest.length;
  for (let i = 0; i < rest.length; i++) {
    const char = rest.charAt(i);
    if (char === "/" || char === "?" || char === "#") {
      end = i;
      break;
    }
  }
  const authority = rest.slice(0, end);
  const tail = rest.slice(end);
  if (authority.includes("@")) return urlBad("userinfo");
  if (tail.includes("#")) return urlBad("fragment");
  if (authority === "") return urlBad("empty_host");
  const split = splitAuthority(authority);
  if (split === null) return urlBad("host");
  const port = readPort(split.portText);
  if (port === null) return urlBad("port");
  const host = parseHost(split.hostText);
  if (!host.ok) {
    if (host.reason === "not_a_hostname") return { ok: false, code: "not_a_hostname", reason: "not_a_hostname" };
    return urlBad("host");
  }
  let path = "/";
  let query = "";
  if (tail !== "") {
    if (tail.startsWith("?")) {
      query = tail.slice(1);
    } else if (tail.startsWith("/")) {
      const mark = tail.indexOf("?");
      path = mark === -1 ? tail : tail.slice(0, mark);
      query = mark === -1 ? "" : tail.slice(mark + 1);
    } else {
      return urlBad("path");
    }
  }
  if (!path.startsWith("/")) return urlBad("path");
  for (const segment of path.split("/")) {
    const decoded = segment.replace(/%2e/gi, ".");
    if (decoded === "." || decoded === "..") return urlBad("dot_segment");
  }
  const suffix = port === 443 ? "" : `:${port}`;
  return {
    ok: true,
    scheme: "https",
    host: host.normalized,
    port,
    path,
    query,
    canonical: `https://${host.normalized}${suffix}${path}${query === "" ? "" : `?${query}`}`,
    hostKind: host.kind,
    hostValue: host.kind === "name" ? host.name : host.address,
  };
}

/** Whether a callback URL is refused exactly because a path segment is `.` or `..` (R5.11). */
export function isDotSegmentCallbackUrl(value: unknown): boolean {
  const checked = checkCallbackUrl(value);
  return !checked.ok && checked.reason === "dot_segment";
}

function urlBad(reason: string): { readonly ok: false; readonly code: "invalid_callback_url"; readonly reason: string } {
  return { ok: false, code: "invalid_callback_url", reason };
}

interface AuthoritySplit {
  readonly hostText: string;
  readonly portText: string | null;
}

function splitAuthority(authority: string): AuthoritySplit | null {
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close === -1) return { hostText: authority, portText: null };
    const after = authority.slice(close + 1);
    if (after === "") return { hostText: authority.slice(0, close + 1), portText: null };
    if (!after.startsWith(":")) return null;
    return { hostText: authority.slice(0, close + 1), portText: after.slice(1) };
  }
  const first = authority.indexOf(":");
  if (first === -1) return { hostText: authority, portText: null };
  if (authority.indexOf(":", first + 1) !== -1) return null;
  return { hostText: authority.slice(0, first), portText: authority.slice(first + 1) };
}

function readPort(text: string | null): number | null {
  if (text === null) return 443;
  if (!PORT_TEXT.test(text) || (text.length > 1 && text.startsWith("0"))) return null;
  const value = Number(text);
  return value >= 1 && value <= 65535 ? value : null;
}
