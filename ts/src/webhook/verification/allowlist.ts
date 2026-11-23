import { parseHost } from "../ssrf/address.js";
import { checkCallbackUrl } from "../ssrf/url.js";

const HTTPS_PREFIX = "https://";
const WILDCARD = "*.";
const PRINTABLE_RE = /^[\x21-\x7e]+$/;
const FIRST_PATH_MARK_RE = /[/?#]/;
const PORT_RE = /^[1-9][0-9]{0,4}$/;
const DEFAULT_PORT = 443;

/** A parsed HTTPS allowlist prefix with port and path defaults applied (R5.7). */
export interface AllowlistEntry {
  readonly ok: true;
  readonly hostPattern: string;
  readonly port: number;
  readonly path: string;
}

/** Parses a literal HTTPS allowlist prefix or a wildcard prefix with an LDH parent (R5.7). */
export function parseAllowlistEntry(text: unknown): AllowlistEntry | { readonly ok: false } {
  const bad = { ok: false } as const;
  if (typeof text !== "string" || !text.startsWith(HTTPS_PREFIX) || !PRINTABLE_RE.test(text)) return bad;
  if (!text.startsWith(`${HTTPS_PREFIX}${WILDCARD}`)) {
    const checked = checkCallbackUrl(text);
    if (!checked.ok || checked.query !== "") return bad;
    return { ok: true, hostPattern: checked.host, port: checked.port, path: checked.path };
  }
  const rest = text.slice(HTTPS_PREFIX.length);
  const stop = rest.search(FIRST_PATH_MARK_RE);
  const authority = stop === -1 ? rest : rest.slice(0, stop);
  const path = stop === -1 ? "/" : rest.slice(stop);
  if (path.includes("?") || path.includes("#") || authority.includes("@")) return bad;
  const colon = authority.indexOf(":");
  const hostText = colon === -1 ? authority : authority.slice(0, colon);
  const portText = colon === -1 ? null : authority.slice(colon + 1);
  const port = portText === null ? DEFAULT_PORT : Number(portText);
  if (portText !== null && (!PORT_RE.test(portText) || port > 65535)) return bad;
  const parent = parseHost(hostText.slice(WILDCARD.length));
  if (!parent.ok || parent.kind !== "name") return bad;
  return { ok: true, hostPattern: `${WILDCARD}${parent.name}`, port, path };
}

/** Returns the first entry matching the callback's host, port and path (R5.7). */
export function allowlistMatches(
  entries: readonly (string | AllowlistEntry)[],
  canonicalUrl: string,
): { readonly matched: boolean; readonly entry: AllowlistEntry | null } {
  const checked = checkCallbackUrl(canonicalUrl);
  if (!checked.ok) return { matched: false, entry: null };
  const list: readonly (string | AllowlistEntry)[] = Array.isArray(entries) ? entries : [];
  for (const value of list) {
    const entry = typeof value === "string" ? parseAllowlistEntry(value) : value;
    if (!entry || entry.ok !== true || entry.port !== checked.port) continue;
    if (!hostMatches(entry.hostPattern, checked.host) || !pathCovers(entry.path, checked.path)) continue;
    return { matched: true, entry };
  }
  return { matched: false, entry: null };
}

/** Whether the case-sensitive entry prefix reaches a path segment boundary, without decoding (R5.7, R5.10). */
export function pathCovers(entryPath: string, urlPath: string): boolean {
  if (typeof entryPath !== "string" || typeof urlPath !== "string" || !urlPath.startsWith(entryPath)) return false;
  return entryPath.endsWith("/") || urlPath.length === entryPath.length || urlPath[entryPath.length] === "/";
}

function hostMatches(pattern: string, host: string): boolean {
  if (typeof pattern !== "string") return false;
  if (!pattern.startsWith(WILDCARD)) return pattern === host;
  const parent = pattern.slice(WILDCARD.length);
  return host.endsWith(`.${parent}`) && host.length > parent.length + 1;
}
