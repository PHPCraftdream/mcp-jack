/** Client profile: a configuration file holding ONLY public data (port of Go client/profile.go). */
import { BadBase64UrlError, decodeBase64URLFixed } from "../encoding.js";
import { validatePublicKey } from "../ed25519.js";
import { Client } from "./rpc.js";
import type { Clock, NonceSource } from "./auth.js";
import type { Signer } from "./signer.js";

/**
 * Profile is a client configuration file. It deliberately has no private-key
 * field: private keys must never live in config files (spec 01 section 6).
 */
export interface Profile {
  url: string;
  aud: string;
  /** Unpadded base64url of the 32-byte server key. */
  serverPublicKey: string;
  /** The client key's identifier (kid), never a private key. */
  kid?: string;
  /** The client key's label. */
  name?: string;
}

/** profileToJSON maps a Profile to its wire form; kid and name are omitted when empty. */
export function profileToJSON(p: Profile): { url: string; aud: string; server_public_key: string; kid?: string; name?: string } {
  return {
    url: p.url,
    aud: p.aud,
    server_public_key: p.serverPublicKey,
    ...(p.kid !== undefined && p.kid !== "" ? { kid: p.kid } : {}),
    ...(p.name !== undefined && p.name !== "" ? { name: p.name } : {}),
  };
}

/** saveProfile returns p as indented JSON with a trailing newline (Go MarshalIndent + newline). */
export function saveProfile(p: Profile): string {
  return JSON.stringify(profileToJSON(p), null, 2) + "\n";
}

/**
 * validateProfile enforces spec 01 sections 3 and 6 field rules.
 */
export function validateProfile(p: Profile): void {
  // WHATWG normalization would turn "https:///mcp" into https://mcp/ (host
  // "mcp"); Go rejects the empty authority, so the raw text is checked too.
  const scheme = /^https?:\/\//.exec(p.url);
  if (scheme === null || p.url.length === scheme[0].length || "/?#".includes(p.url.charAt(scheme[0].length))) {
    throw new Error("jack client: profile url must be an absolute http/https URL with a host");
  }
  let u: URL;
  try {
    u = new URL(p.url);
  } catch {
    throw new Error("jack client: profile url must be an absolute http/https URL with a host");
  }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || u.hostname === "") {
    throw new Error("jack client: profile url must be an absolute http/https URL with a host");
  }
  if (p.aud === "") {
    throw new Error("jack client: profile aud must be non-empty");
  }
  let serverKey: Uint8Array;
  try {
    serverKey = decodeBase64URLFixed(p.serverPublicKey, 32);
  } catch (err) {
    if (err instanceof BadBase64UrlError) {
      throw new Error("jack client: profile server_public_key: invalid base64url");
    }
    throw err;
  }
  const keyErr = validatePublicKey(serverKey);
  if (keyErr !== null) {
    throw keyErr;
  }
  if (p.kid !== undefined && p.kid !== "") {
    try {
      decodeBase64URLFixed(p.kid, 32);
    } catch (err) {
      if (err instanceof BadBase64UrlError) {
        throw new Error("jack client: profile kid: invalid base64url");
      }
      throw err;
    }
  }
}

const KNOWN_FIELDS = ["url", "aud", "server_public_key", "kid", "name"] as const;

/** loadProfile parses and validates a profile document; throws on any violation (Go DisallowUnknownFields + trailing-data check). */
export function loadProfile(text: string): Profile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    // JSON.parse also rejects trailing data like `" } {}"`, covering Go's io.EOF check.
    throw new Error(`jack client: profile: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("jack client: profile: not a JSON object");
  }
  const rec = parsed as { readonly [key: string]: unknown };
  for (const key of Object.keys(rec)) {
    if (!(KNOWN_FIELDS as readonly string[]).includes(key)) {
      throw new Error(`jack client: profile: unknown field "${key}"`);
    }
  }
  const url = requiredString(rec["url"], "url");
  const aud = requiredString(rec["aud"], "aud");
  const serverPublicKey = requiredString(rec["server_public_key"], "server_public_key");
  const kid = optionalString(rec["kid"], "kid");
  const name = optionalString(rec["name"], "name");
  const profile: Profile = {
    url,
    aud,
    serverPublicKey,
    ...(kid !== undefined ? { kid } : {}),
    ...(name !== undefined ? { name } : {}),
  };
  validateProfile(profile);
  return profile;
}

/** A required wire field: absent or null counts as "" (rejected later by validation); any other non-string type is a decode error (Go typed decode). */
function requiredString(v: unknown, field: string): string {
  if (v === undefined || v === null) {
    return "";
  }
  if (typeof v !== "string") {
    throw new Error(`jack client: profile: ${field} must be a string`);
  }
  return v;
}

/** An optional wire field: absent or null -> undefined; any other non-string type is a decode error (Go typed decode). Empty strings are kept (Go keeps "" in the struct; profileToJSON omits it and validation skips it). */
function optionalString(v: unknown, field: string): string | undefined {
  if (v === undefined || v === null) {
    return undefined;
  }
  if (typeof v !== "string") {
    throw new Error(`jack client: profile: ${field} must be a string`);
  }
  return v;
}

/** profileServerKeyBytes returns the decoded 32-byte server public key; BadBase64UrlError propagates. */
export function profileServerKeyBytes(p: Profile): Uint8Array {
  return decodeBase64URLFixed(p.serverPublicKey, 32);
}

/** Optional runtime tuning for clientFromProfile. */
export interface ClientOptions {
  fetchImpl?: typeof fetch;
  clock?: Clock;
  nonceSource?: NonceSource;
  windowSeconds?: number;
}

/** clientFromProfile validates the profile and builds a Client for it (port of Go's NewClientFromProfile implied by profile_test.go). */
export function clientFromProfile(profile: Profile, signer: Signer, options?: ClientOptions): Client {
  validateProfile(profile);
  return new Client({
    baseUrl: profile.url,
    aud: profile.aud,
    signer,
    serverKey: profileServerKeyBytes(profile),
    ...(options?.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
    ...(options?.clock !== undefined ? { clock: options.clock } : {}),
    ...(options?.nonceSource !== undefined ? { nonceSource: options.nonceSource } : {}),
    ...(options?.windowSeconds !== undefined ? { windowSeconds: options.windowSeconds } : {}),
  });
}
