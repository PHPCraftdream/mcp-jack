/** Jack-Auth header grammar parsing (spec 01 section 3). */
import { BadBase64UrlError, decodeBase64URLFixed } from "./encoding.js";
import { Code, JackError } from "./errors.js";

/** RequestAuth holds the parsed parameters of a v1 request Jack-Auth header; kid, nonce and sig are the canonical header values as sent. */
export interface RequestAuth {
  kid: string;
  ts: number;
  nonce: string;
  sig: string;
}

/** ResponseAuth holds the parsed parameters of a v1 response Jack-Auth header. */
export interface ResponseAuth {
  kid: string;
  ts: number;
  sig: string;
}

// Byte lengths required by spec 01 section 2 (sizes of kid, nonce, sig).
const KID_LEN = 32;
const NONCE_LEN = 16;
const SIG_LEN = 64;

/** Fixed base64url byte length per parameter name that must decode via decodeBase64URLFixed. */
type Lengths = Readonly<Record<string, number>>;

/** Parsed name -> value map of one header (values as sent). */
type Params = Map<string, string>;

/** Shared grammar over the allowed parameter names plus fixed-length map; any violation is a JackError with HTTP status 401. */
function parseAuthValues(values: readonly string[], allowed: readonly string[], lengths: Lengths): Params {
  if (values.length === 0) {
    throw new JackError(401, Code.MISSING_AUTH, "missing Jack-Auth header");
  }
  if (values.length > 1) {
    // Spec 01 section 4 step 2: a header may appear at most once.
    throw new JackError(401, Code.MALFORMED_AUTH, "Jack-Auth header present more than once");
  }
  const value = values[0] as string;

  // Scheme: the value up to the first space; checked BEFORE parameters (spec 01 section 3).
  const sp = value.indexOf(" ");
  const scheme = sp >= 0 ? value.slice(0, sp) : value;
  if (scheme !== "v1") {
    if (isVersionScheme(scheme)) {
      throw new JackError(401, Code.UNSUPPORTED_VERSION, "unsupported Jack-Auth version");
    }
    throw new JackError(401, Code.MALFORMED_AUTH, "malformed Jack-Auth scheme");
  }
  if (sp < 0) {
    throw new JackError(401, Code.MALFORMED_AUTH, "missing Jack-Auth parameters");
  }

  // Parameters: comma-separated name=value, no whitespace anywhere (spec 01 section 3 grammar).
  const rest = value.slice(sp + 1);
  const params: Params = new Map();
  for (const part of rest.split(",")) {
    const eq = part.indexOf("=");
    // The grammar ^[a-z]+=[A-Za-z0-9_-]+$ allows exactly one '='.
    if (eq < 0 || eq === 0 || eq === part.length - 1 || part.indexOf("=", eq + 1) >= 0) {
      throw new JackError(401, Code.MALFORMED_AUTH, "malformed Jack-Auth parameter");
    }
    const name = part.slice(0, eq);
    const val = part.slice(eq + 1);
    if (!lowerAlpha(name) || !paramValueCharset(val)) {
      throw new JackError(401, Code.MALFORMED_AUTH, "malformed Jack-Auth parameter");
    }
    if (!allowedName(name, allowed)) {
      throw new JackError(401, Code.MALFORMED_AUTH, "unknown Jack-Auth parameter");
    }
    if (params.has(name)) {
      throw new JackError(401, Code.MALFORMED_AUTH, "repeated Jack-Auth parameter");
    }
    params.set(name, val);
  }
  for (const name of allowed) {
    if (!params.has(name)) {
      throw new JackError(401, Code.MALFORMED_AUTH, `missing Jack-Auth parameter ${name}`);
    }
  }

  // ts: whole seconds, no sign, no leading zeros, at most 12 digits (spec 01 section 3).
  const rawTS = params.get("ts") as string;
  if (!validTS(rawTS)) {
    throw new JackError(401, Code.MALFORMED_AUTH, "malformed ts");
  }
  // The grammar caps ts at 12 digits, far below 2^53, so Number is exact here.
  params.set("ts", String(Number(rawTS)));

  // Fixed-length base64url values: kid 32, nonce 16, sig 64 bytes (spec 01 sections 2 and 3).
  for (const [name, size] of Object.entries(lengths)) {
    const v = params.get(name);
    if (v === undefined) {
      continue;
    }
    try {
      decodeBase64URLFixed(v, size);
    } catch (err) {
      if (err instanceof BadBase64UrlError) {
        throw new JackError(401, Code.MALFORMED_AUTH, `malformed ${name}`);
      }
      throw err;
    }
  }
  return params;
}

/** Exactly "v" plus one or more ASCII digits: unsupported_version; any other bad scheme is malformed_auth (spec 01 section 3). */
function isVersionScheme(s: string): boolean {
  if (s.length < 2 || s.charCodeAt(0) !== 118 /* 'v' */) {
    return false;
  }
  for (let i = 1; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) {
      return false;
    }
  }
  return true;
}

/** ^[a-z]+$ (parameter names, spec 01 section 3). */
function lowerAlpha(s: string): boolean {
  if (s.length === 0) {
    return false;
  }
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 97 || c > 122) {
      return false;
    }
  }
  return true;
}

/** Non-empty, only A-Za-z0-9_- (parameter values, spec 01 section 3). */
function paramValueCharset(s: string): boolean {
  if (s.length === 0) {
    return false;
  }
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (
      !(c >= 65 && c <= 90) &&
      !(c >= 97 && c <= 122) &&
      !(c >= 48 && c <= 57) &&
      c !== 95 /* '_' */ &&
      c !== 45 /* '-' */
    ) {
      return false;
    }
  }
  return true;
}

function allowedName(name: string, allowed: readonly string[]): boolean {
  return allowed.includes(name);
}

/** ^(0|[1-9][0-9]{0,11})$: no sign, no leading zeros, at most 12 digits (spec 01 section 3). */
function validTS(s: string): boolean {
  if (s.length === 0 || s.length > 12) {
    return false;
  }
  if (s.charCodeAt(0) === 48 /* '0' */) {
    return s.length === 1;
  }
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) {
      return false;
    }
  }
  return true;
}

/** Parses the Jack-Auth header values of one HTTP request (all values of headers named Jack-Auth, in order) into RequestAuth. */
export function parseRequestAuth(values: readonly string[]): RequestAuth {
  const p = parseAuthValues(
    values,
    ["kid", "ts", "nonce", "sig"],
    { kid: KID_LEN, nonce: NONCE_LEN, sig: SIG_LEN },
  );
  return {
    kid: p.get("kid") as string,
    ts: Number(p.get("ts")),
    nonce: p.get("nonce") as string,
    sig: p.get("sig") as string,
  };
}

/** ParseRequestAuth for response headers, whose parameter set is exactly kid, ts, sig (spec 01 section 5). */
export function parseResponseAuth(values: readonly string[]): ResponseAuth {
  const p = parseAuthValues(values, ["kid", "ts", "sig"], { kid: KID_LEN, sig: SIG_LEN });
  return {
    kid: p.get("kid") as string,
    ts: Number(p.get("ts")),
    sig: p.get("sig") as string,
  };
}

/** Canonical request header value "v1 kid=...,ts=...,nonce=...,sig=..." (spec 01 section 3). */
export function formatRequestAuth(a: RequestAuth): string {
  return `v1 kid=${a.kid},ts=${String(a.ts)},nonce=${a.nonce},sig=${a.sig}`;
}

/** Canonical response header value "v1 kid=...,ts=...,sig=..." (spec 01 section 5). */
export function formatResponseAuth(a: ResponseAuth): string {
  return `v1 kid=${a.kid},ts=${String(a.ts)},sig=${a.sig}`;
}
