/** JSON-RPC MCP client performing signed, response-verified tool calls (port of Go client/rpc.go). */
import { validatePublicKey } from "../core/ed25519.js";
import { JackError } from "../core/errors.js";
import { MAX_BODY_BYTES, createSigningFetch, readBodyCapped } from "./transport/transport.js";
import type { SigningFetch } from "./transport/transport.js";
import { HTTPError, RPCError, ToolError, parseErrorBody } from "./errors.js";
import type { Clock, NonceSource } from "./signing/auth.js";
import { adminInviteCreate, adminInviteList, adminInviteRevoke, adminUserCreate, adminUserGet, adminUserList, adminUserRevoke, adminUserSetAdmin, enroll, rotateKey, whoAmI } from "./tools.js";
import type { EnrollResult, Entry, InviteCreateParams, InviteCreateResult, InviteListEntry, InviteRevokeResult, KidResult, UserCreateParams, WhoAmIResult } from "./tools.js";
import type { Signer } from "./signing/signer.js";
import { checkDestination } from "./transport/url-policy.js";
import type { ClientEra } from "../modern/era.js";
import { decodeUtf8 } from "../modern/values.js";

/** Any JSON value, exactly as JSON.parse can produce. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { readonly [key: string]: JsonValue };

/**
 * Configuration carrying everything the Client needs to reach and trust one server.
 *
 * `baseUrl` must satisfy the client URL policy (checkDestination, applied to
 * the raw string): https for any host, http only for a literal 127.x.y.z or
 * [::1]. Percent escapes are refused in the authority only; percent-encoded
 * path/query bytes are accepted and signed as given. There is no insecure opt-out. A caller-supplied `fetchImpl` must use
 * TLS for https, connect to exactly the URL it is given and not follow
 * redirects; the SDK cannot police an arbitrary custom fetch.
 */
export interface ClientConfig {
  baseUrl: string;
  aud: string;
  signer: Signer;
  serverKey: Uint8Array;
  fetchImpl?: typeof fetch;
  clock?: Clock;
  nonceSource?: NonceSource;
  windowSeconds?: number;
  /**
   * Era this client speaks (spec 04 section 6). "legacy" is the default and
   * keeps the 0.1.x wire byte-identical; "modern" sends the 2026-07-28 `_meta`
   * and mirror headers, "auto" detects the era once per client from a verified
   * probe. Only the modern helpers (see client/modern.ts) act on it; callWith
   * stays the byte-frozen 0.1.x tool call.
   */
  era?: ClientEra;
}

/** Narrow a decoded JsonValue (possibly absent under noUncheckedIndexedAccess) to a JSON object, if it is one. */
function asRecord(v: JsonValue | undefined): { readonly [key: string]: JsonValue } | undefined {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? v : undefined;
}

/** Whether a decoded JsonValue is structuredContent-present: JSON null counts as absent. */
function isPresent(v: JsonValue | undefined): boolean {
  return v !== undefined && v !== null;
}

/** Whether aud is non-empty and free of C0 control characters and DEL (bytes < 0x20 and 0x7f on the wire; UTF-8 multibyte sequences are all >= 0x80, so a code-unit check is exact). */
function validAudience(aud: string): boolean {
  if (aud === "") return false;
  for (let i = 0; i < aud.length; i++) {
    const c = aud.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return false;
  }
  return true;
}

/** A verified response exactly as received, before any JSON-RPC interpretation (spec 04 C9 reads non-2xx answers this way). */
export interface SignedReply {
  /** HTTP status of the verified response. */
  readonly status: number;
  /** The verified body text; "" when the body is empty. */
  readonly bodyText: string;
  /** The parsed JSON body; undefined when the body is empty or not JSON. */
  readonly json: JsonValue | undefined;
}

/** Client performs signed, response-verified MCP tool calls over JSON-RPC. */
export class Client {
  /** Audience bound into the signing string; needed by the typed-call helpers in tools.ts. */
  readonly aud: string;
  readonly signer: Signer;
  readonly clock: Clock;
  /** Era this client speaks; "legacy" unless configured. */
  readonly era: ClientEra;
  #base: URL;
  #fetch: SigningFetch;
  #nextID = 1;

  constructor(config: ClientConfig) {
    // Policy on the raw string first, before any URL parsing or normalisation.
    checkDestination(config.baseUrl);
    let base: URL;
    try {
      base = new URL(config.baseUrl);
    } catch {
      throw new Error("jack client: base url must be an absolute http/https URL with a host");
    }
    if ((base.protocol !== "http:" && base.protocol !== "https:") || base.hostname === "") {
      throw new Error("jack client: base url must be an absolute http/https URL with a host");
    }
    if (!validAudience(config.aud)) {
      throw new Error("jack client: aud must be non-empty and contain no control characters");
    }
    if (config.serverKey.length !== 32) {
      throw new Error(`jack client: server key must be exactly 32 bytes, got ${config.serverKey.length}`);
    }
    const keyErr = validatePublicKey(config.serverKey);
    if (keyErr !== null) {
      // Local validation never becomes an HTTP response: zero the validator's
      // wire admission status (httpStatus 0 = never an HTTP response, the
      // JackError contract), matching verifyResponse's client-side remap.
      throw new JackError(0, keyErr.code, keyErr.message);
    }
    this.#base = base;
    this.aud = config.aud;
    this.signer = config.signer;
    this.clock = config.clock ?? (() => Math.floor(Date.now() / 1000));
    this.era = config.era ?? "legacy";
    // Like Go's Config.HTTP, an injected fetchImpl is wrapped by OUR signing
    // layer instead of requiring the caller to pre-wrap it, so an unsigned
    // client is never silently accepted.
    this.#fetch = createSigningFetch(
      {
        aud: config.aud,
        signer: config.signer,
        serverKey: config.serverKey,
        ...(config.clock !== undefined ? { clock: config.clock } : {}),
        ...(config.nonceSource !== undefined ? { nonceSource: config.nonceSource } : {}),
        ...(config.windowSeconds !== undefined ? { windowSeconds: config.windowSeconds } : {}),
      },
      config.fetchImpl ?? globalThis.fetch,
    );
  }

  /** callTool calls a tool with the client's default signer and no pinned clock. */
  callTool(tool: string, args?: Record<string, unknown>): Promise<JsonValue> {
    return this.callWith(tool, args, this.signer);
  }

  /**
   * callWith performs one signed, verified tool call with an explicit signer
   * and optional pinned clock, and returns the structuredContent payload.
   * The request body is built by string concatenation to pin the wire field
   * order exactly like Go's json.Marshal of the jsonrpcRequest struct:
   * jsonrpc, id, method, params{name, arguments}.
   */
  async callWith(tool: string, args: Record<string, unknown> | undefined, signer: Signer, fixedNow?: number): Promise<JsonValue> {
    const id = this.#nextID;
    this.#nextID++;
    const bodyText =
      '{"jsonrpc":"2.0","id":' + id + ',"method":"tools/call","params":{"name":' + JSON.stringify(tool) + ',"arguments":' + (args === undefined ? "{}" : JSON.stringify(args)) + "}}";

    const resp = await this.#fetch(this.#base, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: new TextEncoder().encode(bodyText),
      jackSigner: signer,
      ...(fixedNow !== undefined ? { jackFixedNow: fixedNow } : {}),
    });
    const raw = await readBodyCapped(resp, MAX_BODY_BYTES);

    if (resp.status < 200 || resp.status > 299) {
      const { code, message } = parseErrorBody(raw);
      throw new HTTPError(resp.status, code, message);
    }

    let wire: JsonValue;
    try {
      wire = JSON.parse(new TextDecoder().decode(raw)) as JsonValue;
    } catch (err) {
      throw new Error(`jack client: decoding json-rpc response: ${err instanceof Error ? err.message : String(err)}`);
    }
    const wireRecord = asRecord(wire);

    const errRecord = wireRecord !== undefined ? asRecord(wireRecord["error"]) : undefined;
    if (isPresent(wireRecord?.["error"])) {
      if (errRecord === undefined) {
        throw new Error("jack client: decoding json-rpc response: error member is not an object");
      }
      // Go unmarshals Code int / Message string: absent decodes to 0 / "",
      // but a PRESENT member of the wrong type fails the whole decode.
      const rawCode = errRecord["code"];
      const rawMessage = errRecord["message"];
      if (rawCode !== undefined && !(typeof rawCode === "number" && Number.isInteger(rawCode))) {
        throw new Error("jack client: decoding json-rpc response: error code must be an integer");
      }
      if (rawMessage !== undefined && typeof rawMessage !== "string") {
        throw new Error("jack client: decoding json-rpc response: error message must be a string");
      }
      const code = typeof rawCode === "number" && Number.isInteger(rawCode) ? rawCode : 0;
      const message = typeof rawMessage === "string" ? rawMessage : "";
      throw new RPCError(code, message, isPresent(errRecord["data"]) ? errRecord["data"] : undefined);
    }
    if (!isPresent(wireRecord?.["result"])) {
      throw new Error("jack client: json-rpc response has neither result nor error");
    }
    const resultRecord = asRecord(wireRecord?.["result"]);
    const isError = resultRecord !== undefined && resultRecord["isError"] === true;
    if (isError) {
      let message = "";
      const content = resultRecord?.["content"];
      if (Array.isArray(content)) {
        for (const entry of content) {
          const rec = asRecord(entry);
          const text = rec !== undefined ? rec["text"] : undefined;
          if (typeof text === "string" && text !== "") {
            message = text;
            break;
          }
        }
      }
      const structured = isPresent(resultRecord?.["structuredContent"]) ? resultRecord?.["structuredContent"] : undefined;
      throw new ToolError(message, structured);
    }
    if (!isPresent(resultRecord?.["structuredContent"])) {
      throw new Error("jack client: missing structuredContent");
    }
    return resultRecord?.["structuredContent"] as JsonValue;
  }

  /**
   * signedRequest sends one signed JSON-RPC request through the existing
   * transport and signer and returns the VERIFIED response whatever its
   * status: a non-2xx answer is not an error here, because the modern profile
   * reads it (spec 04 C9). A verification failure still throws. `paramsJson`
   * is inserted verbatim (already-encoded params, so `_meta` order is the
   * caller's) and the headers are appended in the given order after
   * Content-Type.
   */
  async signedRequest(
    method: string,
    paramsJson: string | undefined,
    headers: readonly (readonly [string, string])[] = [],
    fixedNow?: number,
  ): Promise<SignedReply> {
    const id = this.#nextID;
    this.#nextID++;
    const bodyText =
      '{"jsonrpc":"2.0","id":' + id + ',"method":' + JSON.stringify(method) + ',"params":' + (paramsJson ?? "{}") + "}";
    const requestHeaders: [string, string][] = [["content-type", "application/json"]];
    for (const [name, value] of headers) {
      requestHeaders.push([name, value]);
    }
    const resp = await this.#fetch(this.#base, {
      method: "POST",
      headers: requestHeaders,
      body: bodyText,
      ...(fixedNow !== undefined ? { jackFixedNow: fixedNow } : {}),
    });
    const raw = await readBodyCapped(resp, MAX_BODY_BYTES);
    const bodyTextOut = decodeUtf8(raw) ?? "";
    let json: JsonValue | undefined;
    if (bodyTextOut.trim() !== "") {
      try {
        json = JSON.parse(bodyTextOut) as JsonValue;
      } catch {
        json = undefined;
      }
    }
    return { status: resp.status, bodyText: bodyTextOut, json };
  }

  /** Enrolls a NEW key with an invite code; the WHOLE request is signed by the new key (spec 03 section 3.2). */
  enroll(code: string, name: string, newSigner: Signer): Promise<EnrollResult> {
    return enroll(this, code, name, newSigner);
  }

  /** Asks the server to describe the calling key. */
  whoAmI(): Promise<WhoAmIResult> {
    return whoAmI(this);
  }

  /** Rotates from the client's current key to newSigner (spec 03 section 3.1). */
  rotateKey(newSigner: Signer): Promise<KidResult> {
    return rotateKey(this, newSigner);
  }

  /** Lists all registry entries. */
  adminUserList(): Promise<Entry[]> {
    return adminUserList(this);
  }

  /** Returns one registry entry by kid. */
  adminUserGet(kid: string): Promise<Entry> {
    return adminUserGet(this, kid);
  }

  /** Registers a key directly as an admin operation. */
  adminUserCreate(params: UserCreateParams): Promise<KidResult> {
    return adminUserCreate(this, params);
  }

  /** Replaces one entry's admin flag; the protocol gates non-admin callers with admin_required. */
  adminUserSetAdmin(kid: string, admin: boolean): Promise<Entry> {
    return adminUserSetAdmin(this, kid, admin);
  }

  /** Revokes one registry entry. */
  adminUserRevoke(kid: string): Promise<KidResult> {
    return adminUserRevoke(this, kid);
  }

  /** Mints an invite. */
  adminInviteCreate(params: InviteCreateParams): Promise<InviteCreateResult> {
    return adminInviteCreate(this, params);
  }

  /** Lists all invites. */
  adminInviteList(): Promise<InviteListEntry[]> {
    return adminInviteList(this);
  }

  /** Revokes one invite. */
  adminInviteRevoke(inviteId: string): Promise<InviteRevokeResult> {
    return adminInviteRevoke(this, inviteId);
  }
}
