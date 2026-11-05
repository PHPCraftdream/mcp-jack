/** Shared non-test helpers for the client SDK tests (port of Go client/harness_test.go). */
import { createPrivateKey, createPublicKey, randomBytes, sign as nodeSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { formatResponseAuth, parseRequestAuth } from "../src/auth-header.js";
import type { RequestAuth } from "../src/auth-header.js";
import { verify } from "../src/ed25519.js";
import { decodeBase64URLFixed, encodeBase64URL, keyId } from "../src/encoding.js";
import { requestSigningString, responseSigningString } from "../src/signing.js";
import { Client } from "../src/client/rpc.js";
import { InMemorySigner } from "../src/client/signer.js";
import type { Signer } from "../src/client/signer.js";
import type { NonceSource } from "../src/client/auth.js";
import { loadKeys } from "./fixtures.js";

/** The state.now of every fixture case. */
export const fixtureNow = 1767225600;

/** The state.aud of every fixture case. */
export const fixtureAud = "https://svc.example.test";

/** Local UTF-8 encoder; the signing strings are signed over their exact UTF-8 bytes. */
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** seedSignerByName returns the InMemorySigner derived from the named key of keys.json ("alice", "newbie", ...); throws when the name is absent. */
export function seedSignerByName(name: string): InMemorySigner {
  const key = loadKeys().keys.find((k) => k.name === name);
  if (key === undefined) {
    throw new Error(`keys.json has no key named ${JSON.stringify(name)}`);
  }
  return seedSignerFromKey(key.seedHex, key.name);
}

/** seedSignerByKid is seedSignerByName keyed by kid instead of name. */
export function seedSignerByKid(kid: string): InMemorySigner {
  const key = loadKeys().keys.find((k) => k.kid === kid);
  if (key === undefined) {
    throw new Error(`keys.json has no key with kid ${JSON.stringify(kid)}`);
  }
  return seedSignerFromKey(key.seedHex, key.name);
}

/** Derives an InMemorySigner from a keys.json seed hex. */
function seedSignerFromKey(seedHex: string, name: string): InMemorySigner {
  const seed = Buffer.from(seedHex, "hex");
  if (seed.length !== 32) {
    throw new Error(`key ${name}: decoded seed is ${seed.length} bytes, want 32`);
  }
  return new InMemorySigner(new Uint8Array(seed));
}

/** fixtureKeys loads keys.json and returns the kid -> 32-byte public key map built from the derived signers (Go fixtureKeys). */
export function fixtureKeys(): Map<string, Uint8Array> {
  const keys = new Map<string, Uint8Array>();
  for (const k of loadKeys().keys) {
    const signer = seedSignerFromKey(k.seedHex, k.name);
    keys.set(signer.kid(), signer.publicKey());
  }
  return keys;
}

/** queuedNonce decodes the given base64url nonces in order; it throws "nonce queue exhausted" when past the end. */
export function queuedNonce(nonces: readonly string[]): NonceSource {
  let i = 0;
  return (): Uint8Array => {
    const b64 = nonces[i];
    if (b64 === undefined) {
      throw new Error("nonce queue exhausted");
    }
    i++;
    return decodeBase64URLFixed(b64, 16);
  };
}

/** One Ed25519 key pair built from a random seed via the fixed PKCS8/SPKI DER prefixes. */
export interface Keypair {
  priv: KeyObject;
  pub: Uint8Array;
  kid: string;
}

/** generateKeypair creates a fresh Ed25519 key pair (Go ed25519.GenerateKey). */
export function generateKeypair(): Keypair {
  // The fixed Ed25519 PKCS#8 DER prefix; appending the 32-byte seed yields a valid private key.
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const seed = randomBytes(32);
  const priv = createPrivateKey({ key: Buffer.concat([pkcs8Prefix, seed]), format: "der", type: "pkcs8" });
  // SPKI DER is a fixed 44-byte header followed by the 32-byte raw key.
  const der = createPublicKey(priv).export({ type: "spki", format: "der" });
  const pub = new Uint8Array(der.subarray(der.length - 32));
  return { priv, pub, kid: keyId(pub) };
}

/** Per-test response logic assigned BEFORE calling the fake fetch. */
export interface TestServer {
  /** Server signing key (needed by the tampered-body test). */
  priv: KeyObject;
  /** Raw 32-byte server public key. */
  pub: Uint8Array;
  /** keyId(pub). */
  kid: string;
  /** Audience used in request signing strings. */
  aud: string;
  /** Response timestamp; tests may adjust. */
  now: number;
  /** Per-test response logic; the fake fetch answers 500 when null. */
  handle: ((auth: RequestAuth, body: Uint8Array) => Response) | null;
  /** The most recent request the fake fetch observed (recorded before verification, so unsigned attempts are captured too). */
  lastRequest: {
    /** HTTP method as received. */
    method: string;
    /** Origin-form target (path plus query). */
    target: string;
    /** The Jack-Auth header value, null when absent. */
    header: string | null;
    /** The exact body bytes. */
    body: Uint8Array;
    /** The received AbortSignal, null when absent. */
    signal: AbortSignal | null;
    /** The received redirect policy, null when absent. */
    redirect: string | null;
  } | null;
  /** The fake fetch: verifies each request per spec 01 section 4, then delegates to handle. */
  fetch: typeof fetch;
  /** Signs status+auth.sig+kid+ts+body with the server key (spec 01 section 5); ts = now. */
  writeSignedJSON(auth: RequestAuth, status: number, body: Uint8Array): Response;
  /** Writes status+body without a Jack-Auth header. */
  writeUnsignedJSON(status: number, body: Uint8Array): Response;
}

/** newTestServer builds a fake in-process server that verifies requests with the fixture client keys. */
export function newTestServer(): TestServer {
  const { priv, pub, kid } = generateKeypair();
  // The client key map is built once at creation, not per request.
  const keys = fixtureKeys();
  const aud = fixtureAud;
  const now = fixtureNow;
  const unauthorizedBody = utf8('{"error":{"code":"unknown_key","message":"verification failed"}}');

  const writeSignedJSON = (auth: RequestAuth, status: number, body: Uint8Array): Response => {
    const msg = utf8(responseSigningString(status, auth.sig, kid, now, body));
    const sig = new Uint8Array(nodeSign(null, Buffer.from(msg), priv));
    return new Response(body, {
      status,
      headers: { "content-type": "application/json", "jack-auth": formatResponseAuth({ kid, ts: now, sig: encodeBase64URL(sig) }) },
    });
  };

  const writeUnsignedJSON = (status: number, body: Uint8Array): Response =>
    new Response(body, { status, headers: { "content-type": "application/json" } });

  const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    let body: Uint8Array;
    if (typeof init?.body === "string") {
      body = utf8(init.body);
    } else if (init?.body instanceof Uint8Array) {
      body = init.body;
    } else {
      body = new Uint8Array(0);
    }
    const hv = headers.get("Jack-Auth");
    const target = new URL(url).pathname + new URL(url).search;
    server.lastRequest = { method, target, header: hv, body, signal: init?.signal ?? null, redirect: init?.redirect ?? null };

    let auth: RequestAuth;
    try {
      if (hv === null) {
        throw new Error("missing Jack-Auth header");
      }
      auth = parseRequestAuth([hv]);
    } catch {
      return writeUnsignedJSON(401, unauthorizedBody);
    }
    const clientPub = keys.get(auth.kid);
    const msg = utf8(requestSigningString(method, target, aud, auth.kid, auth.ts, auth.nonce, body));
    let sig: Uint8Array;
    try {
      sig = decodeBase64URLFixed(auth.sig, 64);
    } catch {
      sig = new Uint8Array(0);
    }
    if (clientPub === undefined || !verify(clientPub, msg, sig)) {
      return writeUnsignedJSON(401, unauthorizedBody);
    }
    if (server.handle === null) {
      return writeUnsignedJSON(500, utf8('{"error":{"code":"internal","message":"no handler"}}'));
    }
    return server.handle(auth, body);
  };

  const server: TestServer = {
    priv,
    pub,
    kid,
    aud,
    now,
    handle: null,
    lastRequest: null,
    fetch: fetchImpl,
    writeSignedJSON,
    writeUnsignedJSON,
  };
  return server;
}

/** rpcResultBody wraps a structuredContent raw JSON value into a JSON-RPC 2.0 / MCP CallToolResult response body. */
export function rpcResultBody(structured: string): Uint8Array {
  return utf8('{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false,"structuredContent":' + structured + "}}");
}

/** newFixtureClient builds a Client pinned to the fake server with the given signer and fixture nonce, clocked at fixtureNow. */
export function newFixtureClient(server: TestServer, signer: Signer, nonceB64: string): Client {
  // "http://mcp.test/mcp" is never connected: the fake fetch intercepts; its target "/mcp" matches the fixtures.
  return new Client({
    baseUrl: "http://mcp.test/mcp",
    aud: fixtureAud,
    signer,
    serverKey: server.pub,
    fetchImpl: server.fetch,
    clock: () => fixtureNow,
    windowSeconds: 30,
    nonceSource: queuedNonce([nonceB64]),
  });
}
