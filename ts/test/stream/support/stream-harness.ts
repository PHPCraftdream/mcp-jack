/**
 * Shared, test-only wiring for the signed-stream server tests (spec 05,
 * scheme `s1`). One `newStreamServer` call builds the real fetch-standard
 * handler in front of the fixture registry, the static `svc` server key, a
 * volatile nonce store and an injected clock; a test installs its wrapped
 * handler through `setNext` and sends a signed request through `signedPost`.
 *
 * Everything a test needs to observe is on the wire: response bytes,
 * `Jack-Auth`, parsed frames and the 3.7 handler context. `verifyBody` feeds
 * the same bytes through the real client verifier, so a server test asserts
 * what a client would accept. No `test()` is declared here.
 */
import { parseRequestAuth } from "../../../src/core/auth-header.js";
import { signRequest, randomNonce } from "../../../src/client/signing/auth.js";
import type { InMemorySigner } from "../../../src/client/signing/signer.js";
import { NonceStore } from "../../../src/server/registry/nonce.js";
import type { RegistryEntry as StateRegistryEntry } from "../../../src/server/registry/state.js";
import { MemoryState } from "../../../src/server/registry/state.js";
import { Verifier } from "../../../src/server/verify.js";
import type { DurableAdmission } from "../../../src/server/durable/admission.js";
import { jackFetchHandler } from "../../../src/server/http/fetch.js";
import type { HandlerConfig } from "../../../src/server/http/fetch.js";
import type { StreamServerOptions } from "../../../src/server/http/stream.js";
import { parseStreamFrame, StreamEventReader } from "../../../src/stream/wire.js";
import type { StreamFrame } from "../../../src/stream/wire.js";
import { verifySignedStream } from "../../../src/stream/verify.js";
import type { StreamVerifyResult } from "../../../src/stream/verify.js";
import { loadKeys, loadRegistry } from "../../support/fixtures/index.js";
import type { RegistryEntry as FixtureRegistryEntry } from "../../support/fixtures/index.js";
import { fixtureAud, fixtureNow, seedSignerByName } from "../../support/client-harness.js";

/** Local UTF-8 encoder; every request and body byte is signed over its exact UTF-8 form. */
const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

/** The fixture user that is in the registry and opens the streams of these tests. */
const USER_NAME = "alice";

/** The fixture server key name; its 32-byte seed signs the open header and every frame. */
const SERVER_KEY_NAME = "svc";

/** The modern protocol version every default request body mirrors (spec 04 S12). */
const MODERN_META_VERSION = "2026-07-28";

/** The body member `params._meta` carries the mirrored version under (spec 04 section 5). */
const META_VERSION_KEY = "io.modelcontextprotocol/protocolVersion";

// ---------------------------------------------------------------------------
// Registry and key fixtures (the same wiring the fetch tests use).
// ---------------------------------------------------------------------------

type Mutable<T> = { -readonly [K in keyof T]: T[K] };

/** Fixture registry entry -> src registry entry; optional fields only when defined (exactOptionalPropertyTypes). */
function toStateEntry(entry: FixtureRegistryEntry): StateRegistryEntry {
  const out: Mutable<StateRegistryEntry> = {
    kid: entry.kid,
    publicKey: entry.publicKey,
    name: entry.name,
  };
  if (entry.admin !== undefined) {
    out.admin = entry.admin;
  }
  if (entry.notBefore !== undefined) {
    out.notBefore = entry.notBefore;
  }
  if (entry.notAfter !== undefined) {
    out.notAfter = entry.notAfter;
  }
  return out;
}

/** Fresh registry state seeded from registry.json (MemoryState is created empty). */
function newRegistryState(): MemoryState {
  const state = new MemoryState();
  state.update((edit) => {
    for (const entry of loadRegistry().keys) {
      edit.putKey(toStateEntry(entry));
    }
  });
  return state;
}

/** The 32-byte seed and derived signer of a keys.json entry. */
function seedByName(name: string): { readonly seed: Uint8Array; readonly signer: InMemorySigner } {
  const key = loadKeys().keys.find((candidate) => candidate.name === name);
  if (key === undefined) {
    throw new Error(`stream-harness: keys.json has no key named ${JSON.stringify(name)}`);
  }
  const seed = new Uint8Array(Buffer.from(key.seedHex, "hex"));
  if (seed.length !== 32) {
    throw new Error(`stream-harness: seed of ${name} is ${seed.length} bytes, want 32`);
  }
  const signer = seedSignerByName(name);
  if (signer.kid() !== key.kid) {
    throw new Error(`stream-harness: derived kid of ${name} differs from keys.json`);
  }
  return { seed, signer };
}

// ---------------------------------------------------------------------------
// The handler harness.
// ---------------------------------------------------------------------------

/** Options of `newStreamServer`. Every stream path is always enabled; the options only tune it. */
export interface StreamHarnessOptions {
  /** Raw 3.2-3.5 settings handed to HandlerConfig.streams; an empty object keeps every default. */
  readonly streams?: StreamServerOptions;
  /** Deployment profile of spec 04; streams exist only in the modern era (1.2), so "modern" is the default. */
  readonly profile?: "legacy" | "modern" | "both";
  /** Initial injected clock in Unix seconds; defaults to `fixtureNow`. */
  readonly clock?: number;
  /**
   * Candidate durable admission seam (spec/candidate/durable-nonces.md): when
   * set, the verifier reserves in this store and wires no volatile nonce store.
   */
  readonly durable?: DurableAdmission;
}

/** What `newStreamServer` exposes to a test. */
export interface StreamHarness {
  /** The real fetch handler (jackFetchHandler) in front of the current `setNext` handler. */
  readonly handler: (req: Request) => Promise<Response>;
  /** The verifier over the fixture registry; its clock is the same injected clock. */
  readonly verifier: Verifier;
  /** The injected clock in Unix seconds (a function, so later `setNow` calls are visible). */
  readonly clock: () => number;
  /** Moves the injected clock; the verifier and the stream signer read it through `clock`. */
  readonly setNow: (seconds: number) => void;
  /** Replaces the wrapped handler the fetch adapter forwards an authorized request to. */
  readonly setNext: (next: (req: Request) => Promise<Response>) => void;
}

/** The default wrapped handler: a plain v1 JSON answer, so a non-stream test stays byte-identical. */
const defaultNext = async (): Promise<Response> =>
  new Response('{"jsonrpc":"2.0","id":1,"result":{}}', { headers: { "content-type": "application/json" } });

/**
 * Builds one fetch handler over the fixture registry and the static `svc`
 * server key. `streams` is always configured (an empty object applies the
 * defaults), because without it the adapter has no stream path at all; the
 * profile defaults to "modern", because streams exist only there (1.2).
 */
export function newStreamServer(options: StreamHarnessOptions = {}): StreamHarness {
  let next: (req: Request) => Promise<Response> = defaultNext;
  let nowSeconds = options.clock ?? fixtureNow;
  const clock = (): number => nowSeconds;
  // Exactly one nonce profile: a supplied durable seam replaces the volatile
  // store, and the conditional spread keeps the other option absent
  // (exactOptionalPropertyTypes).
  const verifier = new Verifier({
    aud: fixtureAud,
    state: newRegistryState(),
    ...(options.durable === undefined ? { nonces: new NonceStore() } : { durable: options.durable }),
    now: clock,
  });
  const server = seedByName(SERVER_KEY_NAME);
  const config: HandlerConfig = {
    verifier,
    serverKey: server.seed,
    profile: options.profile ?? "modern",
    streams: options.streams ?? {},
  };
  // The closure reads `next` on every request, so setNext takes effect for the
  // next request without rebuilding the handler (and the verifier state).
  const handler = jackFetchHandler(config, (req) => next(req));
  return {
    handler,
    verifier,
    clock,
    setNow: (seconds: number): void => {
      nowSeconds = seconds;
    },
    setNext: (replacement: (req: Request) => Promise<Response>): void => {
      next = replacement;
    },
  };
}

// ---------------------------------------------------------------------------
// Signed requests.
// ---------------------------------------------------------------------------

/** Options of `signedPost`. */
export interface SignedPostOptions {
  /** Exact request body; the default is a modern `subscriptions/listen` request with the given id. */
  readonly body?: string;
  /** Opts into a signed stream with the 1.1 `Jack-Accept` line; omitted means no stream path. */
  readonly jackAccept?: string;
  /** JSON-RPC id of the default body (a raw lexeme, never re-encoded); defaults to 1. */
  readonly id?: number;
}

/** One signed POST plus everything needed to replay it byte-identically. */
export interface SignedPost {
  /** The Request handed to the handler. */
  readonly request: Request;
  /** The `sig` parameter of the request `Jack-Auth` (2.5 binds a stream to it). */
  readonly requestSig: string;
  /** The exact request body text that was signed. */
  readonly body: string;
}

/** The default body: a JSON-RPC request with the modern version mirror of spec 04 S12. */
function defaultBody(id: number): string {
  return (
    '{"jsonrpc":"2.0","id":' +
    String(id) +
    ',"method":"subscriptions/listen","params":{"_meta":{"' +
    META_VERSION_KEY +
    '":"' +
    MODERN_META_VERSION +
    '"}}}'
  );
}

/** The `Mcp-Method`/`MCP-Protocol-Version` mirrors a body implies; undefined when the body cannot supply them. */
interface BodyMirrors {
  readonly method?: string;
  readonly version?: string;
}

/** Reads the two modern mirrors a request body must carry (spec 04 S12) without trusting its types. */
function bodyMirrors(body: string): BodyMirrors {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return {};
  }
  if (typeof parsed !== "object" || parsed === null) {
    return {};
  }
  const record = parsed as Record<string, unknown>;
  const method = record["method"];
  const params = record["params"];
  let version: string | undefined;
  if (typeof params === "object" && params !== null) {
    const meta = (params as Record<string, unknown>)["_meta"];
    if (typeof meta === "object" && meta !== null) {
      const value = (meta as Record<string, unknown>)[META_VERSION_KEY];
      if (typeof value === "string") {
        version = value;
      }
    }
  }
  return {
    ...(typeof method === "string" ? { method } : {}),
    ...(version === undefined ? {} : { version }),
  };
}

/**
 * Signs one POST /mcp as the fixture user "alice" with a fresh nonce and the
 * fixture clock. The modern mirrors are derived from the body, so the request
 * survives the modern era rules; `Jack-Accept` is added only when asked (1.1).
 */
export function signedPost(options: SignedPostOptions = {}): SignedPost {
  const body = options.body ?? defaultBody(options.id ?? 1);
  const signer = seedSignerByName(USER_NAME);
  const header = signRequest(signer, fixtureAud, "POST", "/mcp", utf8(body), randomNonce(), fixtureNow);
  const requestSig = parseRequestAuth([header]).sig;
  const headers = new Headers({ "jack-auth": header });
  if (options.jackAccept !== undefined) {
    headers.set("jack-accept", options.jackAccept);
  }
  const mirrors = bodyMirrors(body);
  if (mirrors.method !== undefined) {
    headers.set("mcp-method", mirrors.method);
  }
  if (mirrors.version !== undefined) {
    headers.set("mcp-protocol-version", mirrors.version);
  }
  return {
    request: new Request("http://localhost/mcp", { method: "POST", headers, body }),
    requestSig,
    body,
  };
}

// ---------------------------------------------------------------------------
// Responses.
// ---------------------------------------------------------------------------

/** Options of `sseResponse`. */
export interface SseResponseOptions {
  /** Never close the handler body, so the stream stays open until the client cancels it. */
  readonly stayOpen?: boolean;
  /** Observes the cancellation of the handler body (3.7 / 3.3); called at most once. */
  readonly onCancel?: () => void;
}

/**
 * A handler answer with `content-type: text/event-stream` whose body emits the
 * given UTF-8 pieces. The pieces are enqueued up front (no pull loop), so a
 * `stayOpen` body has no pending read to spin on; `cancel` reports to the test.
 */
export function sseResponse(chunks: readonly string[], options: SseResponseOptions = {}): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller: ReadableStreamDefaultController<Uint8Array>): void {
      for (const chunk of chunks) {
        controller.enqueue(encoder.encode(chunk));
      }
      if (options.stayOpen !== true) {
        controller.close();
      }
    },
    cancel: (): void => {
      options.onCancel?.();
    },
  });
  return new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } });
}

/** The response body bytes. */
export async function readAll(response: Response): Promise<Uint8Array> {
  return new Uint8Array(await response.arrayBuffer());
}

/** The `Jack-Auth` response header value, or undefined when the answer carries none. */
export function authOf(response: Response): string | undefined {
  return response.headers.get("jack-auth") ?? undefined;
}

/** One parsed frame: the 2.6 shape with its 2.7 fields. */
export type ParsedFrame = StreamFrame;

/** Parses a whole signed stream body into its frames (comments and unknown fields produce nothing). */
export function parseFrames(bytes: Uint8Array): ParsedFrame[] {
  const reader = new StreamEventReader();
  const frames: ParsedFrame[] = [];
  for (const lines of reader.push(bytes)) {
    const parsed = parseStreamFrame(lines);
    if (!parsed.ok) {
      throw new Error("stream-harness: the signed body contains an unparseable event");
    }
    frames.push(parsed.value);
  }
  reader.finish();
  return frames;
}

// ---------------------------------------------------------------------------
// Client verification of a produced body.
// ---------------------------------------------------------------------------

/** Options of `verifyBody`. */
export interface VerifyBodyOptions {
  /** The real `Jack-Auth` open value of the response (2.1), never a fabricated one. */
  readonly jackAuth: string;
  /** The server's own response window W; defaults to 30 (3.5). */
  readonly windowSeconds?: number;
  /** The 3.2 cap the server applied; defaults to the client default. */
  readonly frameMaxBytes?: number;
  /** A known successor activation of the `svc` key (5.2). */
  readonly successorActivation?: number;
  /** The 4.5 idle timeout; defaults to the client default. */
  readonly streamIdleMs?: number;
  /** The JSON-RPC id of the opening request (6.3). */
  readonly requestId?: unknown;
  /** The 4.5 measured trailing silence; absent means the body ended. */
  readonly silentAfterMs?: number;
  /** The clock the verifier samples; defaults to `fixtureNow`, matching the harness default. */
  readonly now?: () => number;
}

/** A verification result plus the optional 6.3 completion flag. */
export type VerifiedBody = StreamVerifyResult & { readonly mcpComplete?: boolean };

/**
 * Verifies one produced stream body with the real client verifier: status 200,
 * the real `Jack-Auth`, the pinned `svc` public key, the harness clock and the
 * server window. Optional settings are spread only when set, so
 * exactOptionalPropertyTypes stays satisfied.
 */
export function verifyBody(bytes: Uint8Array, requestSig: string, options: VerifyBodyOptions): VerifiedBody {
  const server = seedSignerByName(SERVER_KEY_NAME);
  const kid = server.kid();
  const publicKey = server.publicKey();
  const now = options.now ?? ((): number => fixtureNow);
  return verifySignedStream({
    status: 200,
    headers: [
      ["Content-Type", "text/event-stream"],
      ["Jack-Auth", options.jackAuth],
    ],
    chunks: [{ bytes, arrivedAtMs: 0 }],
    resolveKey: (candidate: string) =>
      candidate === kid
        ? {
            kid,
            publicKey,
            ...(options.successorActivation === undefined ? {} : { successorActivation: options.successorActivation }),
          }
        : undefined,
    now,
    requestSig,
    windowSeconds: options.windowSeconds ?? 30,
    ...(options.frameMaxBytes === undefined ? {} : { frameMaxBytes: options.frameMaxBytes }),
    ...(options.streamIdleMs === undefined ? {} : { streamIdleMs: options.streamIdleMs }),
    ...(options.requestId === undefined ? {} : { requestId: options.requestId }),
    ...(options.silentAfterMs === undefined ? {} : { silentAfterMs: options.silentAfterMs }),
  });
}
