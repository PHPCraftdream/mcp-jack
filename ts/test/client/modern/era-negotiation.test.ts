/**
 * Spec 04 C9: era negotiation is a state machine driven by VERIFIED replies.
 * The `server/discover` probe decides the era, a `-32022` with a mutually
 * implemented version re-probes once, an unusable verdict fails the operation,
 * the legacy fallback runs `initialize` -> `notifications/initialized` and
 * carries the session and version headers afterwards, an expired session
 * re-runs the handshake without ever replaying a `tools/call`, and a
 * misread era is corrected from the operation's own refusal exactly once.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { EraNegotiationError, ModernClient } from "../../../src/client/modern.js";
import { RPCError } from "../../../src/client/errors.js";
import type { JsonValue } from "../../../src/client/rpc.js";
import { META_PROTOCOL_VERSION } from "../../../src/modern/request.js";
import { bodyOf, headerValues, newModernClient, newModernServer, rpcError, rpcResult } from "./support.js";
import type { ModernServer, RecordedRequest } from "./support.js";

/** The modern `-32020` / `-32021` / `-32022` family and the `-32602` an initializing server may send. */
const HEADER_MISMATCH = -32020;
const UNSUPPORTED_VERSION = -32022;
const INVALID_PARAMS = -32602;
const SESSION_EXPIRED = -32001;

/** The version the fake legacy server negotiates in its `initialize` result. */
const NEGOTIATED_VERSION = "2025-11-25";

/** The session id the fake legacy server assigns. */
const SESSION_ID = "sess-1";

/** Jack's own 400 envelope: a JSON object with no `jsonrpc` member, which C9 reads as the legacy era. */
const LEGACY_ENVELOPE = '{"error":{"code":"invalid_request","message":"x"}}';

/** The JSON-RPC method of one recorded request, null when the body carries none. */
function methodOf(req: RecordedRequest): JsonValue {
  return bodyOf(req)["method"] ?? null;
}

/** The recorded methods, in arrival order: the whole C9 dialogue of one case. */
function methodsOf(server: ModernServer): JsonValue[] {
  return server.requests.map(methodOf);
}

/** The recorded requests whose body method is method, in arrival order. */
function requestsOf(server: ModernServer, method: string): RecordedRequest[] {
  return server.requests.filter((req) => bodyOf(req)["method"] === method);
}

/** The request at index of a list; a missing one is a test bug, not a result. */
function at(requests: readonly RecordedRequest[], index: number): RecordedRequest {
  const req = requests[index];
  if (req === undefined) throw new Error("era test: no request at index " + String(index));
  return req;
}

/** The JSON-RPC id of one recorded request, 1 when it is not a number. */
function idOf(req: RecordedRequest): number {
  const id = bodyOf(req)["id"];
  return typeof id === "number" ? id : 1;
}

/** The `params._meta` member of one recorded request, or undefined when the request carries no `_meta` object. */
function metaOf(req: RecordedRequest): { readonly [key: string]: JsonValue } | undefined {
  const params = bodyOf(req)["params"];
  if (params === null || typeof params !== "object" || Array.isArray(params)) return undefined;
  const meta = params["_meta"];
  if (meta === null || typeof meta !== "object" || Array.isArray(meta)) return undefined;
  return meta;
}

/** The `params` member of one recorded request, or undefined when it is not an object. */
function paramsOf(req: RecordedRequest): { readonly [key: string]: JsonValue } | undefined {
  const params = bodyOf(req)["params"];
  if (params === null || typeof params !== "object" || Array.isArray(params)) return undefined;
  return params;
}

/** The `_meta` protocol version of one recorded request, undefined when it carries none. */
function metaVersionOf(req: RecordedRequest): JsonValue | undefined {
  const meta = metaOf(req);
  return meta !== undefined ? meta[META_PROTOCOL_VERSION] : undefined;
}

/** The signed response the fake server returns, named through the server so the helpers need no DOM types. */
type SignedResponse = ReturnType<ModernServer["sign"]>;

/** A method the case never scripted is a test bug. */
function unexpected(req: RecordedRequest): never {
  throw new Error("era test: unexpected method " + JSON.stringify(methodOf(req)));
}

/** The legacy `initialize` answer: the negotiated version, plus the session id the server assigns. */
function initializeReply(server: ModernServer, req: RecordedRequest): SignedResponse {
  return server.signWithHeaders(200, req.auth, rpcResult(idOf(req), { protocolVersion: NEGOTIATED_VERSION }), [["Mcp-Session-Id", SESSION_ID]]);
}

/** A legacy-era server: discover answers Jack's envelope, initialize assigns a session, initialized answers 202. */
function legacyHandler(server: ModernServer, operation: (req: RecordedRequest) => SignedResponse): (req: RecordedRequest) => SignedResponse {
  return (req) => {
    const method = methodOf(req);
    if (method === "server/discover") return server.sign(400, req.auth, LEGACY_ENVELOPE);
    if (method === "initialize") return initializeReply(server, req);
    if (method === "notifications/initialized") return server.sign(202, req.auth, "");
    return operation(req);
  };
}

test("era negotiation: an initialize error reply aborts the legacy fallback", async () => {
  const server = newModernServer();
  server.handle = (req) => {
    if (methodOf(req) === "initialize") return server.sign(200, req.auth, rpcError(idOf(req), INVALID_PARAMS, "invalid params"));
    return legacyHandler(server, unexpected)(req);
  };
  const mc = new ModernClient(newModernClient(server, "auto"));
  await assert.rejects(mc.call("tools/list"), "era: an initialize error reply fails the operation");

  // The `-32602` answer proves nothing about the era, so the client stops after
  // the probe and the handshake instead of sending the operation.
  assert.deepEqual(methodsOf(server), ["server/discover", "initialize"], "era: the aborted fallback sends no operation");
});

test("era negotiation: the session id and negotiated version reach notifications/initialized and the next call", async () => {
  const server = newModernServer();
  server.handle = legacyHandler(server, (req) => {
    if (methodOf(req) === "tools/list") return server.sign(200, req.auth, rpcResult(idOf(req), { tools: [] }));
    return unexpected(req);
  });
  const mc = new ModernClient(newModernClient(server, "auto"));
  assert.deepEqual(await mc.call("tools/list"), { tools: [] }, "era: the legacy operation answers its result");

  assert.deepEqual(
    methodsOf(server),
    ["server/discover", "initialize", "notifications/initialized", "tools/list"],
    "era: the handshake precedes the first legacy operation",
  );

  const initialized = at(requestsOf(server, "notifications/initialized"), 0);
  assert.equal(Object.hasOwn(bodyOf(initialized), "id"), false, "era: notifications/initialized carries no id");
  assert.deepEqual(headerValues(initialized, "mcp-protocol-version"), [NEGOTIATED_VERSION], "era: the notification carries the negotiated version");
  assert.deepEqual(headerValues(initialized, "mcp-session-id"), [SESSION_ID], "era: the notification carries the assigned session id");

  const list = at(requestsOf(server, "tools/list"), 0);
  assert.deepEqual(headerValues(list, "mcp-protocol-version"), [NEGOTIATED_VERSION], "era: the operation carries the negotiated version");
  assert.deepEqual(headerValues(list, "mcp-session-id"), [SESSION_ID], "era: the operation carries the assigned session id");
  const params = paramsOf(list);
  assert.equal(params !== undefined && Object.hasOwn(params, "_meta"), false, "era: a legacy request carries no _meta");
});

test("era negotiation: a 404 for a known session id re-runs the handshake once", async () => {
  const server = newModernServer();
  let lists = 0;
  server.handle = legacyHandler(server, (req) => {
    if (methodOf(req) !== "tools/list") return unexpected(req);
    lists++;
    if (lists === 1) return server.sign(404, req.auth, rpcError(idOf(req), SESSION_EXPIRED, "session expired"));
    return server.sign(200, req.auth, rpcResult(idOf(req), { tools: [] }));
  });
  const mc = new ModernClient(newModernClient(server, "auto"));
  assert.deepEqual(await mc.call("tools/list"), { tools: [] }, "era: the re-sent operation answers its result");

  assert.deepEqual(
    methodsOf(server),
    ["server/discover", "initialize", "notifications/initialized", "tools/list", "initialize", "notifications/initialized", "tools/list"],
    "era: an expired session re-handshakes and re-sends the operation once",
  );
});

test("era negotiation: a tools/call 404 is returned to the caller after the handshake", async () => {
  const server = newModernServer();
  server.handle = legacyHandler(server, (req) => {
    if (methodOf(req) !== "tools/call") return unexpected(req);
    return server.sign(404, req.auth, rpcError(idOf(req), SESSION_EXPIRED, "session expired"));
  });
  const mc = new ModernClient(newModernClient(server, "auto"));
  await assert.rejects(
    () => mc.call("tools/call", { name: "svc.status", arguments: {} }),
    (err: unknown): boolean => err instanceof RPCError && err.code === SESSION_EXPIRED,
    "era: the session 404 of a tools/call reaches the caller",
  );

  // The handshake re-runs, but the call is never blindly replayed: it may have
  // run server-side already ("Session" row of docs/design/mcp-compatibility.md).
  assert.deepEqual(
    methodsOf(server),
    ["server/discover", "initialize", "notifications/initialized", "tools/call", "initialize", "notifications/initialized"],
    "era: a tools/call 404 is not re-sent",
  );
});

test("era negotiation: unsupported_version_no_overlap aborts", async () => {
  const server = newModernServer();
  server.handle = (req) => {
    if (methodOf(req) !== "server/discover") return unexpected(req);
    return server.sign(400, req.auth, rpcError(idOf(req), UNSUPPORTED_VERSION, "Unsupported protocol version", { supported: [] }));
  };
  const mc = new ModernClient(newModernClient(server, "auto"));
  await assert.rejects(
    () => mc.call("tools/list"),
    (err: unknown): boolean => err instanceof EraNegotiationError && err.detection.reason === "unsupported_version_no_overlap",
    "era: a -32022 with no common version fails the operation",
  );
  assert.deepEqual(methodsOf(server), ["server/discover"], "era: an aborted negotiation sends no operation");
});

test("era negotiation: retry_with_supported re-probes once with the supported version", async () => {
  const server = newModernServer();
  let discovers = 0;
  server.handle = (req) => {
    const method = methodOf(req);
    if (method === "server/discover") {
      discovers++;
      if (discovers === 1) {
        return server.sign(400, req.auth, rpcError(idOf(req), UNSUPPORTED_VERSION, "Unsupported protocol version", { supported: ["2026-07-28"] }));
      }
      return server.sign(200, req.auth, rpcResult(idOf(req), { resultType: "complete" }));
    }
    if (method === "tools/list") return server.sign(200, req.auth, rpcResult(idOf(req), { structuredContent: { ok: true }, ttlMs: 0 }));
    return unexpected(req);
  };
  // The client starts on the legacy version and lets the server move it to the
  // modern one; the re-probe is what proves the move.
  const mc = new ModernClient(newModernClient(server, "auto"), { version: NEGOTIATED_VERSION });
  assert.deepEqual(await mc.call("tools/list"), { ok: true }, "era: the operation runs at the retried version");

  const probes = requestsOf(server, "server/discover");
  assert.equal(probes.length, 2, "era: a mutually implemented version re-probes exactly once");
  assert.equal(metaVersionOf(at(probes, 0)), NEGOTIATED_VERSION, "era: the first probe uses the configured version");
  assert.equal(metaVersionOf(at(probes, 1)), "2026-07-28", "era: the re-probe uses the supported version");
});

test("era negotiation: resetEra re-probes", async () => {
  const server = newModernServer();
  server.handle = (req) => {
    const method = methodOf(req);
    if (method === "server/discover") return server.sign(200, req.auth, rpcResult(idOf(req), { resultType: "complete" }));
    if (method === "tools/list") return server.sign(200, req.auth, rpcResult(idOf(req), { tools: [] }));
    return unexpected(req);
  };
  const mc = new ModernClient(newModernClient(server, "auto"));
  assert.deepEqual(await mc.call("tools/list"), { tools: [] }, "era: the modern operation answers its result");
  assert.equal(mc.era, "modern", "era: the probe adopted the modern era");

  mc.resetEra();
  assert.equal(mc.era, "auto", "era: resetEra drops the cached verdict");
  assert.deepEqual(await mc.call("tools/list"), { tools: [] }, "era: the operation still succeeds after a re-probe");
  assert.equal(requestsOf(server, "server/discover").length, 2, "era: resetEra makes the next operation probe again");
});

test("era negotiation: a legacy request answered with a modern error re-probes", async () => {
  const server = newModernServer();
  let discovers = 0;
  let lists = 0;
  server.handle = (req) => {
    const method = methodOf(req);
    if (method === "server/discover") {
      discovers++;
      if (discovers === 1) return server.sign(400, req.auth, LEGACY_ENVELOPE);
      return server.sign(200, req.auth, rpcResult(idOf(req), { resultType: "complete" }));
    }
    if (method === "tools/list") {
      lists++;
      if (lists === 1) return server.sign(400, req.auth, rpcError(idOf(req), HEADER_MISMATCH, "Header mismatch: Mcp-Method is missing"));
      return server.sign(200, req.auth, rpcResult(idOf(req), { structuredContent: { ok: true }, ttlMs: 0 }));
    }
    return legacyHandler(server, unexpected)(req);
  };
  const mc = new ModernClient(newModernClient(server, "auto"));
  assert.deepEqual(await mc.call("tools/list"), { ok: true }, "era: the retried operation answers its result");

  assert.deepEqual(
    methodsOf(server),
    ["server/discover", "initialize", "notifications/initialized", "tools/list", "server/discover", "tools/list"],
    "era: a modern-era refusal of a legacy attempt re-probes and retries once",
  );

  const retried = at(requestsOf(server, "tools/list"), 1);
  assert.deepEqual(headerValues(retried, "mcp-protocol-version"), ["2026-07-28"], "era: the retry speaks the modern version");
  assert.notEqual(metaOf(retried), undefined, "era: the retry carries _meta");
});
test("era negotiation: initialize advertises the newest legacy version and carries no version header", async () => {
  const server = newModernServer();
  server.handle = legacyHandler(server, (req) => {
    if (methodOf(req) === "tools/list") return server.sign(200, req.auth, rpcResult(idOf(req), { tools: [] }));
    return unexpected(req);
  });
  const mc = new ModernClient(newModernClient(server, "auto"));
  assert.deepEqual(await mc.call("tools/list"), { tools: [] }, "era: the fallback operation answers its result");

  const probe = at(requestsOf(server, "server/discover"), 0);
  assert.deepEqual(headerValues(probe, "mcp-protocol-version"), ["2026-07-28"], "era: the probe is a modern request");

  const initialize = at(requestsOf(server, "initialize"), 0);
  // A both-profile server reads the era from this header: sending the modern
  // version here made the initialize look modern and get refused instead of
  // being served as legacy.
  assert.deepEqual(headerValues(initialize, "mcp-protocol-version"), [], "era: initialize carries no version header");
  assert.equal(paramsOf(initialize)?.["protocolVersion"], NEGOTIATED_VERSION, "era: initialize advertises the newest legacy version");

  const initialized = at(requestsOf(server, "notifications/initialized"), 0);
  assert.deepEqual(headerValues(initialized, "mcp-protocol-version"), [NEGOTIATED_VERSION], "era: the notification carries the negotiated version");
  assert.deepEqual(headerValues(initialized, "mcp-session-id"), [SESSION_ID], "era: the notification carries the assigned session id");

  const list = at(requestsOf(server, "tools/list"), 0);
  assert.deepEqual(headerValues(list, "mcp-protocol-version"), [NEGOTIATED_VERSION], "era: the operation carries the negotiated version");
  assert.deepEqual(headerValues(list, "mcp-session-id"), [SESSION_ID], "era: the operation carries the assigned session id");
});

test("era negotiation: a rejected notifications/initialized leaves no handshake credit", async () => {
  const server = newModernServer();
  let initialized = 0;
  server.handle = (req) => {
    const method = methodOf(req);
    if (method === "server/discover") return server.sign(400, req.auth, LEGACY_ENVELOPE);
    if (method === "initialize") return initializeReply(server, req);
    if (method === "notifications/initialized") {
      initialized++;
      // The first handshake is refused: the session must not be adopted.
      if (initialized === 1) return server.sign(400, req.auth, rpcError(idOf(req), INVALID_PARAMS, "invalid params"));
      return server.sign(202, req.auth, "");
    }
    if (method === "tools/list") return server.sign(200, req.auth, rpcResult(idOf(req), { tools: [] }));
    return unexpected(req);
  };
  const mc = new ModernClient(newModernClient(server, "auto"));
  await assert.rejects(
    () => mc.call("tools/list"),
    (err: unknown): boolean =>
      err instanceof Error && err.message === "modern profile: notifications/initialized answered HTTP 400",
    "era: a refused notification fails the operation",
  );
  assert.equal(server.requests.length, 3, "era: a refused handshake sends no operation");

  assert.deepEqual(await mc.call("tools/list"), { tools: [] }, "era: the retried handshake runs the operation");
  // Without the cleared credit the second call would have sent tools/list with
  // no initialize; a server that refused the notification would then see a
  // legacy request its session never accepted.
  assert.deepEqual(
    methodsOf(server),
    ["server/discover", "initialize", "notifications/initialized", "server/discover", "initialize", "notifications/initialized", "tools/list"],
    "era: the next call handshakes again instead of sending a legacy request without one",
  );
});

test("era negotiation: an initialize negotiating a modern version is refused", async () => {
  const server = newModernServer();
  server.handle = (req) => {
    const method = methodOf(req);
    if (method === "server/discover") return server.sign(400, req.auth, LEGACY_ENVELOPE);
    if (method === "initialize") {
      return server.sign(200, req.auth, rpcResult(idOf(req), { protocolVersion: "2026-07-28" }));
    }
    return unexpected(req);
  };
  const mc = new ModernClient(newModernClient(server, "auto"));
  await assert.rejects(
    () => mc.call("tools/list"),
    (err: unknown): boolean =>
      err instanceof Error && err.message.includes("2026-07-28") && err.message.includes("not a legacy version"),
    "era: a modern version in a legacy initialize reply fails the operation",
  );
  // Adopting a modern version from the legacy handshake would leave the client
  // mixing eras, so nothing after the refused initialize may be sent.
  assert.equal(requestsOf(server, "notifications/initialized").length, 0, "era: a refused initialize sends no notification");
  assert.deepEqual(methodsOf(server), ["server/discover", "initialize"], "era: the refused initialize ends the fallback");
});

test("era negotiation: a legacy supported entry is retried by handshake, not by a modern probe", async () => {
  const server = newModernServer();
  let discovers = 0;
  server.handle = (req) => {
    const method = methodOf(req);
    if (method === "server/discover") {
      discovers++;
      // The first entry is the version just attempted, so retrying it cannot
      // succeed; the later legacy entry is the only usable overlap.
      return server.sign(
        400,
        req.auth,
        rpcError(idOf(req), UNSUPPORTED_VERSION, "Unsupported protocol version", { supported: ["2026-07-28", "2025-11-25"] }),
      );
    }
    if (method === "initialize") return initializeReply(server, req);
    if (method === "notifications/initialized") return server.sign(202, req.auth, "");
    if (method === "tools/list") return server.sign(200, req.auth, rpcResult(idOf(req), { tools: [] }));
    return unexpected(req);
  };
  const mc = new ModernClient(newModernClient(server, "auto"));
  assert.deepEqual(await mc.call("tools/list"), { tools: [] }, "era: the legacy retry runs the operation");
  assert.equal(mc.era, "legacy", "era: the legacy retry adopts the legacy era");

  // A legacy endpoint has no modern probe to answer: a second server/discover
  // would be sent at a version the server has just refused.
  assert.equal(discovers, 1, "era: the legacy retry sends no modern probe");
  const initialize = at(requestsOf(server, "initialize"), 0);
  assert.deepEqual(headerValues(initialize, "mcp-protocol-version"), [], "era: the retried handshake still carries no version header");
  assert.equal(paramsOf(initialize)?.["protocolVersion"], NEGOTIATED_VERSION, "era: the handshake runs at the chosen legacy version");
});

test("era negotiation: a supported list holding only the attempted version aborts without a second probe", async () => {
  const server = newModernServer();
  server.handle = (req) => {
    if (methodOf(req) !== "server/discover") return unexpected(req);
    return server.sign(
      400,
      req.auth,
      rpcError(idOf(req), UNSUPPORTED_VERSION, "Unsupported protocol version", { supported: ["2026-07-28"] }),
    );
  };
  const mc = new ModernClient(newModernClient(server, "auto"));
  await assert.rejects(
    () => mc.call("tools/list"),
    (err: unknown): boolean => err instanceof EraNegotiationError && err.detection.reason === "unsupported_version_no_overlap",
    "era: a supported list with no other implemented version aborts",
  );
  assert.equal(server.requests.length, 1, "era: retrying the attempted version is refused instead of probing again");
  assert.equal(mc.era, "auto", "era: an unconfirmed version never adopts an era");
});

test("era negotiation: a second retry verdict exhausts the one-retry budget", async () => {
  const server = newModernServer();
  let discovers = 0;
  server.handle = (req) => {
    if (methodOf(req) !== "server/discover") return unexpected(req);
    discovers++;
    // The first verdict selects the modern version; the second arrives after
    // the one allowed re-probe and must not adopt anything.
    const supported = discovers === 1 ? ["2026-07-28"] : ["2026-07-28", "2025-11-25"];
    return server.sign(
      400,
      req.auth,
      rpcError(idOf(req), UNSUPPORTED_VERSION, "Unsupported protocol version", { supported }),
    );
  };
  const mc = new ModernClient(newModernClient(server, "auto"), { version: NEGOTIATED_VERSION });
  await assert.rejects(
    () => mc.call("tools/list"),
    (err: unknown): boolean => err instanceof EraNegotiationError && err.detection.reason === "unsupported_version_no_overlap",
    "era: a retry verdict after the one allowed re-probe aborts",
  );
  // The budget is two probes in total: a third would advertise a version no
  // verified answer has confirmed.
  assert.equal(requestsOf(server, "server/discover").length, 2, "era: a negotiation sends at most two probes");
  assert.equal(mc.era, "auto", "era: the unconfirmed modern version never adopts the modern era");
});
