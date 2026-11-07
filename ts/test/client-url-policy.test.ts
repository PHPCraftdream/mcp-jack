/** Client destination-URL policy tests: the shared table spec/fixtures/client-url-policy.json run against every client entry point, plus bypass, loopback/HTTPS round trip and redirect regressions. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Code, JackError } from "../src/errors.js";
import { encodeBase64URL } from "../src/encoding.js";
import {
  Client,
  DestinationRefusedError,
  RedirectRefusedError,
  checkDestination,
  clientFromProfile,
  createSigningFetch,
  loadProfile,
  profileToJSON,
  validateProfile,
} from "../src/client/index.js";
import type { Profile, Signer } from "../src/client/index.js";
import { fixture } from "./fixtures.js";
import { fixtureAud, fixtureNow, newTestServer, rpcResultBody, seedSignerByName } from "./client-harness.js";

/*
 * Entry paths exercised by EVERY row of the table (no row is skipped; extra
 * optional row fields such as "parse_reject", which only concern Go's parser,
 * are ignored: every allow=true row must be accepted by TypeScript):
 * - checkDestination(url): allowed rows accepted, refused rows throw DestinationRefusedError.
 * - Client constructor: refused rows throw DestinationRefusedError before any signer or fetch use;
 *   allowed rows construct, and the first callTool reaches the spy fetch exactly once with the
 *   WHATWG-normalised href (which must itself pass checkDestination) and redirect "error".
 * - validateProfile: refused rows throw, allowed rows pass.
 * - loadProfile: refused rows throw, allowed rows load with the url unchanged.
 * - clientFromProfile: refused rows throw before any fetch; allowed rows build a client whose
 *   first call reaches the spy fetch exactly once.
 * - createSigningFetch with the raw URL string: refused rows reject with DestinationRefusedError
 *   before any signer or fetch use; allowed rows reach the spy fetch exactly once with the string
 *   untouched and redirect "error".
 * Each fixture-driven test keeps per-path tallies asserted equal to the number of rows.
 */

/** One row of the shared policy table. */
interface PolicyCase {
  readonly name: string;
  readonly url: string;
  readonly allow: boolean;
}

/** Reads and strictly decodes spec/fixtures/client-url-policy.json. */
function loadPolicyCases(): readonly PolicyCase[] {
  const doc = fixture("client-url-policy.json");
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new Error("client-url-policy.json: not an object");
  }
  const cases = doc["cases"];
  if (!Array.isArray(cases)) {
    throw new Error("client-url-policy.json: cases is not an array");
  }
  return cases.map((item, index): PolicyCase => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error(`client-url-policy.json: cases[${index}] is not an object`);
    }
    const name = item["name"];
    const url = item["url"];
    const allow = item["allow"];
    if (typeof name !== "string" || typeof url !== "string" || typeof allow !== "boolean") {
      throw new Error(`client-url-policy.json: cases[${index}] has a wrong field type`);
    }
    return { name, url, allow };
  });
}

const cases = loadPolicyCases();

/** The failure every spy fetch answers with: reaching it proves the policy let the call through, and no network is touched. */
const CANNED = "canned transport failure";

const isCanned = (err: unknown): boolean => err instanceof Error && err.message === CANNED;

/** One recorded call of a spy fetch. */
interface FetchCall {
  readonly url: string;
  readonly redirect: string | undefined;
}

/** A fetch that records its calls and always fails with CANNED. */
function spyFetch(): { fetchImpl: typeof fetch; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  const fetchImpl = async (input: string | Request | URL, init?: RequestInit): Promise<Response> => {
    calls.push({ url: String(input), redirect: init?.redirect });
    throw new Error(CANNED);
  };
  return { fetchImpl, calls };
}

/** An alice signer counting every use, to prove a refusal happens before signing. */
function spySigner(): { signer: Signer; uses: () => number } {
  const inner = seedSignerByName("alice");
  let n = 0;
  const signer: Signer = {
    sign(message: Uint8Array): Uint8Array {
      n++;
      return inner.sign(message);
    },
    publicKey(): Uint8Array {
      n++;
      return inner.publicKey();
    },
    kid(): string {
      n++;
      return inner.kid();
    },
  };
  return { signer, uses: () => n };
}

const server = newTestServer();

test("policy table is loaded", () => {
  assert.ok(cases.length >= 200, `expected the full table, got ${cases.length} cases`);
});

test("checkDestination runs every fixture case", () => {
  let exercised = 0;
  for (const c of cases) {
    if (c.allow) {
      assert.doesNotThrow(() => checkDestination(c.url), `${c.name}: ${JSON.stringify(c.url)} must be allowed`);
    } else {
      assert.throws(() => checkDestination(c.url), DestinationRefusedError, `${c.name}: ${JSON.stringify(c.url)} must be refused`);
    }
    exercised++;
  }
  assert.equal(exercised, cases.length);
});

test("Client constructor runs every fixture case", async () => {
  let refused = 0;
  let called = 0;
  for (const c of cases) {
    const spy = spyFetch();
    const sp = spySigner();
    const make = (): Client => new Client({ baseUrl: c.url, aud: fixtureAud, signer: sp.signer, serverKey: server.pub, fetchImpl: spy.fetchImpl });
    if (!c.allow) {
      assert.throws(make, DestinationRefusedError, `${c.name}: constructor must refuse`);
      assert.equal(spy.calls.length, 0, `${c.name}: fetch must not be called`);
      assert.equal(sp.uses(), 0, `${c.name}: signer must not be used`);
      refused++;
    } else {
      assert.doesNotThrow(() => new URL(c.url), `${c.name}: an allowed row must parse as a WHATWG URL`);
      const normalised = new URL(c.url).href;
      assert.doesNotThrow(() => checkDestination(normalised), `${c.name}: the normalised href ${normalised} must pass the policy`);
      const client = make();
      await assert.rejects(client.callTool("jack.whoami"), isCanned, `${c.name}: call must reach the fetch`);
      assert.equal(spy.calls.length, 1, `${c.name}: fetch calls`);
      assert.equal(spy.calls[0]?.url, normalised, `${c.name}: the Client passes the normalised href`);
      assert.equal(spy.calls[0]?.redirect, "error", `${c.name}: redirect must stay error`);
      called++;
    }
  }
  assert.equal(refused + called, cases.length);
  assert.equal(called, cases.filter((c) => c.allow).length);
});

test("profile validation and loading run every fixture case", async () => {
  const signer = seedSignerByName("alice");
  const tally = { refusedRows: 0, validated: 0, loaded: 0, clientBuilt: 0, called: 0 };
  for (const c of cases) {
    const spy = spyFetch();
    const profile: Profile = { url: c.url, aud: fixtureAud, serverPublicKey: encodeBase64URL(server.pub) };
    const doc = JSON.stringify(profileToJSON(profile));
    if (!c.allow) {
      assert.throws(() => validateProfile(profile), Error, `${c.name}: validateProfile must refuse`);
      assert.throws(() => loadProfile(doc), Error, `${c.name}: loadProfile must refuse`);
      assert.throws(() => clientFromProfile(profile, signer, { fetchImpl: spy.fetchImpl }), Error, `${c.name}: clientFromProfile must refuse`);
      assert.equal(spy.calls.length, 0, `${c.name}: fetch must not be called`);
      tally.refusedRows++;
    } else {
      assert.doesNotThrow(() => new URL(c.url), `${c.name}: an allowed row must parse as a WHATWG URL`);
      assert.doesNotThrow(() => validateProfile(profile), `${c.name}: validateProfile must accept`);
      tally.validated++;
      assert.equal(loadProfile(doc).url, c.url, `${c.name}: loadProfile must accept`);
      tally.loaded++;
      const client = clientFromProfile(profile, signer, { fetchImpl: spy.fetchImpl });
      tally.clientBuilt++;
      await assert.rejects(client.callTool("jack.whoami"), isCanned, `${c.name}: call must reach the fetch`);
      assert.equal(spy.calls.length, 1, `${c.name}: fetch calls`);
      assert.equal(spy.calls[0]?.url, new URL(c.url).href, `${c.name}: the Client passes the normalised href`);
      tally.called++;
    }
  }
  const allowed = cases.filter((c) => c.allow).length;
  assert.equal(tally.refusedRows + allowed, cases.length);
  assert.deepEqual(
    { validated: tally.validated, loaded: tally.loaded, clientBuilt: tally.clientBuilt, called: tally.called },
    { validated: allowed, loaded: allowed, clientBuilt: allowed, called: allowed },
  );
});

test("createSigningFetch runs every fixture case", async () => {
  let refused = 0;
  let reached = 0;
  for (const c of cases) {
    const spy = spyFetch();
    const sp = spySigner();
    const sf = createSigningFetch({ aud: fixtureAud, signer: sp.signer, serverKey: server.pub }, spy.fetchImpl);
    const init = { method: "POST", headers: { "content-type": "application/json" }, body: '{"ping":1}' };
    if (!c.allow) {
      await assert.rejects(sf(c.url, init), DestinationRefusedError, `${c.name}: must refuse`);
      assert.equal(spy.calls.length, 0, `${c.name}: fetch must not be called`);
      assert.equal(sp.uses(), 0, `${c.name}: signer must not be used`);
      refused++;
    } else {
      assert.doesNotThrow(() => new URL(c.url), `${c.name}: an allowed row must parse as a WHATWG URL`);
      await assert.rejects(sf(c.url, init), isCanned, `${c.name}: must reach the fetch`);
      assert.equal(spy.calls.length, 1, `${c.name}: fetch calls`);
      assert.equal(spy.calls[0]?.url, c.url, `${c.name}: the URL string is passed through untouched`);
      assert.equal(spy.calls[0]?.redirect, "error", `${c.name}: redirect must stay error`);
      reached++;
    }
  }
  assert.equal(refused + reached, cases.length);
  assert.equal(reached, cases.filter((c) => c.allow).length);
});

test("createSigningFetch refuses a remote http destination in every input form", async () => {
  const targets = ["http://svc.example.test/mcp", "http://localhost/mcp", "http://10.0.0.1:8080/mcp", "http://127.0.0.1.nip.io/mcp", "http://[::2]/mcp"];
  for (const target of targets) {
    const spy = spyFetch();
    const sp = spySigner();
    const sf = createSigningFetch({ aud: fixtureAud, signer: sp.signer, serverKey: server.pub }, spy.fetchImpl);
    const init = { method: "POST", body: "x" };
    await assert.rejects(sf(target, init), DestinationRefusedError, `string ${target}`);
    await assert.rejects(sf(new URL(target), init), DestinationRefusedError, `URL ${target}`);
    await assert.rejects(sf(new Request(target, { method: "POST", body: "x" })), DestinationRefusedError, `Request ${target}`);
    await assert.rejects(sf(new Request(target, { method: "POST", body: "x" }), { jackSigner: sp.signer }), DestinationRefusedError, `Request+init ${target}`);
    assert.equal(spy.calls.length, 0, `${target}: fetch must not be called`);
    assert.equal(sp.uses(), 0, `${target}: signer must not be used`);
  }
});

test("a refused destination does not read the body", async () => {
  const spy = spyFetch();
  const sf = createSigningFetch({ aud: fixtureAud, signer: seedSignerByName("alice"), serverKey: server.pub }, spy.fetchImpl);
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("x"));
      controller.close();
    },
  });
  await assert.rejects(sf("http://svc.example.test/mcp", { method: "POST", body: stream }), DestinationRefusedError);
  assert.equal(stream.locked, false, "the refused request must not have read the body");
  assert.equal(spy.calls.length, 0);
});

test("a non-canonical loopback spelling is refused as a string", async () => {
  const spy = spyFetch();
  const sf = createSigningFetch({ aud: fixtureAud, signer: seedSignerByName("alice"), serverKey: server.pub }, spy.fetchImpl);
  await assert.rejects(sf("http://0x7f.0.0.1/mcp", { method: "POST", body: "x" }), DestinationRefusedError);
  assert.equal(spy.calls.length, 0);
});

/** A signing fetch pinned to the test server, clocked at fixtureNow. */
function newServerTransport(): ReturnType<typeof createSigningFetch> {
  return createSigningFetch(
    { aud: fixtureAud, signer: seedSignerByName("alice"), serverKey: server.pub, clock: () => fixtureNow, windowSeconds: 30 },
    server.fetch,
  );
}

test("signed round trips over loopback http and remote https", async () => {
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResultBody('{"ok":true}'));
  const urls = ["http://127.0.0.1:8080/mcp?q=1", "http://[::1]:8080/mcp?q=1", "https://svc.example.test/mcp?q=1"];
  for (const url of urls) {
    const resp = await newServerTransport()(url, { method: "POST", headers: { "content-type": "application/json" }, body: '{"ping":1}' });
    assert.equal(resp.status, 200, `${url}: status`);
    assert.equal(server.lastRequest?.target, "/mcp?q=1", `${url}: signed target`);
    assert.equal(server.lastRequest?.redirect, "error", `${url}: redirect`);
  }
});

test("Client signed round trip over loopback and remote https", async () => {
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResultBody('{"ok":true}'));
  for (const baseUrl of ["http://127.0.0.1:8080/mcp", "http://[::1]:8080/mcp", "https://svc.example.test/mcp"]) {
    const client = new Client({
      baseUrl,
      aud: fixtureAud,
      signer: seedSignerByName("alice"),
      serverKey: server.pub,
      fetchImpl: server.fetch,
      clock: () => fixtureNow,
      windowSeconds: 30,
    });
    assert.deepEqual(await client.callTool("jack.whoami"), { ok: true }, `${baseUrl}: result`);
  }
});

/** A response body that records whether it was cancelled. */
function trackedBody(): { body: ReadableStream<Uint8Array>; cancelled: () => boolean } {
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new TextEncoder().encode("x"));
    },
    cancel() {
      cancelled = true;
    },
  });
  return { body, cancelled: () => cancelled };
}

test("redirect answers from the injected fetch are refused and disposed", async () => {
  const requested = "https://svc.example.test/mcp";
  const makers: readonly { readonly name: string; readonly make: (body: ReadableStream<Uint8Array>) => Response }[] = [
    { name: "301", make: (body) => new Response(body, { status: 301, headers: { location: "https://evil.example/mcp" } }) },
    { name: "302", make: (body) => new Response(body, { status: 302, headers: { location: "http://evil.example/mcp" } }) },
    { name: "303", make: (body) => new Response(body, { status: 303, headers: { location: requested } }) },
    { name: "307", make: (body) => new Response(body, { status: 307, headers: { location: requested } }) },
    { name: "308", make: (body) => new Response(body, { status: 308, headers: { location: "https://evil.example/mcp" } }) },
    {
      name: "opaqueredirect",
      make: (body) => {
        const r = new Response(body, { status: 200 });
        Object.defineProperty(r, "type", { value: "opaqueredirect" });
        return r;
      },
    },
    {
      name: "redirected",
      make: (body) => {
        const r = new Response(body, { status: 200 });
        Object.defineProperty(r, "redirected", { value: true });
        return r;
      },
    },
    {
      name: "url differs",
      make: (body) => {
        const r = new Response(body, { status: 200 });
        Object.defineProperty(r, "url", { value: "https://other.example/mcp" });
        return r;
      },
    },
  ];
  for (const m of makers) {
    const tracked = trackedBody();
    const calls: FetchCall[] = [];
    const fetchImpl = async (input: string | Request | URL, init?: RequestInit): Promise<Response> => {
      calls.push({ url: String(input), redirect: init?.redirect });
      return m.make(tracked.body);
    };
    const sf = createSigningFetch({ aud: fixtureAud, signer: seedSignerByName("alice"), serverKey: server.pub, clock: () => fixtureNow }, fetchImpl);
    await assert.rejects(sf(requested, { method: "POST", body: '{"ping":1}' }), RedirectRefusedError, m.name);
    assert.equal(calls.length, 1, `${m.name}: fetch calls`);
    assert.equal(calls[0]?.redirect, "error", `${m.name}: redirect must stay error`);
    assert.equal(tracked.cancelled(), true, `${m.name}: body must be cancelled`);
  }
});

test("a response url equal to the requested url is accepted", async () => {
  const requested = "https://svc.example.test/mcp";
  server.handle = (auth) => {
    const r = server.writeSignedJSON(auth, 200, rpcResultBody('{"ok":true}'));
    Object.defineProperty(r, "url", { value: requested });
    return r;
  };
  const resp = await newServerTransport()(requested, { method: "POST", body: '{"ping":1}' });
  assert.equal(resp.status, 200);
});

/** Gives an injected response a realistic `url` (a real fetch Response.url is the final url WITHOUT the fragment). */
function withUrl(resp: Response, url: string): Response {
  Object.defineProperty(resp, "url", { value: url });
  return resp;
}

/** The harness server fetch, answering with a non-empty, realistic, fragmentless Response.url. */
function serverFetchReportingUrl(responseUrl: string): typeof fetch {
  return async (input: string | Request | URL, init?: RequestInit): Promise<Response> => withUrl(await server.fetch(input, init), responseUrl);
}

// REGRESSION: a fragment in the requested url. A valid baseUrl such as
// "https://svc.example.test/mcp#frag" is allowed by the policy and kept by the
// Client, but a real fetch Response.url never contains the fragment. Before the
// fix refuseRedirected compared new URL(resp.url).href with
// new URL(requested).href, the fragment made the two hrefs differ, and a
// perfectly valid signed response was refused with RedirectRefusedError
// ("response url differs"). The comparison now ignores the fragment on copies
// of both urls; the signed target (pathname + search) is unchanged.
test("Client with a fragment in baseUrl accepts a fragmentless response url", async () => {
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResultBody('{"ok":true}'));
  const client = new Client({
    baseUrl: "https://svc.example.test/mcp#frag",
    aud: fixtureAud,
    signer: seedSignerByName("alice"),
    serverKey: server.pub,
    fetchImpl: serverFetchReportingUrl("https://svc.example.test/mcp"),
    clock: () => fixtureNow,
    windowSeconds: 30,
  });
  assert.deepEqual(await client.callTool("jack.whoami"), { ok: true });
  assert.equal(server.lastRequest?.target, "/mcp", "the fragment is never part of the signed target");
});

test("createSigningFetch accepts a fragmentless response url for a url with a fragment", async () => {
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResultBody('{"ok":true}'));
  const rows: readonly { readonly requested: string; readonly responseUrl: string; readonly target: string }[] = [
    { requested: "https://svc.example.test/mcp?q=1#frag", responseUrl: "https://svc.example.test/mcp?q=1", target: "/mcp?q=1" },
    { requested: "https://svc.example.test#frag", responseUrl: "https://svc.example.test/", target: "/" },
    { requested: "https://svc.example.test/mcp#", responseUrl: "https://svc.example.test/mcp", target: "/mcp" },
  ];
  for (const row of rows) {
    const sf = createSigningFetch(
      { aud: fixtureAud, signer: seedSignerByName("alice"), serverKey: server.pub, clock: () => fixtureNow, windowSeconds: 30 },
      serverFetchReportingUrl(row.responseUrl),
    );
    const resp = await sf(row.requested, { method: "POST", body: '{"ping":1}' });
    assert.equal(resp.status, 200, row.requested);
    assert.equal(server.lastRequest?.target, row.target, `${row.requested}: signed target`);
  }
});

test("a fragmentless response url that differs in path, query, origin or scheme is still refused", async () => {
  const rows: readonly { readonly name: string; readonly requested: string; readonly responseUrl: string }[] = [
    { name: "path", requested: "https://svc.example.test/mcp#frag", responseUrl: "https://svc.example.test/other" },
    { name: "query", requested: "https://svc.example.test/mcp?q=1#frag", responseUrl: "https://svc.example.test/mcp?q=2" },
    { name: "missing query", requested: "https://svc.example.test/mcp?q=1#frag", responseUrl: "https://svc.example.test/mcp" },
    { name: "origin", requested: "https://svc.example.test/mcp#frag", responseUrl: "https://other.example/mcp" },
    { name: "scheme", requested: "https://svc.example.test/mcp#frag", responseUrl: "http://svc.example.test/mcp" },
    { name: "path without fragment", requested: "https://svc.example.test/mcp", responseUrl: "https://svc.example.test/other" },
  ];
  for (const row of rows) {
    const tracked = trackedBody();
    const fetchImpl = async (): Promise<Response> => withUrl(new Response(tracked.body, { status: 200 }), row.responseUrl);
    const sf = createSigningFetch({ aud: fixtureAud, signer: seedSignerByName("alice"), serverKey: server.pub, clock: () => fixtureNow }, fetchImpl);
    await assert.rejects(sf(row.requested, { method: "POST", body: '{"ping":1}' }), RedirectRefusedError, row.name);
    assert.equal(tracked.cancelled(), true, `${row.name}: body must be cancelled`);
  }
});

/** Asserts err is a verification JackError (never a RedirectRefusedError) with the wanted code. */
function isVerificationError(code: string): (err: unknown) => boolean {
  return (err: unknown): boolean => err instanceof JackError && !(err instanceof RedirectRefusedError) && err.code === code;
}

// Only 301, 302, 303, 307 and 308 are redirect statuses. 304 Not Modified (and
// 300) are not: a correctly signed one is verified and returned as before.
test("a correctly signed 304 with an empty body is verified and returned", async () => {
  server.handle = (auth) => server.writeSignedJSON(auth, 304, new Uint8Array(0));
  const resp = await newServerTransport()("https://svc.example.test/mcp", { method: "POST", body: '{"ping":1}' });
  assert.equal(resp.status, 304);
  assert.equal(resp.body, null);
});

test("an unsigned 304 or 300 fails verification, not redirect refusal", async () => {
  const makers: readonly { readonly name: string; readonly make: () => Response }[] = [
    { name: "304", make: () => new Response(null, { status: 304 }) },
    { name: "300", make: () => new Response("x", { status: 300 }) },
  ];
  for (const m of makers) {
    const fetchImpl = async (): Promise<Response> => m.make();
    const sf = createSigningFetch({ aud: fixtureAud, signer: seedSignerByName("alice"), serverKey: server.pub, clock: () => fixtureNow }, fetchImpl);
    await assert.rejects(sf("https://svc.example.test/mcp", { method: "POST", body: '{"ping":1}' }), isVerificationError(Code.MISSING_AUTH), m.name);
  }
});

test("a 304 signed as another status or with a bad signature fails verification, not redirect refusal", async () => {
  // Signed as 200 but delivered as 304: the status is bound into the signature.
  server.handle = (auth) => {
    const signed = server.writeSignedJSON(auth, 200, new Uint8Array(0));
    return new Response(null, { status: 304, headers: signed.headers });
  };
  await assert.rejects(
    newServerTransport()("https://svc.example.test/mcp", { method: "POST", body: '{"ping":1}' }),
    isVerificationError(Code.BAD_SIGNATURE),
    "signed as 200, delivered as 304",
  );
  // A signature made over a different request signature (stale replay) must fail too.
  server.handle = (auth) => {
    const signed = server.writeSignedJSON({ ...auth, sig: auth.sig.slice(1) + "A" }, 304, new Uint8Array(0));
    return new Response(null, { status: 304, headers: signed.headers });
  };
  await assert.rejects(
    newServerTransport()("https://svc.example.test/mcp", { method: "POST", body: '{"ping":1}' }),
    isVerificationError(Code.BAD_SIGNATURE),
    "signed over another request signature",
  );
});
