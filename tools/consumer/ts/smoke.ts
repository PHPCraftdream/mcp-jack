import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import {
  Code,
  JackError,
  MemoryState,
  NonceStore,
  ServerUserKey,
  Verifier,
  client,
  encodeBase64URL,
  exportUserKeyPublicEnvelope,
  generateClientUserKey,
  importClientUserKeyCredential,
  importServerUserKeyPublicEnvelope,
  issueUserKey,
  issueUserKeyCredential,
  jackFetchHandler,
  jackIdentity,
  keyId,
  parseRequestAuth,
  rotation,
  serveNode,
  validateUserKeyCredentialForServer,
  verify,
} from "mcp-jack";
import type { ExpectedServerIdentity, RegistryEntry } from "mcp-jack";

const AUDIENCE = "https://consumer.example.test";
const NOW = 1_800_000_000;
let consumerPhase: "static-client" | "candidate-store" | "candidate-http" | "candidate-reopen" = "static-client";
const utf8 = (value: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(value);
const boundedFetch: typeof fetch = (input, init) => fetch(input, { ...init, signal: AbortSignal.timeout(5000) });

async function listen(server: ReturnType<typeof createServer>): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address !== null && typeof address !== "string", "loopback server bound to a TCP address");
  return `http://127.0.0.1:${(address as AddressInfo).port}/mcp`;
}

async function close(server: ReturnType<typeof createServer>): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections();
  });
}

async function rotationConsumer(baseUrl: string, signer: client.Signer, trusted: ExpectedServerIdentity): Promise<void> {
  consumerPhase = "candidate-store";
  assert.equal(process.platform, "linux", "candidate store consumer qualification requires Linux");
  client.checkDestination(baseUrl);
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mcp-jack-rotation-consumer-")));
  chmodSync(root, 0o700);
  const stateFile = join(root, "trust");
  const options: rotation.RotationStoreOptions = {
    binding: { endpoint: baseUrl, aud: trusted.aud }, window: 30,
    checkpoint: { ordinal: 0, hash: "-", kid: trusted.server_kid,
      publicKeyB64u: trusted.server_public_key, publishedAt: 0 }, now: () => NOW,
  };
  let owner: rotation.RotationTrustStore | undefined;
  try {
    rotation.RotationTrustStore.initializeUnused(stateFile, options);
    assert.equal(existsSync(stateFile), true, "installed store creates concrete state");
    assert.equal(existsSync(stateFile + ".owner"), false, "explicit initialization settles cleanly");
    owner = rotation.RotationTrustStore.open(stateFile, options);
    assert.equal(existsSync(stateFile + ".owner"), true, "installed store holds its owner gate");
    const controller = new rotation.RotationController(owner);
    consumerPhase = "candidate-http";
    const body = utf8(JSON.stringify({ jsonrpc: "2.0", id: "candidate-consumer", method: "tools/call",
      params: { name: "consumer.echo", arguments: {} } }));
    const target = new URL(baseUrl);
    const header = client.signRequest(signer, trusted.aud, "POST", target.pathname + target.search, body, client.randomNonce(), NOW);
    const requestSignature = parseRequestAuth([header]).sig;
    const received = await boundedFetch(baseUrl, { method: "POST", redirect: "error",
      headers: { "Jack-Auth": header, "Content-Type": "application/json" }, body });
    const auth = received.headers.get("jack-auth");
    assert.ok(auth, "installed controller receives an actual response signature");
    const reply: rotation.RotationResponse = { status: received.status, headers: [auth], requestSignature,
      body: new Uint8Array(await received.arrayBuffer()) };
    assert.ok(reply.body.length <= 1024 * 1024, "controlled consumer response stays within the candidate cap");
    const verified = controller.verifyResponse(reply);
    const rpc = JSON.parse(new TextDecoder().decode(verified)) as { result?: { structuredContent?: { echoed?: boolean } } };
    assert.equal(rpc.result?.structuredContent?.echoed, true, "installed candidate controller authenticates the real server reply");
    const changed = new Uint8Array(reply.body);
    changed[0] = (changed[0] ?? 0) ^ 1;
    assert.throws(() => controller.verifyResponse({ ...reply, body: changed }),
      (error: unknown) => error instanceof JackError && error.httpStatus === 0 && error.code === Code.BAD_SIGNATURE,
      "installed candidate controller rejects tampered bytes");
    assert.equal(owner.snapshot().snapshot.revision, 1, "ordinary response never adopts rotation data");
    consumerPhase = "candidate-reopen";
    owner.close();
    assert.equal(existsSync(stateFile + ".owner"), false, "clean close releases only the settled owner");
    owner = rotation.RotationTrustStore.open(stateFile, options);
    const restored = new rotation.RotationController(owner);
    assert.deepEqual(Buffer.from(restored.verifyResponse(reply)), Buffer.from(reply.body), "clean reopen retains the independently provisioned trust bytes");
    assert.deepEqual(owner.snapshot().snapshot.head, { ordinal: 0, hash: "-" });
  } finally {
    try { owner?.close(); }
    finally { rmSync(root, { recursive: true, force: true }); }
  }
}

async function main(): Promise<void> {
  // Generate a client key in the OS-backed SDK API, export/import only its public identity.
  const generatedClientKey = generateClientUserKey();
  const signatureMessage = utf8("consumer generated-key signature check");
  const generatedSignature = generatedClientKey.sign(signatureMessage);
  assert.equal(verify(generatedClientKey.publicKey(), signatureMessage, generatedSignature), true, "root verification API accepts the generated-key signature");
  assert.equal(verify(generatedClientKey.publicKey(), utf8("different message"), generatedSignature), false, "root verification API rejects a changed message");
  const tamperedSignature = new Uint8Array(generatedSignature);
  tamperedSignature[0] = (tamperedSignature[0] ?? 0) ^ 1;
  assert.equal(verify(generatedClientKey.publicKey(), signatureMessage, tamperedSignature), false, "root verification API rejects a changed signature");
  assert.equal(verify(generatedClientKey.publicKey(), signatureMessage, generatedSignature.subarray(0, 63)), false, "root verification API rejects a truncated signature");
  const publicEnvelope = exportUserKeyPublicEnvelope(generatedClientKey);
  const importedServerIdentity = importServerUserKeyPublicEnvelope(publicEnvelope);
  assert.ok(importedServerIdentity instanceof ServerUserKey, "public envelope imports as a server-side public identity");
  assert.equal(importedServerIdentity.kid(), generatedClientKey.kid(), "public identity remains bound to the generated client key");

  // Independently issued server key signs the loopback reply; private seed remains local and unlogged.
  const serviceKey = issueUserKey();
  const state = new MemoryState();
  const addRegistryEntry = (key: ServerUserKey, name: string): void => {
    const entry: RegistryEntry = {
      kid: key.kid(),
      publicKey: encodeBase64URL(key.publicKey()),
      name,
    };
    state.update((edit) => edit.putKey(entry));
  };
  addRegistryEntry(importedServerIdentity, "envelope-client");

  let expectedClientKid: string | undefined;
  const verifier = new Verifier({
    aud: AUDIENCE,
    state,
    nonces: new NonceStore(),
    now: () => NOW,
  });
  const handler = serveNode(
    jackFetchHandler(
      { verifier, serverKey: serviceKey.handoff.exportSeed() },
      async (request) => {
        const identity = jackIdentity(request);
        assert.ok(identity !== undefined, "wrapped handler receives the verified caller identity");
        assert.ok(expectedClientKid !== undefined, "credential identity is imported before requests are handled");
        assert.ok(Object.isFrozen(identity), "verified caller identity is immutable");
        assert.strictEqual(jackIdentity(request), identity, "identity reads return the same immutable snapshot");
        assert.deepEqual(
          identity,
          { kid: expectedClientKid, name: "credential-client", admin: false },
          "wrapped handler receives the exact verified non-admin registry identity",
        );
        const rpc = (await request.json()) as { id?: unknown; params?: { name?: unknown } };
        if (rpc.params?.name === "consumer.admin.only" && !identity.admin) {
          return new Response(JSON.stringify({ error: { code: "app_denied", message: "application policy denied" } }), {
            status: 403,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: rpc.id ?? null, result: { structuredContent: { echoed: true } } }), {
          headers: { "content-type": "application/json" },
        });
      },
    ),
  );
  const server = createServer(handler);

  try {
    const baseUrl = await listen(server);
    // This trusted tuple is constructed independently from the locally held server identity.
    const trustedServer: ExpectedServerIdentity = {
      url: baseUrl,
      aud: AUDIENCE,
      server_public_key: encodeBase64URL(serviceKey.server.publicKey()),
      server_kid: serviceKey.server.kid(),
    };
    assert.equal(trustedServer.server_kid, keyId(serviceKey.server.publicKey()), "trusted server tuple has the independently computed key id");

    const issuedCredential = issueUserKeyCredential(trustedServer);
    const credentialBytes = issuedCredential.exportCredential();
    validateUserKeyCredentialForServer(credentialBytes, trustedServer);
    const wrongCredentialPin: ExpectedServerIdentity = {
      url: trustedServer.url,
      aud: trustedServer.aud,
      server_public_key: encodeBase64URL(generatedClientKey.publicKey()),
      server_kid: generatedClientKey.kid(),
    };
    assert.throws(
      () => importClientUserKeyCredential(credentialBytes, wrongCredentialPin),
      (error: unknown) => error instanceof JackError && error.code === "server_identity_mismatch",
      "credential import refuses a mismatched independently trusted server tuple",
    );
    const importedClient = importClientUserKeyCredential(credentialBytes, trustedServer);
    expectedClientKid = importedClient.signer.kid();
    assert.equal(importedClient.connection.server_kid, trustedServer.server_kid, "client credential is pinned to the trusted service identity");
    addRegistryEntry(issuedCredential.publicIdentity(), "credential-client");

    const workingClient = new client.Client({
      baseUrl,
      aud: AUDIENCE,
      signer: importedClient.signer,
      serverKey: importedClient.connection.serverKey,
      clock: () => NOW,
      fetchImpl: boundedFetch,
    });
    assert.deepEqual(await workingClient.callTool("consumer.echo"), { echoed: true }, "client verifies the signed loopback response");
    let applicationDenialVerified = false;
    try {
      await workingClient.callTool("consumer.admin.only");
    } catch (error) {
      applicationDenialVerified = error instanceof client.HTTPError && error.status === 403 && error.code === "app_denied";
    }
    assert.equal(applicationDenialVerified, true, "the wrapped application denies its own tool for the verified non-admin caller");
    await rotationConsumer(baseUrl, importedClient.signer, trustedServer);
    consumerPhase = "static-client";

    const wrongPinClient = new client.Client({
      baseUrl,
      aud: AUDIENCE,
      signer: importedClient.signer,
      serverKey: generatedClientKey.publicKey(),
      clock: () => NOW,
      fetchImpl: boundedFetch,
    });
    let wrongPinRejected = false;
    try {
      await wrongPinClient.callTool("consumer.echo");
    } catch (error) {
      wrongPinRejected = error instanceof JackError && error.code === Code.UNKNOWN_SERVER_KEY;
    }
    assert.ok(wrongPinRejected, "client rejects a response signed by a server other than its pin");

    const tamperingFetch: typeof fetch = async (input, init) => {
      if (!(init?.body instanceof Uint8Array)) throw new Error("tamper input unavailable");
      const original = new TextDecoder().decode(init.body);
      const tampered = original.replace('"consumer.echo"', '"consumer.fcho"');
      if (tampered === original) throw new Error("tamper target unavailable");
      return fetch(input, { ...init, signal: AbortSignal.timeout(5000), body: utf8(tampered) });
    };
    const tamperedClient = new client.Client({
      baseUrl,
      aud: AUDIENCE,
      signer: importedClient.signer,
      serverKey: importedClient.connection.serverKey,
      clock: () => NOW,
      fetchImpl: tamperingFetch,
    });
    let tamperedMessageRejected = false;
    try {
      await tamperedClient.callTool("consumer.echo");
    } catch (error) {
      tamperedMessageRejected = error instanceof client.UnauthenticatedResponseError;
    }
    assert.ok(tamperedMessageRejected, "server rejects a request whose message changed after signing");
  } finally {
    await close(server);
  }
}

main().catch(() => {
  // Static failure label only: never print credentials, seeds, key objects, or exception material.
  console.error("TS consumer smoke failed:", consumerPhase);
  process.exitCode = 1;
});
