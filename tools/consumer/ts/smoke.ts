import assert from "node:assert/strict";
import { createServer } from "node:http";
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
  keyId,
  parsePolicy,
  serveNode,
  validateUserKeyCredentialForServer,
  verify,
} from "mcp-jack";
import type { ExpectedServerIdentity, RegistryEntry } from "mcp-jack";

const AUDIENCE = "https://consumer.example.test";
const NOW = 1_800_000_000;
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
      scopes: [],
    };
    state.update((edit) => edit.putKey(entry));
  };
  addRegistryEntry(importedServerIdentity, "envelope-client");

  const verifier = new Verifier({
    aud: AUDIENCE,
    state,
    nonces: new NonceStore(),
    policy: parsePolicy(JSON.stringify({ version: 1, rules: [{ match: { method: "tools/call", tool: "consumer.echo" }, scope: null }] })),
    now: () => NOW,
  });
  const handler = serveNode(
    jackFetchHandler(
      { verifier, serverKey: serviceKey.handoff.exportSeed() },
      async (request) => {
        const rpc = (await request.json()) as { id?: unknown };
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
  console.error("TS consumer smoke failed");
  process.exitCode = 1;
});
