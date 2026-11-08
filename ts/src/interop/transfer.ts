import { stdin, stderr, stdout } from "node:process";
import {
  ClientUserKey,
  JackError,
  decodeBase64URL,
  decodeBase64URLFixed,
  encodeBase64URL,
  exportUserKeyPublicEnvelope,
  generateClientUserKey,
  importClientUserKeyCredential,
  importClientUserKeyPrivateEnvelope,
  importServerUserKeyPublicEnvelope,
  importUserKeyPublicEnvelope,
  issueUserKeyCredential,
  validateUserKeyCredentialForServer,
  verify,
} from "../index.js";
import type { ExpectedServerIdentity } from "../index.js";
import type { Signer } from "../client/index.js";

const MAX_IPC_BYTES = 2 * 1024 * 1024;
const MAX_OPERATIONS = 1024;
const MAX_MESSAGES = 16;
const MAX_MESSAGE_BYTES = 4096;
const TRANSFER_CLASSES = new Set([
  "malformed_json", "wrong_root_type", "oversized_envelope", "unknown_version", "unknown_type",
  "bad_member_set", "wrong_field_type", "bad_encoding", "bad_url", "invalid_public_key",
  "seed_pub_mismatch", "kid_mismatch", "non_canonical_bytes", "wrong_envelope_type",
  "private_material_rejected", "not_private", "server_identity_mismatch",
]);

type JsonRecord = Record<string, unknown>;
type Result = Record<string, unknown>;

function protocolFailure(): never {
  throw new Error("protocol failure");
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function fields(value: JsonRecord, allowed: readonly string[]): void {
  if (Object.keys(value).some((name) => !allowed.includes(name))) protocolFailure();
}

function requiredString(value: JsonRecord, name: string): string {
  const field = value[name];
  if (typeof field !== "string") protocolFailure();
  return field;
}

function bytes(value: string): Uint8Array {
  return decodeBase64URL(value);
}

function transferClass(error: unknown): string | undefined {
  if (error instanceof JackError && TRANSFER_CLASSES.has(error.code)) return error.code;
  if (error instanceof Error && error.name === "JackError" && "code" in error) {
    const code = (error as Error & { code?: unknown }).code;
    if (typeof code === "string" && TRANSFER_CLASSES.has(code)) return code;
  }
  return undefined;
}

function errorResult(id: unknown, error: unknown): Result {
  const classification = transferClass(error);
  if (classification !== undefined) return { id, ok: false, class: classification };
  protocolFailure();
}

function parseMessages(value: JsonRecord): Uint8Array[] {
  const encoded = value["messages_b64u"];
  if (!Array.isArray(encoded) || encoded.length > MAX_MESSAGES) protocolFailure();
  return encoded.map((item: unknown) => {
    if (typeof item !== "string") protocolFailure();
    const message = bytes(item);
    if (message.length > MAX_MESSAGE_BYTES) protocolFailure();
    return message;
  });
}

function signerResult(id: unknown, signer: Signer, messages: Uint8Array[], connection?: {
  url: string;
  aud: string;
  server_public_key: string;
  server_kid: string;
}): Result {
  for (const name of ["exportSeed", "exportPrivateEnvelope", "secret", "seed", "privateKey"]) {
    if (name in signer) protocolFailure();
  }
  const publicKey = signer.publicKey();
  const envelope = exportUserKeyPublicEnvelope(signer);
  const signatures = messages.map((message) => encodeBase64URL(signer.sign(message)));
  const result: Result = {
    id,
    ok: true,
    public_key: encodeBase64URL(publicKey),
    kid: signer.kid(),
    public_envelope_b64u: encodeBase64URL(envelope),
    signatures_b64u: signatures,
  };
  if (connection !== undefined) result["connection"] = connection;
  return result;
}

function expectedValue(value: JsonRecord): ExpectedServerIdentity {
  // The SDK deliberately receives absent/null/incomplete tuples unchanged so
  // document validation retains precedence over expected-identity refusal.
  return value["expected"] as ExpectedServerIdentity;
}

function runOperation(input: unknown): Result {
  if (!isRecord(input)) protocolFailure();
  const id = input["id"];
  if (!("id" in input)) protocolFailure();
  const name = requiredString(input, "op");
  let allowed: readonly string[];
  switch (name) {
    case "issue": allowed = ["id", "op", "seed_b64u", "expected"]; break;
    case "generate":
    case "from-seed": allowed = ["id", "op", "seed_b64u", "messages_b64u"]; break;
    case "import-private": allowed = ["id", "op", "document_b64u", "messages_b64u"]; break;
    case "import-credential": allowed = ["id", "op", "document_b64u", "expected", "messages_b64u"]; break;
    case "import-public": allowed = ["id", "op", "document_b64u", "role", "verifications"]; break;
    case "validate-credential": allowed = ["id", "op", "document_b64u", "expected"]; break;
    default: protocolFailure();
  }
  fields(input, allowed);

  try {
    switch (name) {
      case "issue": {
        const seed = decodeBase64URLFixed(requiredString(input, "seed_b64u"), 32);
        const expected = expectedValue(input);
        const issued = issueUserKeyCredential(expected, (length) => {
          if (length !== seed.length) throw new Error("invalid random request");
          return new Uint8Array(seed);
        });
        const first = issued.exportCredential();
        const original = new Uint8Array(first);
        const second = issued.exportCredential();
        const publicBefore = issued.publicIdentity().publicKey();
        const kidBefore = issued.publicIdentity().kid();
        const imported = importClientUserKeyCredential(original, expected);
        const signer = imported.signer;
        const signature = signer.sign(new Uint8Array());
        const originalPublicKey = new Uint8Array(signer.publicKey());
        first.fill(0);
        const third = issued.exportCredential();
        const fresh = first.length > 0 && first !== second && second !== third &&
          original.length === second.length && original.every((byte, index) => byte === second[index]) &&
          original.every((byte, index) => byte === third[index]) &&
          encodeBase64URL(signer.publicKey()) === encodeBase64URL(publicBefore) &&
          encodeBase64URL(signer.sign(new Uint8Array())) === encodeBase64URL(signature) &&
          encodeBase64URL(signer.publicKey()) === encodeBase64URL(originalPublicKey) &&
          signer.kid() === kidBefore &&
          issued.publicIdentity().kid() === kidBefore &&
          publicBefore.every((byte, index) => byte === issued.publicIdentity().publicKey()[index]);
        if (!fresh) protocolFailure();
        return {
          id, ok: true, credential_b64u: encodeBase64URL(third),
          public_key: encodeBase64URL(publicBefore), kid: kidBefore, export_fresh: fresh,
        };
      }
      case "generate":
        return signerResult(id, generateClientUserKey(), parseMessages(input));
      case "from-seed": {
        const seed = decodeBase64URLFixed(requiredString(input, "seed_b64u"), 32);
        return signerResult(id, new ClientUserKey(seed), parseMessages(input));
      }
      case "import-private": {
        const document = bytes(requiredString(input, "document_b64u"));
        return signerResult(id, importClientUserKeyPrivateEnvelope(document), parseMessages(input));
      }
      case "import-credential": {
        const document = bytes(requiredString(input, "document_b64u"));
        const before = new Uint8Array(document);
        const expected = expectedValue(input);
        const beforeExpected = JSON.stringify(expected);
        let imported: ReturnType<typeof importClientUserKeyCredential>;
        try {
          imported = importClientUserKeyCredential(document, expected);
        } finally {
          if (!document.every((byte, index) => byte === before[index]) || JSON.stringify(expected) !== beforeExpected) {
            protocolFailure();
          }
        }
        const returned = imported.connection;
        const returnedConfig = {
          url: returned.url,
          aud: returned.aud,
          server_public_key: returned.server_public_key,
          server_kid: returned.server_kid,
        };
        return signerResult(id, imported.signer, parseMessages(input), returnedConfig);
      }
      case "import-public": {
        const document = bytes(requiredString(input, "document_b64u"));
        const role = requiredString(input, "role");
        if (role !== "client" && role !== "server") protocolFailure();
        const rawVerifications = input["verifications"];
        if (rawVerifications !== undefined && !Array.isArray(rawVerifications)) protocolFailure();
        const verifications = rawVerifications === undefined ? [] : rawVerifications as unknown[];
        if (verifications.length > MAX_MESSAGES) protocolFailure();
        const pairs = verifications.map((entry) => {
          if (!isRecord(entry)) protocolFailure();
          fields(entry, ["message_b64u", "signature_b64u"]);
          const message = bytes(requiredString(entry, "message_b64u"));
          const signature = bytes(requiredString(entry, "signature_b64u"));
          if (message.length > MAX_MESSAGE_BYTES || signature.length > MAX_MESSAGE_BYTES) protocolFailure();
          return { message, signature };
        });
        let publicKey: Uint8Array;
        let kid: string;
        let verifyPair: (message: Uint8Array, signature: Uint8Array) => boolean;
        if (role === "client") {
          const identity = importUserKeyPublicEnvelope(document);
          const probe = identity as unknown as JsonRecord;
          for (const member of ["sign", "Sign", "seed", "exportSeed", "exportCredential", "privateKey", "exportPrivateEnvelope", "credential"]) {
            if (member in probe) protocolFailure();
          }
          publicKey = identity.pub32;
          kid = identity.kid;
          verifyPair = (message, signature) => verify(publicKey, message, signature);
        } else {
          const identity = importServerUserKeyPublicEnvelope(document);
          const probe = identity as unknown as JsonRecord;
          for (const member of ["sign", "Sign", "seed", "exportSeed", "exportCredential", "privateKey", "exportPrivateEnvelope", "credential"]) {
            if (member in probe) protocolFailure();
          }
          publicKey = identity.publicKey();
          kid = identity.kid();
          const privateSurface = identity as unknown as { sign?: unknown; seed?: unknown; exportSeed?: unknown; exportCredential?: unknown; exportPrivateEnvelope?: unknown; credential?: unknown; privateKey?: unknown };
          if (privateSurface.sign !== undefined || privateSurface.seed !== undefined || privateSurface.exportSeed !== undefined || privateSurface.exportCredential !== undefined || privateSurface.exportPrivateEnvelope !== undefined || privateSurface.credential !== undefined || privateSurface.privateKey !== undefined) protocolFailure();
          verifyPair = (message, signature) => verify(publicKey, message, signature);
        }
        return {
          id, ok: true, public_key: encodeBase64URL(publicKey), kid,
          public_only: true,
          verification_results: pairs.map(({ message, signature }) => verifyPair(message, signature)),
        };
      }
      case "validate-credential": {
        const document = bytes(requiredString(input, "document_b64u"));
        validateUserKeyCredentialForServer(document, expectedValue(input));
        return { id, ok: true };
      }
    }
  } catch (error) {
    return errorResult(id, error);
  }
  return protocolFailure();
}

async function readInput(): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of stdin) {
    const part = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    length += part.length;
    if (length > MAX_IPC_BYTES) protocolFailure();
    chunks.push(part);
  }
  return Buffer.concat(chunks, length);
}

async function main(): Promise<void> {
  let request: unknown;
  try {
    request = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readInput())) as unknown;
  } catch {
    protocolFailure();
  }
  if (!isRecord(request)) protocolFailure();
  fields(request, ["operations"]);
  if (!Array.isArray(request["operations"]) || request["operations"].length > MAX_OPERATIONS) protocolFailure();
  const results = request["operations"].map(runOperation);
  const output = Buffer.from(`${JSON.stringify({ results })}\n`, "utf8");
  if (output.length > MAX_IPC_BYTES) protocolFailure();
  stdout.write(output);
}

main().catch(() => {
  stderr.write("interop-transfer: invalid request or SDK failure\n");
  process.exitCode = 1;
});
