// Shared constants and helpers of the modern (MCP 2026-07-28) interop
// executables: the fixed clock file, the contract's deterministic nonces and
// the fixture values both roles agree on (interop/modern/contract.md 2, 4, 5).
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { encodeBase64URL } from "../../core/encoding.js";
import type { JsonValue } from "../../core/json-raw.js";
import type { ClientInfo } from "../../modern/request.js";

/** The first modern-era protocol version; every modern request of the matrix advertises it. */
export const MODERN_VERSION = "2026-07-28";

/** The newest legacy-era protocol version: the fallback version of contract 4.3. */
export const LEGACY_VERSION = "2025-11-25";

/** The protocol versions this client implements, newest first, in the order the `-32022` retry rule falls back through. */
export const IMPLEMENTED_VERSIONS: readonly string[] = [MODERN_VERSION, LEGACY_VERSION, "2025-06-18"];

/** The client identity the contract pins for `_meta["io.modelcontextprotocol/clientInfo"]`. */
export const CLIENT_INFO: ClientInfo = { name: "mcp-jack-interop-modern-client", version: "1.0.0" };

/** The one endpoint the contract defines; `--url` is only the origin it lives on. */
export const TARGET_PATH = "/mcp";

/** The fixed `region.echo` definition of contract 3.4 (d), projected when a scenario calls the tool without reading `tools/list` first. */
export const REGION_ECHO_SCHEMA: JsonValue = {
  type: "object",
  properties: { region: { type: "string", "x-mcp-header": "Region" } },
  required: ["region"],
};

/** The message of a thrown value, for a one-line diagnostic. */
export function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Reads the fixed clock file: one decimal integer, the only source of "now" (contract section 2). Throws when it is unreadable or malformed. */
export function readClock(file: string): number {
  let text: string;
  try {
    text = readFileSync(file, "utf8").trim();
  } catch (err) {
    throw new Error(`cannot read clock file ${file}: ${message(err)}`);
  }
  if (!/^-?\d+$/.test(text)) throw new Error(`clock file ${file} does not hold a decimal integer`);
  const value = Number(text);
  if (!Number.isSafeInteger(value)) throw new Error(`clock file ${file} does not hold a safe integer`);
  return value;
}

/**
 * An injected clock: samples the clock file on EVERY call. A failed sample after
 * startup is fatal (contract section 2): "now" only ever comes from that file,
 * so the process reports one stderr line and exits 1 instead of running on
 * stale time. `label` is the executable name of that line.
 */
export function clockSource(file: string, label: string): () => number {
  return (): number => {
    try {
      return readClock(file);
    } catch (err) {
      process.stderr.write(`${label}: ${message(err)}\n`);
      process.exit(1);
      // Kept for the type only: the layout check compiles without @types/node,
      // where `process.exit` is untyped and cannot end the control flow.
      throw err;
    }
  };
}

/** The deterministic nonce of request `index` of `scenario`: the first 16 bytes of sha256(utf8("mcp-jack-interop-modern/nonce/" + scenario + "/" + index)) (contract section 2). */
export function nonceFor(scenario: string, index: number): Uint8Array {
  const digest = createHash("sha256").update(Buffer.from(`mcp-jack-interop-modern/nonce/${scenario}/${index}`, "utf8")).digest();
  return new Uint8Array(digest.subarray(0, 16));
}

/** Canonical unpadded base64url of bytes, the form every byte field of the result line uses. */
export function b64u(bytes: Uint8Array): string {
  return encodeBase64URL(bytes);
}

/** True for a JSON object: non-null and not an array. */
export function isJsonObject(value: JsonValue | undefined): value is { readonly [key: string]: JsonValue } {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** An own member of a JSON object, or undefined; a prototype member never counts. */
export function ownMember(value: JsonValue | undefined, key: string): JsonValue | undefined {
  return isJsonObject(value) && Object.hasOwn(value, key) ? value[key] : undefined;
}

/** The exact JSON text of a value; `JSON.stringify` of a parsed value is never undefined, the fallback only satisfies the type. */
export function jsonText(value: JsonValue): string {
  return JSON.stringify(value) ?? "null";
}
