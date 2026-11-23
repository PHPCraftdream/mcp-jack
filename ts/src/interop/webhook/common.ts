import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";
import { checkServerIdentity, createSecureContext } from "node:tls";
import type { PeerCertificate } from "node:tls";
import { checkDelivery, HardenedTransport } from "../../webhook/index.js";
import type { HardenedDialTarget, HardenedDialer, HardenedRequest, HardenedResponse, WebhookResolver } from "../../webhook/index.js";

export type Flags = Record<string, string | string[] | boolean | undefined>;
export const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

export class UsageError extends Error {}
export function parse(argv: string[], repeat: readonly string[], booleans: readonly string[], defaults: Flags = {}): Flags {
  const out: Flags = { ...defaults };
  const seen = new Set<string>();
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i]!;
    if (!flag.startsWith("--")) throw new UsageError(`unexpected argument: ${flag}`);
    const key = flag.slice(2).replace(/-([a-z])/g, (_m, c: string) => c.toUpperCase());
    if (booleans.includes(flag)) { if (seen.has(key)) throw new UsageError(`duplicate flag: ${flag}`); seen.add(key); out[key] = true; continue; }
    const value = argv[++i];
    if (value === undefined || value.startsWith("--")) throw new UsageError(`missing value for ${flag}`);
    if (repeat.includes(flag)) out[key] = [...(Array.isArray(out[key]) ? out[key] as string[] : []), value];
    else if (seen.has(key)) throw new UsageError(`duplicate flag: ${flag}`);
    else { seen.add(key); out[key] = value; }
  }
  return out;
}
export function str(flags: Flags, key: string, required = true): string {
  const value = flags[key];
  if (typeof value === "string" && value !== "") return value;
  if (!required) return "";
  throw new UsageError(`missing --${key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`);
}
export function list(flags: Flags, key: string): string[] { return Array.isArray(flags[key]) ? flags[key] as string[] : []; }
export function readClock(file: string): number {
  const text = readFileSync(file, "utf8").trim();
  if (!/^-?[0-9]+$/.test(text)) throw new Error("the clock file does not hold a decimal integer");
  const n = Number(text); if (!Number.isSafeInteger(n)) throw new Error("invalid clock value"); return n;
}
export function clockWrite(file: string, value: number): void { writeFileSync(file, `${value}\n`); }
export function sha(bytes: Uint8Array): Uint8Array { return createHash("sha256").update(bytes).digest(); }
export function derivedId(scenario: string, index: number, kind: string): string {
  const suffix = Array.from(sha(Buffer.from(`mcp-jack-interop-webhook/id/${scenario}/${index}`, "utf8")), (b) => ALPHABET[b % 62]).join("");
  const prefix = kind === "gap" || kind === "terminated" ? `msg_${kind}_` : "msg_";
  return prefix + suffix;
}
export function seed(text: string): Uint8Array { return sha(Buffer.from(text, "utf8")); }
export function seedHex(value: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) throw new Error("seed must be 64 hexadecimal characters");
  return Buffer.from(value, "hex");
}
export function resolverFor(file?: string): WebhookResolver {
  if (!file) return { async resolve(host) { const { lookup } = await import("node:dns/promises"); return (await lookup(host, { all: true })).map((x) => x.address); } };
  const data: unknown = JSON.parse(readFileSync(file, "utf8"));
  if (data === null || typeof data !== "object" || Array.isArray(data)) throw new Error("resolver file must be an object");
  return { async resolve(host) {
    const answers = (data as Record<string, unknown>)[host];
    if (!Array.isArray(answers) || answers.length === 0 || answers.some((x) => typeof x !== "string")) throw new Error("ENOTFOUND");
    return answers as string[];
  } };
}
export function caDialer(caFile?: string): HardenedDialer {
  const ca = caFile ? readFileSync(caFile) : undefined;
  if (ca !== undefined) createSecureContext({ ca });
  return (target: HardenedDialTarget, request: HardenedRequest) => new Promise<HardenedResponse>((resolve, reject) => {
    const headers = { ...request.headers, host: target.hostHeader, "content-length": String(request.body?.byteLength ?? 0), connection: "close" };
    let responseTimer: ReturnType<typeof setTimeout> | undefined;
    let connectTimer: ReturnType<typeof setTimeout> | undefined;
    let req!: ReturnType<typeof httpsRequest>;
    const timeout = () => req.destroy(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" }));
    const options = { host: target.address, port: target.port, family: target.ipv6 ? 6 : 4,
      ...(target.sni ? { servername: target.sni } : {}), checkServerIdentity: (_host: string, cert: PeerCertificate) => checkServerIdentity(target.sni ?? target.address, cert),
      ...(ca === undefined ? {} : { ca }), method: request.method, path: request.path, headers, agent: false, rejectUnauthorized: true };
    req = httpsRequest(options, (res) => {
      clearTimeout(connectTimer);
      const chunks: Buffer[] = []; let size = 0;
      res.on("data", (chunk: Buffer) => { size += chunk.length; if (size > (request.maxResponseBytes ?? 262144)) { req.destroy(); resolve({ status: 413, headers: {}, body: new Uint8Array() }); } else chunks.push(chunk); });
      res.on("end", () => { clearTimeout(responseTimer); const out: Record<string, string> = {}; for (const [k, v] of Object.entries(res.headers)) if (typeof v === "string") out[k] = v; else if (Array.isArray(v)) out[k] = v.join(", "); resolve({ status: res.statusCode ?? 0, headers: out, body: Buffer.concat(chunks) }); });
      res.on("error", reject);
    });
    connectTimer = setTimeout(timeout, request.connectTimeoutMs ?? 10000);
    const attemptTimer = setTimeout(timeout, 20000);
    req.once("finish", () => { responseTimer = setTimeout(timeout, request.responseTimeoutMs ?? 10000); });
    req.once("socket", (socket) => socket.once("secureConnect", () => clearTimeout(connectTimer)));
    req.once("close", () => { clearTimeout(connectTimer); clearTimeout(responseTimer); clearTimeout(attemptTimer); });
    req.once("error", reject);
    if (request.body) req.end(request.body); else req.end();
  });
}
export function transport(flags: Flags): HardenedTransport {
  return new HardenedTransport({ resolver: resolverFor(typeof flags.resolverFile === "string" ? flags.resolverFile : undefined),
    dialer: caDialer(typeof flags.tlsCa === "string" ? flags.tlsCa : typeof flags.tlsCaDer === "string" ? flags.tlsCaDer : undefined), allowedRanges: list(flags, "allowedRange") });
}
export function preflight(url: string, flags: Flags): string | null {
  try {
    const hostname = new URL(url).hostname;
    let answers: readonly string[] = [];
    if (/^[0-9.]+$/.test(hostname) || hostname.includes(":")) answers = [hostname];
    else if (typeof flags.resolverFile === "string") {
      const data = JSON.parse(readFileSync(flags.resolverFile, "utf8")) as Record<string, unknown>;
      const value = data[hostname]; if (!Array.isArray(value)) return "connection_refused"; answers = value as string[];
    } else return null;
    const decision = checkDelivery({ url, answers, allowedRanges: list(flags, "allowedRange") });
    return decision.decision === "allow" ? null : decision.code === "blocked_address" ? "ssrf_blocked_address" : decision.code === "dns_rebinding" ? "ssrf_rebinding_blocked" : "connection_refused";
  } catch { return "connection_refused"; }
}
export function output(value: unknown): void { process.stdout.write(`${JSON.stringify(value)}\n`); }
export function fatal(error: unknown): never { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exit(error instanceof UsageError ? 2 : 1); }
