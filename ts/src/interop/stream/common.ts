import { readFileSync } from "node:fs";
import { encodeBase64URL } from "../../core/encoding.js";

export type Flags = Record<string, string>;
export function parseFlags(argv: readonly string[]): Flags {
  const out: Flags = {};
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i]!;
    if (!flag.startsWith("--") || argv[i + 1] === undefined || argv[i + 1]!.startsWith("--")) throw new Error(`invalid flag ${flag}`);
    const key = flag.slice(2);
    if (Object.hasOwn(out, key)) throw new Error(`duplicate flag ${flag}`);
    out[key] = argv[++i]!;
  }
  return out;
}
export function need(f: Flags, key: string): string { const v = f[key]; if (v === undefined || v === "") throw new Error(`missing --${key}`); return v; }
export function integer(f: Flags, key: string, fallback?: number): number {
  const raw = f[key]; if (raw === undefined && fallback !== undefined) return fallback;
  if (!raw || !/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error(`invalid --${key}`);
  const n = Number(raw); if (!Number.isSafeInteger(n)) throw new Error(`invalid --${key}`); return n;
}
export function clockFile(file: string): () => number {
  return () => { const text = readFileSync(file, "utf8").trim(); if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error("invalid clock file"); const n = Number(text); if (!Number.isSafeInteger(n)) throw new Error("invalid clock file"); return n; };
}
export const b64 = (v: Uint8Array): string => encodeBase64URL(v);
export const scenarios = JSON.parse(readFileSync(new URL("../../../../interop/stream-scenarios.json", import.meta.url), "utf8")).matrices.stream as Array<Record<string, any>>;
export function scenario(id: string): Record<string, any> { const row = scenarios.find(x => x.id === id); if (!row) throw new Error(`unknown active stream scenario ${id}`); return row; }
export function jsonl(v: unknown): void { process.stdout.write(`${JSON.stringify(v)}\n`); }
export function diagnostic(err: unknown): void { process.stderr.write(`${err instanceof Error ? err.stack ?? err.message : String(err)}\n`); }
