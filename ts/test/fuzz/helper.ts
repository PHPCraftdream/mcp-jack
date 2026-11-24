import { readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "../support/fixtures/decode-base.js";

export const DEFAULT_SEED = 0x192;
export const DEFAULT_ITERATIONS = 20_000;

export function settings(): { seed: number; iterations: number } {
  const seedText = process.env.MCP_JACK_FUZZ_SEED;
  const iterText = process.env.MCP_JACK_FUZZ_ITERATIONS;
  const seed = seedText === undefined ? DEFAULT_SEED : Number(seedText);
  const iterations = iterText === undefined ? DEFAULT_ITERATIONS : Number(iterText);
  if (!Number.isSafeInteger(seed) || !Number.isSafeInteger(iterations) || iterations < 1) throw new Error("invalid fuzz environment");
  return { seed: seed >>> 0, iterations };
}

export function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}

export function corpus(name: string): unknown {
  return JSON.parse(readFileSync(join(repoRoot(), "ts", "test", "fuzz", name), "utf8")) as unknown;
}

export function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function context(seed: number, iteration: number, input: unknown, bytes?: Uint8Array): string {
  const wire = bytes ?? new TextEncoder().encode(typeof input === "string" ? input : JSON.stringify(input));
  return `seed=${seed} iteration=${iteration} input_hex=${hex(wire)} input_json=${JSON.stringify(input)}`;
}

export function runProperty(seed: number, iteration: number, input: unknown, fn: () => void, bytes?: Uint8Array): void {
  try {
    fn();
  } catch (error) {
    throw new Error(`${context(seed, iteration, input, bytes)}: ${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}`, { cause: error });
  }
}

export async function runAsyncProperty(seed: number, iteration: number, input: unknown, fn: () => Promise<void>, bytes?: Uint8Array): Promise<void> {
  try {
    await fn();
  } catch (error) {
    throw new Error(`${context(seed, iteration, input, bytes)}: ${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}`, { cause: error });
  }
}

export function mutateBytes(source: Uint8Array, next: () => number): Uint8Array {
  const bytes = source.slice();
  const operation = Math.floor(next() * 6);
  if (operation === 0 && bytes.length > 0) bytes[Math.floor(next() * bytes.length)]! ^= 1 << Math.floor(next() * 8);
  else if (operation === 1) {
    const at = Math.floor(next() * (bytes.length + 1));
    const out = new Uint8Array(bytes.length + 1); out.set(bytes.subarray(0, at)); out[at] = Math.floor(next() * 256); out.set(bytes.subarray(at), at + 1); return out;
  } else if (operation === 2 && bytes.length > 0) {
    const at = Math.floor(next() * bytes.length); return Uint8Array.from([...bytes.subarray(0, at), ...bytes.subarray(at + 1)]);
  } else if (operation === 3) return bytes.subarray(0, Math.floor(next() * (bytes.length + 1))).slice();
  else if (operation === 4) return Uint8Array.from([...bytes, ...bytes]);
  else if (operation === 5 && bytes.length > 1) {
    const cut = Math.floor(next() * bytes.length);
    return Uint8Array.from([...bytes.subarray(0, cut), ...bytes.subarray(Math.floor(next() * bytes.length))]);
  }
  return bytes;
}
