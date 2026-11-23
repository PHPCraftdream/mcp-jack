/** Shared loaders for the four normative modern-profile corpora of spec 04 section 8 (spec/fixtures/modern/*). */
import { fixture } from "../../support/fixtures/index.js";
import type { JsonValue } from "../../support/fixtures/index.js";
export { fixture };

/**
 * One `[name, value]` header pair, order and casing preserved. The fixture
 * package's HeaderPair is an object view of the same data; the modern rules
 * consume tuple pairs, so the tuple form is declared here.
 */
export type HeaderPair = readonly [string, string];

/** One corpus file of spec/fixtures/modern. */
export function modernFixture(name: string): JsonValue {
  return fixture("modern/" + name);
}

/** A JSON object view; throws with the label when the value is not an object. */
export function record(value: JsonValue | undefined, what: string): { readonly [key: string]: JsonValue } {
  if (value === undefined || value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(what + ": expected a JSON object");
  }
  return value;
}

/** A JSON array of cases; throws with the label when the value is not an array. */
export function arrayOf(value: JsonValue | undefined, what: string): JsonValue[] {
  if (!Array.isArray(value)) {
    throw new Error(what + ": expected a JSON array");
  }
  return value;
}

/** A required string member. */
export function text(obj: { readonly [key: string]: JsonValue }, key: string, what: string): string {
  const value = obj[key];
  if (typeof value !== "string") {
    throw new Error(what + "." + key + ": expected a string");
  }
  return value;
}

/** A required boolean member. */
export function flag(obj: { readonly [key: string]: JsonValue }, key: string, what: string): boolean {
  const value = obj[key];
  if (typeof value !== "boolean") {
    throw new Error(what + "." + key + ": expected a boolean");
  }
  return value;
}

/** A `[[name, value], ...]` header list, order and casing preserved. */
export function headerPairs(value: JsonValue | undefined, what: string): readonly HeaderPair[] {
  const entries = arrayOf(value, what);
  const pairs: HeaderPair[] = [];
  entries.forEach((entry, index) => {
    const where = what + "[" + index + "]";
    if (!Array.isArray(entry) || entry.length !== 2) {
      throw new Error(where + ": expected a [name, value] pair");
    }
    const name = entry[0];
    const val = entry[1];
    if (typeof name !== "string" || typeof val !== "string") {
      throw new Error(where + ": expected a [string, string] pair");
    }
    pairs.push([name, val]);
  });
  return pairs;
}

/** A JSON array of strings. */
export function textList(value: JsonValue | undefined, what: string): string[] {
  const entries = arrayOf(value, what);
  return entries.map((entry, index) => {
    if (typeof entry !== "string") {
      throw new Error(what + "[" + index + "]: expected a string");
    }
    return entry;
  });
}

/** The one summary line per corpus: `VECTOR-SUMMARY corpus=<corpus> sdk=ts pass=<n> excluded=0 deviation=0`. */
export function printSummary(
  corpus: "modern-request" | "header-encoding" | "x-mcp-header" | "era-detection",
  pass: number,
): void {
  console.log("VECTOR-SUMMARY corpus=" + corpus + " sdk=ts pass=" + pass + " excluded=0 deviation=0");
}
