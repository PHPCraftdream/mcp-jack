import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { JsonValue, HeaderPair } from "./types.js";

let cachedRoot: string | undefined;

/** Walk up from this file (source or compiled) to the directory that contains spec/fixtures. */
export function repoRoot(): string {
  if (cachedRoot !== undefined) {
    return cachedRoot;
  }
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    if (existsSync(join(dir, "spec", "fixtures"))) {
      cachedRoot = dir;
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      throw new Error(`fixture root not found: no spec/fixtures above ${dir}`);
    }
    dir = parent;
  }
}

/** Raw access to one fixture file, mirroring Go's spec.Fixture. */
export function fixture(name: string): JsonValue {
  let text: string;
  try {
    text = readFileSync(join(repoRoot(), "spec", "fixtures", name), "utf8");
  } catch (err) {
    throw new Error(`fixture ${name}: ${(err as Error).message}`);
  }
  try {
    return JSON.parse(text) as JsonValue;
  } catch (err) {
    throw new Error(`fixture ${name}: ${(err as Error).message}`);
  }
}

// Strict decode helpers: unknown fields, wrong types, nulls where Go rejects
// them, and missing fields are all load errors (Go's DisallowUnknownFields).

export function asObject(value: JsonValue, what: string): Record<string, JsonValue> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new Error(`${what}: expected a JSON object`);
  }
  return value as Record<string, JsonValue>;
}

export function rejectUnknownKeys(obj: Record<string, JsonValue>, allowed: readonly string[], what: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      throw new Error(`${what}: unknown field "${key}"`);
    }
  }
}

export function requireField(obj: Record<string, JsonValue>, key: string, what: string): JsonValue {
  if (!Object.hasOwn(obj, key)) {
    throw new Error(`${what}: missing field "${key}"`);
  }
  const value = obj[key];
  if (value === undefined) {
    throw new Error(`${what}: field "${key}" is not valid JSON`);
  }
  return value;
}

export function optionalField(obj: Record<string, JsonValue>, key: string, what: string): JsonValue | undefined {
  if (!Object.hasOwn(obj, key)) {
    return undefined;
  }
  const value = obj[key];
  if (value === undefined) {
    throw new Error(`${what}: field "${key}" is not valid JSON`);
  }
  return value;
}

export function asString(value: JsonValue, what: string): string {
  if (typeof value !== "string") {
    throw new Error(`${what}: expected a string`);
  }
  return value;
}

export function asInt(value: JsonValue, what: string): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error(`${what}: expected an integer`);
  }
  return value;
}

export function asBool(value: JsonValue, what: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`${what}: expected a boolean`);
  }
  return value;
}

export function asArray(value: JsonValue, what: string): readonly JsonValue[] {
  if (!Array.isArray(value)) {
    throw new Error(`${what}: expected an array`);
  }
  return value;
}

export function asStringArray(value: JsonValue, what: string): readonly string[] {
  return asArray(value, what).map((item) => asString(item, `${what}[]`));
}

export function optString(obj: Record<string, JsonValue>, key: string, what: string): string | undefined {
  const value = optionalField(obj, key, what);
  return value === undefined ? undefined : asString(value, what);
}

export function optInt(obj: Record<string, JsonValue>, key: string, what: string): number | undefined {
  const value = optionalField(obj, key, what);
  return value === undefined ? undefined : asInt(value, what);
}

export function optBool(obj: Record<string, JsonValue>, key: string, what: string): boolean | undefined {
  const value = optionalField(obj, key, what);
  return value === undefined ? undefined : asBool(value, what);
}

export function optObject(obj: Record<string, JsonValue>, key: string, what: string): Record<string, JsonValue> | undefined {
  const value = optionalField(obj, key, what);
  return value === undefined ? undefined : asObject(value, what);
}

export function optNullableString(obj: Record<string, JsonValue>, key: string, what: string): string | null | undefined {
  const value = optionalField(obj, key, what);
  if (value === undefined) {
    return undefined;
  }
  return value === null ? null : asString(value, what);
}

export function optNullableInt(obj: Record<string, JsonValue>, key: string, what: string): number | null | undefined {
  const value = optionalField(obj, key, what);
  if (value === undefined) {
    return undefined;
  }
  return value === null ? null : asInt(value, what);
}

export function asHeaderPair(entry: JsonValue, what: string): HeaderPair {
  const pair = asArray(entry, what);
  if (pair.length !== 2) {
    throw new Error(`${what}: header pair must have exactly 2 elements, got ${pair.length}`);
  }
  const name = pair[0];
  const headerValue = pair[1];
  if (typeof name !== "string" || typeof headerValue !== "string") {
    throw new Error(`${what}: header pair elements must be strings, got null`);
  }
  return { name, value: headerValue };
}

export function asHeaders(value: JsonValue, what: string): readonly HeaderPair[] {
  return asArray(value, what).map((item, index) => asHeaderPair(item, `${what}[${index}]`));
}
