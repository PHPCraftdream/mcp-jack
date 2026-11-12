// ---------------------------------------------------------------------------
// Общий tokenizer: native last-wins неизменен, candidate имеет отдельный strict entry.
// ---------------------------------------------------------------------------

/** Any JSON value. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/** One node of the parallel source tree: exact text plus parsed value. */
export interface RawJsonNode {
  /** Exact source slice of this value. */
  readonly text: string;
  /** Parsed value (numbers decode like Number(), strings like JSON.parse). */
  readonly value: JsonValue;
  /** Object member nodes, last duplicate wins; undefined for non-objects. */
  readonly members: ReadonlyMap<string, RawJsonNode> | undefined;
  /** Array element nodes; undefined for non-arrays. */
  readonly items: readonly RawJsonNode[] | undefined;
}

/**
 * Strict RFC 8259 parser: throws Error("invalid JSON") on any violation,
 * including trailing content after the root value. Whitespace is exactly
 * " \t\n\r"; raw control chars (< 0x20) in strings violate; escapes are
 * \" \\ \/ \b \f \n \r \t \uXXXX (4 hex digits, any other escape violates).
 * Duplicate object keys keep the LAST (value object and members map alike) —
 * normative since D13: last occurrence wins, no member merging (spec 02
 * section 4). A member named "__proto__" is
 * defined with Object.defineProperty so it becomes an own property instead of
 * a prototype change (JSON.parse parity; the reference verifier does the
 * same); all other keys by plain assignment. The members Map needs no such
 * care (a Map has no prototype hazard). Each source node is built complete at
 * construction — value, exact text and members/items are all present when the
 * node literal is created; no node is mutated after construction.
 */
function parseRawJson(text: string, candidate: boolean): { readonly value: JsonValue; readonly source: RawJsonNode } {
  let i = 0;
  const fail = (): never => {
    throw new Error("invalid JSON");
  };
  const ws = (): void => {
    while (i < text.length && " \t\n\r".includes(text[i] as string)) i++;
  };
  const digit = (c: string | undefined): boolean => c !== undefined && c >= "0" && c <= "9";
  // An own property even for the key "__proto__", which plain assignment
  // would turn into a prototype change.
  const setMember = (obj: { [key: string]: JsonValue }, key: string, value: JsonValue): void => {
    if (key === "__proto__") {
      Object.defineProperty(obj, key, { value, writable: true, enumerable: true, configurable: true });
    } else {
      obj[key] = value;
    }
  };

  function string(): string {
    i += 1; // opening quote
    let out = "";
    for (;;) {
      if (i >= text.length) fail();
      const c = text[i] as string;
      if (c === '"') {
        i += 1;
        if (candidate && Buffer.from(out, "utf8").toString("utf8") !== out) fail();
        return out;
      }
      if (c === "\\") {
        const e = text[i + 1];
        i += 2;
        if (e === "u") {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail();
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else if (e === '"') out += '"';
        else if (e === "\\") out += "\\";
        else if (e === "/") out += "/";
        else if (e === "b") out += "\b";
        else if (e === "f") out += "\f";
        else if (e === "n") out += "\n";
        else if (e === "r") out += "\r";
        else if (e === "t") out += "\t";
        else fail();
      } else {
        if (text.charCodeAt(i) < 0x20) fail(); // raw control char
        out += c;
        i += 1;
      }
    }
  }

  function number(): number {
    const start = i;
    if (text[i] === "-") i += 1;
    // RFC 8259 grammar: no leading zeros; fraction and exponent when present.
    if (text[i] === "0") i += 1;
    else if (digit(text[i])) {
      while (i < text.length && digit(text[i])) i += 1;
    } else fail();
    if (text[i] === ".") {
      i += 1;
      if (!digit(text[i])) fail();
      while (i < text.length && digit(text[i])) i += 1;
    }
    if (text[i] === "e" || text[i] === "E") {
      i += 1;
      if (text[i] === "+" || text[i] === "-") i += 1;
      if (!digit(text[i])) fail();
      while (i < text.length && digit(text[i])) i += 1;
    }
    return Number(text.slice(start, i));
  }

  // Parses one value and builds its node in one step: value, exact source text
  // and members/items are all present at construction, so no node can ever be
  // observed with a placeholder value. The source tree is the single source of
  // truth; `parseJsonRaw`'s returned value is `root.value`.
  function valueNode(depth = 0): RawJsonNode {
    if (candidate && depth > 64) fail();
    ws();
    const start = i;
    const c = text[i];
    if (c === "{") {
      i += 1;
      ws();
      const obj: { [key: string]: JsonValue } = {};
      const members = new Map<string, RawJsonNode>();
      if (text[i] === "}") {
        i += 1;
        return { text: text.slice(start, i), value: obj, members, items: undefined };
      }
      for (;;) {
        if (text[i] !== '"') fail();
        const key = string();
        ws();
        if (text[i] !== ":") fail();
        i += 1;
        const child = valueNode(depth + 1);
        // Last duplicate wins in the members map and the value object alike.
        if (candidate && members.has(key)) fail();
        members.set(key, child);
        setMember(obj, key, child.value);
        ws();
        if (text[i] === ",") {
          i += 1;
          ws();
          continue;
        }
        if (text[i] === "}") {
          i += 1;
          return { text: text.slice(start, i), value: obj, members, items: undefined };
        }
        fail();
      }
    }
    if (c === "[") {
      i += 1;
      ws();
      const arr: JsonValue[] = [];
      const items: RawJsonNode[] = [];
      if (text[i] === "]") {
        i += 1;
        return { text: text.slice(start, i), value: arr, members: undefined, items };
      }
      for (;;) {
        const child = valueNode(depth + 1);
        items.push(child);
        arr.push(child.value);
        ws();
        if (text[i] === ",") {
          i += 1;
          ws();
          continue;
        }
        if (text[i] === "]") {
          i += 1;
          return { text: text.slice(start, i), value: arr, members: undefined, items };
        }
        fail();
      }
    }
    if (c === '"') {
      const s = string();
      return { text: text.slice(start, i), value: s, members: undefined, items: undefined };
    }
    if (text.startsWith("true", i)) {
      i += 4;
      return { text: text.slice(start, i), value: true, members: undefined, items: undefined };
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return { text: text.slice(start, i), value: false, members: undefined, items: undefined };
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return { text: text.slice(start, i), value: null, members: undefined, items: undefined };
    }
    const n = number();
    return { text: text.slice(start, i), value: n, members: undefined, items: undefined };
  }

  const root = valueNode();
  ws();
  if (i !== text.length) fail(); // trailing content is a violation
  return { value: root.value, source: root };
}

/** Native policy неизменна: последняя запись duplicate member побеждает. */
export function parseJsonRaw(text: string): { readonly value: JsonValue; readonly source: RawJsonNode } {
  return parseRawJson(text, false);
}

/** Внутренний candidate decoder: duplicate/scalar/depth guards, без trust promotion. */
export function parseCandidateJsonRaw(text: string): RawJsonNode {
  return parseRawJson(text, true).source;
}
