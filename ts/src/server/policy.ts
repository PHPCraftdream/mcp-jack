/** Policy document loading and validation, then first-match-wins evaluation; a missing scope and a null scope differ. */
import { matchPattern, validScope } from "../syntax.js";

/** A load-time validation failure of a policy document (spec 02 section 3); reason is a short stable identifier. */
export class PolicyError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    // Go parity: the message carries the reason verbatim.
    super("server: invalid policy: " + reason);
    this.reason = reason;
    this.name = "PolicyError";
  }
}

/** The policy verdict for one operation. */
export interface Decision {
  readonly allowed: boolean;
  /** The scope the caller must hold; null means any authenticated key. */
  readonly scope: string | null;
}

/** One compiled rule; tool undefined = any tool, scope null = any authenticated key (allow rules only). */
interface Rule {
  method: string;
  tool: string | undefined;
  deny: boolean;
  scope: string | null;
}

/** Operator-owned list of first-match-wins rules; anything no rule allows is denied (spec 02 section 3). */
export class Policy {
  /**
   * Public so the module-level parsePolicy can construct the compiled policy.
   * Callers must use parsePolicy: it is the only entry point that validates
   * the document (the constructor does not).
   */
  constructor(private readonly rules: readonly Rule[]) {}

  /** Verdict for a method and, for tools/call, a tool name; first matching rule wins. */
  evaluate(method: string, tool: string | undefined): Decision {
    for (const rule of this.rules) {
      if (!matchPattern(rule.method, method)) {
        continue;
      }
      // A tool-restricted rule only matches an actual tools/call with a tool name.
      if (
        rule.tool !== undefined &&
        !(method === "tools/call" && tool !== undefined && matchPattern(rule.tool, tool))
      ) {
        continue;
      }
      if (rule.deny) {
        return { allowed: false, scope: null };
      }
      return { allowed: true, scope: rule.scope };
    }
    return { allowed: false, scope: null };
  }
}

// Go's encoding/json silently replaces invalid UTF-8; here a bad byte rejects
// the whole document — load-time strictness beats silent repair.
const UTF8 = new TextDecoder("utf-8", { fatal: true });

/** True when v is a plain JSON object (not null, not an array). */
function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** True when every key of obj is in allowed; unknown fields are a hard error. */
function onlyKeys(obj: Record<string, unknown>, allowed: string[]): boolean {
  return Object.keys(obj).every((k) => allowed.includes(k));
}

/** Validates and compiles a policy document, throwing PolicyError on any invalid document. */
export function parsePolicy(json: string | Uint8Array): Policy {
  let text: string;
  try {
    text = typeof json === "string" ? json : UTF8.decode(json);
  } catch {
    throw new PolicyError("document");
  }
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new PolicyError("document");
  }
  // Duplicate keys keep the last value (JSON.parse semantics); not a duplicate-detection exercise.
  if (!isObject(doc) || !onlyKeys(doc, ["version", "rules"])) {
    throw new PolicyError("document");
  }
  const version = doc["version"];
  if (typeof version !== "number" || version !== 1) {
    throw new PolicyError("document");
  }
  const rawRules = doc["rules"];
  if (!Array.isArray(rawRules)) {
    // Explicit null fails Array.isArray, same reason as Go.
    throw new PolicyError("document");
  }

  const rules: Rule[] = [];
  for (const raw of rawRules) {
    rules.push(parseRule(raw));
  }
  return new Policy(rules);
}

/** Parses one rule, throwing PolicyError with the rule-level reason on failure. */
function parseRule(raw: unknown): Rule {
  if (!isObject(raw) || !onlyKeys(raw, ["match", "scope", "effect"])) {
    throw new PolicyError("unknown_field");
  }
  const match = raw["match"];
  if (!isObject(match) || !onlyKeys(match, ["method", "tool"])) {
    throw new PolicyError("unknown_field");
  }

  const method = match["method"];
  if (typeof method !== "string" || method === "") {
    throw new PolicyError("method");
  }
  let tool: string | undefined;
  // Presence is checked explicitly: match.tool === null is a "tool" error, not "absent".
  if (Object.hasOwn(match, "tool")) {
    const t = match["tool"];
    if (typeof t !== "string" || t === "") {
      throw new PolicyError("tool");
    }
    if (method !== "tools/call") {
      // A tool restriction only makes sense for tools/call; "tools/*" with a tool is rejected.
      throw new PolicyError("tool_without_tools_call");
    }
    tool = t;
  }

  let deny = false;
  // Spec 02 section 3: a PRESENT effect must be exactly "allow" or "deny" —
  // explicit null is neither and is rejected. Go and the reference verifier
  // treat null as absent; the spec wins (reported divergence). An ABSENT
  // effect defaults to allow.
  if (Object.hasOwn(raw, "effect")) {
    const effect = raw["effect"];
    if (effect === "deny") {
      deny = true;
    } else if (effect !== "allow") {
      throw new PolicyError("effect");
    }
  }

  if (!Object.hasOwn(raw, "scope")) {
    if (deny) {
      return { method, tool, deny, scope: null };
    }
    throw new PolicyError("missing_scope");
  }
  const scope = raw["scope"];
  if (deny) {
    // A deny rule needs no scope — present at all (even null) is a contradiction.
    throw new PolicyError("scope_with_deny");
  }
  if (scope === null) {
    return { method, tool, deny, scope: null }; // any authenticated key
  }
  if (typeof scope !== "string" || !validScope(scope)) {
    // Shape check before the reserved check, matching the reference taxonomy.
    throw new PolicyError("malformed_scope");
  }
  if (scope === "admin") {
    // admin is only grantable to registry entries, never a policy scope.
    throw new PolicyError("reserved_scope");
  }
  return { method, tool, deny, scope };
}
