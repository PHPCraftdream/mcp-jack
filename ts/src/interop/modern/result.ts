// The result line of the modern matrix client (contract 4.2): outcome, wire code and the era of the last request, plus the code derivation every language shares.
import type { JsonValue } from "../../core/json-raw.js";
import { isJsonObject, ownMember } from "./common.js";
import type { Reply, Step } from "./wire.js";

/** The three verdicts of a run (contract 4.2); a client-side verdict replaces the wire one below. */
export type Outcome = "ok" | "rejected" | "client_error";

/** A client-side verdict that replaces the wire verdict of the last response. */
export interface VerdictOverride {
  readonly outcome: "rejected" | "client_error";
  readonly code: string;
}

/** The one stdout result line (contract 4.2), every member present. */
export interface ResultLine {
  readonly scenario: string;
  readonly outcome: Outcome;
  readonly http_status: number | null;
  readonly code: string | number | null;
  readonly data: { readonly era: "modern" | "legacy"; readonly steps: readonly Step[] };
}

/** Contract 4.2 code derivation: an integer code of a JSON-RPC 2.0 error object, then a string Jack envelope code, else null. */
export function wireCode(json: JsonValue | undefined): string | number | null {
  const error = ownMember(json, "error");
  // A bare non-object `error` member carries no code at all.
  if (!isJsonObject(error)) return null;
  const code = ownMember(error, "code");
  // The integer form belongs to JSON-RPC 2.0 only: the `jsonrpc` member must be exactly "2.0".
  if (ownMember(json, "jsonrpc") === "2.0" && typeof code === "number" && Number.isInteger(code)) return code;
  // The spec 01 section 4 envelope carries a string code and may omit `jsonrpc` entirely.
  return typeof code === "string" ? code : null;
}

/** True for a verified 2xx status: the one shape contract 4.2 calls a completed operation. */
function isOkStatus(status: number | null): boolean {
  return status !== null && status >= 200 && status <= 299;
}

/** Builds the result line of a run from its last reply and the verdict the run settled on (contract 4.2). */
export function buildResult(input: {
  readonly scenario: string;
  readonly era: "modern" | "legacy";
  readonly steps: readonly Step[];
  readonly last: Reply | null;
  readonly override: VerdictOverride | null;
}): ResultLine {
  const data = { era: input.era, steps: input.steps };
  const override = input.override;
  if (override !== null) {
    // A client-side verdict still names the status it reacted to, except when
    // no answer was trusted at all (contract 4.2: client_error has no status).
    return {
      scenario: input.scenario,
      outcome: override.outcome,
      http_status: override.outcome === "client_error" ? null : (input.last?.status ?? null),
      code: override.code,
      data,
    };
  }
  const last = input.last;
  if (last === null) {
    // Nothing was answered: the run could not settle an era at all.
    return { scenario: input.scenario, outcome: "client_error", http_status: null, code: "unsupported_version", data };
  }
  if (last.trust === "unverified") {
    // An untrusted answer never reports its wire status or code.
    return {
      scenario: input.scenario,
      outcome: "client_error",
      http_status: null,
      code: last.clientCode ?? "missing_auth",
      data,
    };
  }
  return {
    scenario: input.scenario,
    outcome: isOkStatus(last.status) ? "ok" : "rejected",
    http_status: last.status,
    code: wireCode(last.json),
    data,
  };
}
