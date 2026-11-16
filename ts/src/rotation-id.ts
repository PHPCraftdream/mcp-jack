/**
 * Exact-decimal canonicalisation of numeric JSON-RPC ids, ported from
 * rotation/result.go canonicalNumber (Go) / rust/src/rotation/result.rs
 * canonical_id (Rust): the response must carry the shortest decimal form of
 * the expected number without an exponent, computed without float arithmetic.
 */

/** Same constant as Go MaxResultBodyBytes / Rust MAX_RESULT_BODY_BYTES. */
const MAX_BODY_BYTES = 256 * 1024;

/** JSON number grammar check: -?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?. */
function parseNumberLexeme(text: string): { negative: boolean; digits: string; exponent: number } | undefined {
  let rest = text;
  let negative = false;
  if (rest.startsWith("-")) {
    negative = true;
    rest = rest.slice(1);
  }
  const expIndex = rest.search(/[eE]/);
  let mantissa = rest;
  let expText = "";
  if (expIndex >= 0) {
    mantissa = rest.slice(0, expIndex);
    expText = rest.slice(expIndex + 1);
  }
  const dotIndex = mantissa.indexOf(".");
  const intPart = dotIndex >= 0 ? mantissa.slice(0, dotIndex) : mantissa;
  const fracPart = dotIndex >= 0 ? mantissa.slice(dotIndex + 1) : "";
  const allDigits = (value: string): boolean => value !== "" && /^[0-9]+$/.test(value);
  if (!allDigits(intPart) || (intPart.length > 1 && intPart.startsWith("0"))) return undefined;
  if (dotIndex >= 0 && !allDigits(fracPart)) return undefined;
  let exponent = -fracPart.length;
  if (expText !== "") {
    let sign = 1;
    if (expText.startsWith("+") || expText.startsWith("-")) {
      if (expText.startsWith("-")) sign = -1;
      expText = expText.slice(1);
    }
    if (!allDigits(expText)) return undefined;
    const parsed = Number(expText);
    // A giant exponent is cut off by the overflow gate anyway (Go strconv.Atoi parity).
    if (!Number.isSafeInteger(parsed)) return undefined;
    exponent += sign * parsed;
  }
  return { negative, digits: intPart + fracPart, exponent };
}

/**
 * Exact |value| < 2^1024 gate via BigInt (no float): E >= 0 compares
 * D·10^E with 2^1024, E < 0 compares D with 2^1024·10^(-E). Outside the f64
 * range the gate closes immediately: 10^309 > 2^1024; E < -MAX_BODY_BYTES
 * means the canonical text is longer than the accepted body limit and cannot
 * match the response lexeme byte-for-byte.
 */
function withinFloatRange(digits: string, exponent: number): boolean {
  if (exponent > 308) return false;
  if (-exponent > MAX_BODY_BYTES) return false;
  const value = BigInt(digits);
  const limit = 2n ** 1024n;
  if (exponent >= 0) return value * 10n ** BigInt(exponent) < limit;
  return value < limit * 10n ** BigInt(-exponent);
}

/**
 * Shortest decimal form without an exponent; leading/trailing zeros removed,
 * -0 becomes "0", minus sign only on a nonzero value. Returns undefined when
 * the lexeme is not a JSON number within the f64 range (e.g. it would round
 * to Infinity).
 */
export function canonicalNumber(text: string): string | undefined {
  const parsed = parseNumberLexeme(text);
  if (parsed === undefined || !withinFloatRange(parsed.digits, parsed.exponent)) return undefined;
  let digits = parsed.digits.replace(/^0+/, "");
  if (digits === "") return "0";
  const exponent = parsed.exponent;
  let result: string;
  if (exponent >= 0) {
    result = digits + "0".repeat(exponent);
  } else {
    const split = -exponent;
    let integer = "0";
    let fraction = digits;
    if (digits.length > split) {
      integer = digits.slice(0, digits.length - split);
      fraction = digits.slice(digits.length - split);
    } else {
      fraction = "0".repeat(split - digits.length) + digits;
    }
    fraction = fraction.replace(/0+$/, "");
    result = fraction === "" ? integer : `${integer}.${fraction}`;
  }
  return parsed.negative ? `-${result}` : result;
}
