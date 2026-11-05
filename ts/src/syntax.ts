/** Shared syntax checks: scope names (spec 02 section 2) and policy pattern matching where * is the only metacharacter. */

/** ValidScope: ^[a-z][a-z0-9_]*(:[a-z0-9_]+)*$ (spec 02 section 2). */
export function validScope(s: string): boolean {
  return /^[a-z][a-z0-9_]*(:[a-z0-9_]+)*$/.test(s);
}

/** ValidName: 1-64 characters of [A-Za-z0-9._-] (spec 03 section 1). */
export function validName(s: string): boolean {
  return /^[A-Za-z0-9._-]{1,64}$/.test(s);
}

/** MatchPattern reports whether input matches pattern: '*' matches any run of characters including none and newlines; every other character is literal and case-sensitive (spec 02 section 3). */
export function matchPattern(pattern: string, input: string): boolean {
  // Go matches bytes, this matches UTF-16 code units — equivalent because '*'
  // is the only metacharacter and a single ASCII unit in both (a '*' may match
  // half a surrogate pair just as Go's may match half a UTF-8 sequence).
  // Classic greedy matcher: backtrack to the most recent '*' on mismatch.
  let p = 0;
  let i = 0;
  let starP = -1; // index of the last '*' seen in the pattern
  let starI = 0; // input position at which that '*' started matching
  while (i < input.length) {
    if (p < pattern.length && pattern.charCodeAt(p) === 42 /* '*' */) {
      starP = p;
      starI = i;
      p++; // '*' can also match the empty run; try advancing first
      continue;
    }
    if (p < pattern.length && pattern.charCodeAt(p) === input.charCodeAt(i)) {
      p++;
      i++;
      continue;
    }
    if (starP >= 0) {
      // Extend the run matched by the last '*'.
      starI++;
      i = starI;
      p = starP + 1;
      continue;
    }
    return false;
  }
  // Only trailing '*'s may remain to match the empty remainder.
  while (p < pattern.length && pattern.charCodeAt(p) === 42) {
    p++;
  }
  return p === pattern.length;
}
