/** Shared syntax checks: name syntax only (spec 03 section 1). */

/** ValidName: 1-64 characters of [A-Za-z0-9._-] (spec 03 section 1). */
export function validName(s: string): boolean {
  return /^[A-Za-z0-9._-]{1,64}$/.test(s);
}
