import assert from "node:assert/strict";
import { test } from "node:test";
import { jackAcceptStreams } from "../../src/stream/codes.js";
import { corpus, mutateBytes, random, runProperty, settings } from "./helper.js";

function specRecognizes(lines: readonly string[]): boolean {
  for (const line of lines) {
    let index = 0;
    let found = false;
    let invalid = false;
    while (index < line.length && line[index] === " ") index++;
    while (index < line.length) {
      const start = index;
      while (index < line.length && /[A-Za-z0-9-]/.test(line[index]!)) index++;
      if (index === start) { invalid = true; break; }
      if (line.slice(start, index) === "s1") found = true;
      while (index < line.length && line[index] === " ") index++;
      if (index === line.length) break;
      if (line[index] !== ",") { invalid = true; break; }
      index++;
      while (index < line.length && line[index] === " ") index++;
      if (index === line.length) { invalid = true; break; }
    }
    if (!invalid && found) return true;
  }
  return false;
}

test("fuzz Jack-Accept stream opt-in", () => {
  const { seed, iterations } = settings(); const next = random(seed);
  const boundaries = corpus("accept-boundaries.json") as { lines: string[]; whitespace: string[] };
  const bases = ["s1", "s2", "S1", "s10", "s1,s2", "s2, s1", "s1 , s2", "", ",s1", "s1,", "s1\ts2", "s1\ns2", "s1\rs2", "s1\u0000s2", ...boundaries.lines, ...boundaries.whitespace, ...boundaries.whitespace.flatMap((space) => boundaries.lines.map((line) => `${space}${line}${space}`))];
  const insertions = [" ", "  ", "\t", ",", "\u0000", "\r", "\n", ...boundaries.whitespace];
  for (const lines of [[",s2", "s1"], ["s1", ",s2"]]) {
    runProperty(seed, 0, lines, () => assert.equal(jackAcceptStreams(lines), specRecognizes(lines)));
    assert.equal(specRecognizes(lines), true);
  }
  for (let i = 0; i < iterations; i++) {
    const base = bases[Math.floor(next() * bases.length)]!;
    const second = bases[Math.floor(next() * bases.length)]!;
    const line = i % 2 === 0 ? base : new TextDecoder().decode(mutateBytes(new TextEncoder().encode(base), next));
    const inserted = next() < 0.5 ? line : (() => { const at = Math.floor(next() * (line.length + 1)); return line.slice(0, at) + insertions[Math.floor(next() * insertions.length)]! + line.slice(at); })();
    const changed = next() < 0.35 ? inserted.replace(/[A-Za-z]/g, (letter) => next() < 0.25 ? letter.toUpperCase() : letter) : inserted;
    const lines = [changed, second];
    runProperty(seed, i, lines, () => assert.equal(jackAcceptStreams(lines), specRecognizes(lines)));
  }
});
