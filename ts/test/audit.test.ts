/** Tests for the audit sinks, ported from Go's audit_test.go. */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AUDIT_FAILURE,
  AUDIT_SUCCESS,
  JsonlAuditSink,
  MemoryAuditSink,
  type AuditEvent,
} from "../src/server/audit.js";

class BufferWriter {
  private readonly chunks: string[] = [];
  write(chunk: string): unknown {
    this.chunks.push(chunk);
    return undefined;
  }
  text(): string {
    return this.chunks.join("");
  }
}

function auditTestEvent(outcome: string, code?: string): AuditEvent {
  return {
    time: 1767225500,
    tool: "tools/call",
    outcome,
    ...(code ? { code } : {}),
    actorKid: "k1",
  };
}

/** Drops readonly so a test can mutate a returned event. */
type Writable<T> = { -readonly [K in keyof T]: T[K] };

test("memory sink order and copy", () => {
  const sink = new MemoryAuditSink();
  sink.record(auditTestEvent(AUDIT_SUCCESS));
  sink.record(auditTestEvent(AUDIT_FAILURE, "E_INVITE_EXPIRED"));

  const events = sink.events();
  assert.equal(events.length, 2);
  assert.equal(events[0]?.outcome, AUDIT_SUCCESS);
  assert.equal(events[1]?.outcome, AUDIT_FAILURE);

  // Mutating the returned events must not affect the sink.
  const first = events[0] as Writable<AuditEvent>;
  first.tool = "MUTATED";
  first.actorKid = "MUTATED";
  const again = sink.events();
  assert.equal(again[0]?.tool, "tools/call");
  assert.equal(again[0]?.actorKid, "k1");
});

test("jsonl sink field sets", () => {
  const writer = new BufferWriter();
  const sink = new JsonlAuditSink(writer);

  sink.record(auditTestEvent(AUDIT_SUCCESS));
  const failure = { ...auditTestEvent(AUDIT_FAILURE, "E_POLICY"), target: "file:/tmp/x" };
  sink.record(failure);

  const out = writer.text();
  assert.equal([...out].filter((c) => c === "\n").length, 2);
  const lines = out.replace(/\n$/, "").split("\n");
  assert.equal(lines.length, 2);

  const success = JSON.parse(lines[0] as string) as Record<string, unknown>;
  assert.deepStrictEqual(
    Object.keys(success).sort(),
    ["actor_kid", "outcome", "time", "tool"],
  );
  assert.equal(success.outcome, AUDIT_SUCCESS);
  assert.equal(success.actor_kid, "k1");

  const fail = JSON.parse(lines[1] as string) as Record<string, unknown>;
  assert.deepStrictEqual(
    Object.keys(fail).sort(),
    ["actor_kid", "code", "outcome", "target", "time", "tool"],
  );
  assert.equal(fail.code, "E_POLICY");
  assert.equal(fail.target, "file:/tmp/x");
});

test("audit event never carries secret keys", () => {
  const writer = new BufferWriter();
  const sink = new JsonlAuditSink(writer);
  sink.record({
    time: 1767225500,
    tool: "tools/call",
    outcome: AUDIT_FAILURE,
    code: "E_POLICY",
    actorKid: "k1",
    actorName: "alice",
    target: "file:/tmp/x",
  });
  const ev = JSON.parse(writer.text().replace(/\n$/, "")) as Record<string, unknown>;
  const allowed = new Set([
    "time",
    "tool",
    "outcome",
    "code",
    "actor_kid",
    "actor_name",
    "target",
  ]);
  for (const key of Object.keys(ev)) {
    assert.ok(allowed.has(key), `unexpected key ${key} in serialized audit event`);
  }
});

test("jsonl sink: 50 records, no interleaving", () => {
  const writer = new BufferWriter();
  const sink = new JsonlAuditSink(writer);
  for (let i = 0; i < 50; i++) sink.record(auditTestEvent(AUDIT_SUCCESS));

  const lines = writer.text().replace(/\n$/, "").split("\n");
  assert.equal(lines.length, 50);
  for (const line of lines) {
    const ev = JSON.parse(line as string) as Record<string, unknown>;
    assert.equal(ev.outcome, AUDIT_SUCCESS);
    assert.equal(ev.actor_kid, "k1");
  }
});
