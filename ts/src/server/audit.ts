/**
 * Audit sink recording every call and administrative change with the caller's
 * key id. Events carry nothing that could hold an invite code or a private key
 * (spec 03 section 8).
 */

/** Audit outcome values (Go AuditSuccess/AuditFailure). */
export const AUDIT_SUCCESS = "success";
export const AUDIT_FAILURE = "failure";

/** One audit record: time, tool, outcome, failure code, caller kid and name, target. */
export interface AuditEvent {
  readonly time: number;
  readonly tool: string;
  readonly outcome: string;
  /** Omitted on the wire when absent (Go omitempty). */
  readonly code?: string;
  readonly actorKid: string;
  /** Omitted on the wire when absent. */
  readonly actorName?: string;
  /** Omitted on the wire when absent. */
  readonly target?: string;
}

/** Receives audit events. */
export interface AuditSink {
  /** TS form of Go's error return: a failing sink throws instead of returning an error. */
  record(event: AuditEvent): void;
}

/** In-memory sink; record always succeeds, events() returns fresh copies. */
export class MemoryAuditSink implements AuditSink {
  // Storage is not named `events`: a field and the events() method cannot
  // share a name in one class.
  private readonly recorded: AuditEvent[] = [];

  record(event: AuditEvent): void {
    // Shallow clone: fields are strings/numbers, so a per-event copy gives the
    // value semantics Go gets from struct copies.
    this.recorded.push({ ...event });
  }

  /** Fresh copies in record order, so caller mutation never reaches the sink. */
  events(): AuditEvent[] {
    return this.recorded.map((e) => ({ ...e }));
  }
}

/** Writes one compact JSON object per line to a synchronous writer. */
export class JsonlAuditSink implements AuditSink {
  constructor(private readonly target: { write(chunk: string): unknown }) {}

  record(event: AuditEvent): void {
    // One literal with conditional spreads: absent optional fields are dropped
    // (Go omitempty) and Go's struct field order is preserved.
    const wire = {
      time: event.time,
      tool: event.tool,
      outcome: event.outcome,
      ...(event.code ? { code: event.code } : {}),
      actor_kid: event.actorKid,
      ...(event.actorName ? { actor_name: event.actorName } : {}),
      ...(event.target ? { target: event.target } : {}),
    };
    // JSON.stringify alone yields the compact one-line encoding.
    this.target.write(JSON.stringify(wire) + "\n");
  }
}
