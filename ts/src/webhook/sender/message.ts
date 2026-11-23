import { randomBytes as defaultRandomBytes } from "node:crypto";
import { gapEnvelope, terminatedEnvelope } from "../subscription/lifecycle.js";
import type { TerminatedEnvelopeInput } from "../subscription/lifecycle.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ID_LENGTH = 32;
const UTF8 = new TextEncoder();

/** The event and control messages a sender can deliver. */
export type OutboundKind = "event" | "gap" | "terminated" | "verification";

/** One logical delivery, with the same id and body on every attempt. */
export interface OutboundMessage {
  readonly kind: OutboundKind;
  readonly webhookId: string;
  readonly body: Uint8Array;
}

/** Generates an unbiased, independent webhook id (spec 06 R1.4). */
export function newWebhookId(kind: OutboundKind, randomBytes: (n: number) => Uint8Array = defaultRandomBytes): string {
  let suffix = "";
  while (suffix.length < ID_LENGTH) {
    const bytes = randomBytes(ID_LENGTH - suffix.length);
    if (bytes.length === 0) throw new Error("random source returned no bytes");
    for (const byte of bytes) {
      if (byte >= 248) continue;
      suffix += ALPHABET.charAt(byte % ALPHABET.length);
      if (suffix.length === ID_LENGTH) break;
    }
  }
  return (kind === "event" ? "msg_" : `msg_${kind}_`) + suffix;
}

function message(kind: OutboundKind, body: Uint8Array, randomBytes?: (n: number) => Uint8Array): OutboundMessage {
  return { kind, webhookId: newWebhookId(kind, randomBytes), body };
}

/** Wraps an event's already serialized bytes without re-encoding them. */
export function eventMessage(body: Uint8Array, randomBytes?: (n: number) => Uint8Array): OutboundMessage {
  return message("event", body, randomBytes);
}

/** Creates the gap control message for the supplied replay cursor. */
export function gapMessage(cursor: string | null, randomBytes?: (n: number) => Uint8Array): OutboundMessage {
  return message("gap", UTF8.encode(gapEnvelope(cursor)), randomBytes);
}

/** Creates the verification control message for an in-subscribe challenge. */
export function verificationMessage(challenge: string, randomBytes?: (n: number) => Uint8Array): OutboundMessage {
  return message("verification", UTF8.encode(JSON.stringify({ type: "verification", challenge })), randomBytes);
}

/** Creates the terminated control message using the subscription error envelope. */
export function terminatedMessage(input: TerminatedEnvelopeInput, randomBytes?: (n: number) => Uint8Array): OutboundMessage {
  return message("terminated", UTF8.encode(terminatedEnvelope(input)), randomBytes);
}
