import { readFileSync } from "node:fs";
import { subscriptionKey, webhookSigningKeyFromSeed, eventMessage, gapMessage, terminatedMessage, WebhookSender, EndpointVerifier } from "../../webhook/index.js";
import type { OutboundMessage, ActiveSecret, VersionedSigningKey } from "../../webhook/index.js";
import { clockWrite, derivedId, fatal, list, output, parse, preflight, readClock, seed, seedHex, str, transport, ALPHABET, UsageError } from "./common.js";

const usage = "usage: webhook_sender --scenario <id> --url <https-url> --aud <aud> --clock-file <file> --secret-seed <text> --messages <kind>[,<kind>...] [options]";
function main(): void {
  const f = parse(process.argv.slice(2), ["--allowlist", "--allowed-range"], [], { messages: "event" });
  for (const flag of Object.keys(f)) if (!["scenario", "url", "aud", "clockFile", "secretSeed", "messages", "subscriptionId", "signingSeedHex", "jackSeedHex", "allowlist", "allowedRange", "resolverFile", "rebindAddress", "bodyFile", "tlsCa", "tlsCaDer"].includes(flag)) throw new UsageError(`unknown flag: --${flag.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}\n${usage}`);
  const scenario = str(f, "scenario"), url = str(f, "url"), aud = str(f, "aud"), clockFile = str(f, "clockFile"), secretSeed = str(f, "secretSeed");
  const kinds = (typeof f.messages === "string" ? f.messages : "event").split(",").map((x) => x.trim()).filter(Boolean);
  if (!kinds.length || kinds.some((k) => !["event", "gap", "terminated", "raw"].includes(k))) throw new Error("--messages contains an unknown kind");
  if (kinds.includes("raw") && typeof f.bodyFile !== "string") throw new UsageError("the raw message kind needs --body-file");
  const derived = subscriptionKey({ principal: "alice", url, name: "incident.created", arguments: { severity: "P1" } });
  if (!derived.ok) throw new Error(`invalid callback URL: ${derived.code}`);
  const subId = typeof f.subscriptionId === "string" ? f.subscriptionId : derived.id;
  const secrets: ActiveSecret[] = [{ secret: seed(secretSeed), current: true }];
  const signKey = typeof f.signingSeedHex === "string" ? webhookSigningKeyFromSeed(seedHex(f.signingSeedHex)) : null;
  const jackKey = typeof f.jackSeedHex === "string" ? webhookSigningKeyFromSeed(seedHex(f.jackSeedHex)) : null;
  let index = 0;
  const randomBytes = (n: number): Uint8Array => {
    const id = derivedId(scenario, index, kinds[index] ?? "event");
    const suffix = id.slice(id.indexOf("_") + 1).replace(/^[^_]+_/, "");
    const bytes = Buffer.from(Array.from({ length: n }, (_, i) => ALPHABET.indexOf(suffix[i % suffix.length]!)));
    return bytes;
  };
  const clockNow = () => readClock(clockFile);
  clockNow();
  const rawBody = kinds.includes("raw") ? readFileSync(str(f, "bodyFile")) : undefined;
  const tlsCa = typeof f.tlsCa === "string" ? f.tlsCa : typeof f.tlsCaDer === "string" ? f.tlsCaDer : undefined;
  const http = transport({ ...f, ...(tlsCa ? { tlsCa } : {}) });
  const verifier = new EndpointVerifier({ transport: http, allowlist: list(f, "allowlist"), now: clockNow });
  const sender = new WebhookSender({ transport: http, verifier, now: clockNow, randomBytes,
    ...(jackKey ? { jack: { aud, signingKey: jackKey } } : {}),
    sleep: async (ms) => { clockWrite(clockFile, clockNow() + Math.ceil(ms / 1000)); } });
  output({ ready: true, role: "sender", callback_url: url, derived_subscription_id: derived.id });
  void (async () => {
    const results = [];
    for (index = 0; index < kinds.length; index += 1) {
      const kind = kinds[index]!;
      let message: OutboundMessage;
      if (kind === "event") message = eventMessage(Buffer.from('{"eventId":"evt_1","name":"incident.created","timestamp":"2026-11-22T09:00:00Z","data":{"incidentId":"INC-1234","severity":"P1"},"cursor":"cursor_xyz"}'), randomBytes);
      else if (kind === "gap") message = gapMessage("cursor_7f3a", randomBytes);
      else if (kind === "terminated") message = terminatedMessage({ code: -32024, message: "Forbidden", data: { reason: "Access revoked" } }, randomBytes);
      else message = { kind: "event", webhookId: derivedId(scenario, index, "raw"), body: rawBody! };
      if (kind === "raw") (message as { webhookId: string }).webhookId = derivedId(scenario, index, "raw");
      const keys: VersionedSigningKey[] = signKey ? [{ key: signKey, current: true }] : [];
      const target = { subscriptionId: subId, principal: "alice", callbackUrl: url, secrets, signingKeys: keys,
        verificationExpiresAt: Math.floor(clockNow()) + 3600 };
      const policy = preflight(url, f);
      const outcome = await sender.deliver(target, message);
      const blocked = policy === "ssrf_blocked_address" || policy === "ssrf_rebinding_blocked";
      results.push({ message: index, kind, webhook_id: message.webhookId, attempts: blocked ? 0 : outcome.attempts,
        accepted: blocked ? false : outcome.accepted, http_status: blocked ? null : outcome.status,
        last_error: blocked ? policy : outcome.lastError });
    }
    output({ event: "result", scenario, role: "sender", callback_url: url, derived_subscription_id: derived.id, results });
  })().catch(fatal);
}
try { main(); } catch (error) { fatal(error); }
