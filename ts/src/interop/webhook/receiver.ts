import { createServer } from "node:https";
import { readFileSync } from "node:fs";
import { canonicalUrl, defaultCardUrl, WebhookReceiver, parseWebhookBody, fetchDecision } from "../../webhook/index.js";
import { encodeBase64URL } from "../../core/encoding.js";
import type { HeaderPairs, ReceiverSecret } from "../../webhook/index.js";
import { fatal, output, parse, readClock, seed, str, UsageError } from "./common.js";

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") { const record = value as Record<string, unknown>; return `{${Object.keys(record).sort().map((k) => `${JSON.stringify(k)}:${canonical(record[k])}`).join(",")}}`; }
  return JSON.stringify(value) ?? "null";
}

function main(): void {
  const f = parse(process.argv.slice(2), [], ["--pending-secret", "--enforce-server-identity", "--require-jack"]);
  const allowed = ["port", "tlsCert", "tlsKey", "clockFile", "secretSeed", "subscriptionId", "callbackUrl", "aud", "cardFile", "cardMcpUrl", "mcpServerKid", "enqueueFail", "pendingSecret", "enforceServerIdentity", "requireJack"];
  for (const key of Object.keys(f)) if (!allowed.includes(key)) throw new UsageError(`unknown flag: --${key}`);
  const port = Number(str(f, "port"));
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("--port must be an integer in 0..65535");
  const clockFile = str(f, "clockFile"), subscriptionId = str(f, "subscriptionId"), callbackUrl = str(f, "callbackUrl"), aud = str(f, "aud");
  readClock(clockFile);
  const callback = canonicalUrl(callbackUrl); if (!callback.ok) throw new Error(`invalid callback URL: ${callback.code}`);
  let failCount = Number(typeof f.enqueueFail === "string" ? f.enqueueFail : "0");
  if (!Number.isSafeInteger(failCount) || failCount < 0) throw new Error("--enqueue-fail must be a non-negative integer");
  const pending = f.pendingSecret === true;
  const secrets: ReceiverSecret[] = [{ secret: seed(str(f, "secretSeed")), ...(pending ? { callbackUrl } : { subscriptionId }) }];
  let acceptedKeys: readonly unknown[] = [];
  if (typeof f.cardFile === "string") {
    const doc = JSON.parse(readFileSync(f.cardFile, "utf8"));
    const mcpUrl = str(f, "cardMcpUrl");
    const derived = canonicalUrl(mcpUrl); if (!derived.ok) throw new Error("invalid --card-mcp-url");
    const cardUrl = defaultCardUrl(mcpUrl); if (cardUrl === null) throw new Error("invalid --card-mcp-url");
    const decision = fetchDecision({ mcpUrl, cardUrl, response: { status: 200, headers: { "content-type": "application/mcp-server-card+json" }, bodyB64u: encodeBase64URL(Buffer.from(JSON.stringify(doc))) },
      ...(typeof f.mcpServerKid === "string" ? { mcpServerKid: f.mcpServerKid } : {}) });
    if (decision.ok) acceptedKeys = decision.keys;
  }
  let enqueued = 0, failures = failCount, seq = 0;
  const forwarded: string[][] = [];
  const receiver = new WebhookReceiver({ secrets, routed: pending ? [] : [subscriptionId], enforceServerIdentity: f.enforceServerIdentity === true,
    mcpServerKid: typeof f.mcpServerKid === "string" ? f.mcpServerKid : null,
    keys: acceptedKeys as import("../../webhook/crypto/signatures.js").AcceptedWebhookKey[], webhookKeyCheck: "ignore",
    ...(f.requireJack === true ? { jack: { aud, callbackUrls: { [subscriptionId]: callbackUrl } } } : {}),
    enqueue: async (messages) => { if (failures > 0) { failures -= 1; throw new Error("enqueue failed"); }
      for (const message of messages) { const bytes = Buffer.from(canonical(message)); enqueued += 1; forwarded.push([encodeBase64URL(bytes)]); }
    } });
  const known = receiver.snapshot().routed.includes(subscriptionId);
  const cert = readFileSync(str(f, "tlsCert")), key = readFileSync(str(f, "tlsKey"));
  const listener = createServer({ cert, key }, (req, res) => {
    void (async () => {
      const path = new URL(req.url ?? "/", "https://local.invalid").pathname;
      if (req.method !== "POST" || path !== new URL(callbackUrl).pathname) {
        const body = Buffer.from(JSON.stringify({ error: { code: "no_route", message: "not a delivery endpoint" } }));
        res.writeHead(404, { "content-type": "application/json", "content-length": String(body.length), connection: "close" }); res.end(body); return;
      }
      const rawHeaders = req.rawHeaders;
      const headers: [string, string][] = [];
      for (let i = 0; i + 1 < rawHeaders.length; i += 2) if (!/^(connection|transfer-encoding)$/i.test(rawHeaders[i]!)) headers.push([rawHeaders[i]!, rawHeaders[i + 1]!]);
      const declared = headers.filter(([n]) => n.toLowerCase() === "content-length").map(([, v]) => v);
      let body = Buffer.alloc(0), oversized = declared.some((v) => /^[0-9]+$/.test(v) && Number(v) > 262144);
      if (!oversized) {
        const chunks: Buffer[] = []; let size = 0;
        for await (const chunk of req) { const b = Buffer.from(chunk); size += b.length; if (size > 262144) { oversized = true; break; } chunks.push(b); }
        if (!oversized) body = Buffer.concat(chunks);
      }
      const now = readClock(clockFile);
      const result = oversized
        ? { status: 413, body: { error: { code: "body_too_large", message: "body or declared length above the limit" } }, code: "body_too_large", delivered: [], recorded: false }
        : await receiver.handle({ now, headers: headers as HeaderPairs, body });
      const payload = Buffer.from(JSON.stringify(result.body));
      res.writeHead(result.status, { "content-type": "application/json", "content-length": String(payload.length), connection: "close", ...(result.status === 401 ? { "www-authenticate": "Webhook-Signature" } : {}) }); res.end(payload);
      const parsed = result.status >= 400 && result.code !== "enqueue_failed" ? null : parseWebhookBody(body);
      const obj = result.body as Record<string, unknown>;
      const kind = typeof obj.challenge === "string" ? "verification" : result.delivered[0] ? parsed?.ok ? parsed.envelope.type ?? "event" : null : result.code === "enqueue_failed" || result.code === "subscription_terminated" || result.code === "subscription_not_routed" ? parsed?.ok ? parsed.envelope.type ?? "event" : null : null;
      const bodyStatus = obj.status === "accepted" || obj.status === "duplicate" ? obj.status : typeof obj.challenge === "string" ? "challenge" : null;
      const h = Object.fromEntries(headers.filter(([n]) => ["webhook-id", "webhook-timestamp", "x-mcp-subscription-id"].includes(n.toLowerCase())).map(([n, v]) => [n.toLowerCase(), v]));
      const thisForwarded = result.delivered.map((m) => encodeBase64URL(Buffer.from(canonical(m))));
      output({ event: "delivery", seq: seq++, status: result.status, code: result.code, body_status: bodyStatus, kind,
        webhook_id: h["webhook-id"] ?? null, subscription_id: h["x-mcp-subscription-id"] ?? null, webhook_timestamp: h["webhook-timestamp"] ?? null,
        challenge: typeof obj.challenge === "string" ? obj.challenge : null, enqueued, forwarded: thisForwarded, headers, body_b64u: encodeBase64URL(body) });
    })().catch((error) => { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); res.destroy(); });
  });
  listener.once("error", (error: Error) => { process.stderr.write(`${error.message}\n`); process.exit(1); });
  listener.listen(port, "127.0.0.1", () => {
    const address = listener.address(); const actual = typeof address === "object" && address ? address.port : port;
    output({ ready: true, role: "receiver", port: actual, subscription_id: subscriptionId, subscription_known: known });
  });
  const stop = () => listener.close(() => process.exit(0));
  process.on("SIGTERM", stop); process.on("SIGINT", stop); process.stdin.on("end", stop); process.stdin.resume();
}
try { main(); } catch (error) { fatal(error); }
