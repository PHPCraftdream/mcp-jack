import type { HeaderPairs, WebhookReceiver } from "./core.js";

/** The default maximum size of a raw webhook body, in bytes (R1.2). */
export const MAX_BODY_BYTES = 262144;

/** A Node webhook request with repeated headers and a raw body stream. */
export interface NodeWebhookRequest {
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly body: AsyncIterable<Uint8Array>;
}

/** The HTTP response to write for a Node webhook request. */
export interface NodeWebhookResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

/** The buffered raw body or a refusal because it exceeded the byte limit. */
export type BodyRead = { readonly ok: true; readonly body: Uint8Array } | { readonly ok: false };

/** Stops at the first oversized chunk without closing the stream, so Node can still send a 413. */
export async function readBoundedBody(
  stream: AsyncIterable<Uint8Array>,
  maxBodyBytes = MAX_BODY_BYTES,
): Promise<BodyRead> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const iterator = stream[Symbol.asyncIterator]();
  for (let next = await iterator.next(); !next.done; next = await iterator.next()) {
    const chunk = next.value;
    total += chunk.byteLength;
    if (total > maxBodyBytes) return { ok: false };
    if (chunk.byteLength > 0) chunks.push(Uint8Array.from(chunk));
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, body };
}

function response(status: number, body: Record<string, unknown>): NodeWebhookResponse {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (status === 401) headers["www-authenticate"] = "Webhook-Signature";
  return { status, headers, body: JSON.stringify(body) };
}

function bodyTooLarge(): NodeWebhookResponse {
  return response(413, { error: { code: "body_too_large", message: "body or declared length above the limit" } });
}

/**
 * Bounds the raw body and serializes the receiver's response. The adapter never discards
 * forwarded messages and only answers 2xx for them after the application's enqueue resolves.
 */
export async function adaptNodeRequest(receiver: WebhookReceiver, request: NodeWebhookRequest & {
  readonly now: number;
  readonly maxBodyBytes?: number;
}): Promise<NodeWebhookResponse> {
  const { now, maxBodyBytes = MAX_BODY_BYTES } = request;
  const entries = Object.entries(request.headers);
  for (const [name, value] of entries) {
    if (name.toLowerCase() !== "content-length" || value === undefined) continue;
    const lengths = typeof value === "string" ? [value] : value;
    if (lengths.some((length) => /^[0-9]+$/.test(length) && Number(length) > maxBodyBytes)) {
      return bodyTooLarge();
    }
  }
  const read = await readBoundedBody(request.body, maxBodyBytes);
  if (!read.ok) return bodyTooLarge();

  const headers: HeaderPairs[number][] = [];
  for (const [name, value] of entries) {
    if (typeof value === "string") headers.push([name, value]);
    else if (value !== undefined) {
      for (const entry of value) headers.push([name, entry]);
    }
  }
  const { status, body } = await receiver.handle({ now, headers, body: read.body });
  return response(status, body);
}

/** Handles a streaming request and an optional clock value in Unix seconds. */
export type ReceiverNodeHandler = (request: NodeWebhookRequest, now?: number) => Promise<NodeWebhookResponse>;

/** Creates a streaming handler with optional clock and body-size limit overrides. */
export function createNodeHandler(receiver: WebhookReceiver, options?: {
  readonly now?: () => number;
  readonly maxBodyBytes?: number;
}): ReceiverNodeHandler {
  const { now: clock, maxBodyBytes } = options ?? {};
  return (request, now = Date.now() / 1000) => adaptNodeRequest(receiver, {
    ...request,
    now: clock?.() ?? now,
    ...(maxBodyBytes === undefined ? {} : { maxBodyBytes }),
  });
}
