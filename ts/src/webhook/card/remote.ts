import { checkCallbackUrl } from "../ssrf/url.js";

/** The MCP Events extension identifier used in Server Cards (spec 06 R7.1). */
export const EVENTS_EXTENSION = "io.modelcontextprotocol/events";

/** Whether two valid HTTPS URLs share a host and effective port (spec 06 R7.2). */
export function sameOrigin(a: string, b: string): boolean {
  const left = checkCallbackUrl(a);
  const right = checkCallbackUrl(b);
  return left.ok && right.ok && left.host === right.host && left.port === right.port;
}

/** The default Server Card URL, or null when the MCP URL is not valid HTTPS (spec 06 R7.2). */
export function defaultCardUrl(mcpUrl: string): string | null {
  const checked = checkCallbackUrl(mcpUrl);
  if (!checked.ok) return null;
  const port = checked.port === 443 ? "" : `:${checked.port}`;
  const path = checked.path.length > 1 && checked.path.endsWith("/") ? checked.path.slice(0, -1) : checked.path;
  return `https://${checked.host}${port}${path === "/" ? "" : path}/server-card`;
}

/** The matching Server Card remote, or a refusal when there is no same-origin candidate. */
export type RemoteSelection =
  | { readonly ok: true; readonly remote: Record<string, unknown> }
  | { readonly ok: false; readonly code: "no_remote" };

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" ? (value as Record<string, unknown>) : null;
}

function member(value: unknown, name: string): unknown {
  return (value as Record<string, unknown> | null | undefined)?.[name];
}

/** Selects by exact path, longest path prefix, then origin, keeping document order on ties (spec 06 R7.1). */
export function selectRemote(card: unknown, { mcpUrl }: { readonly mcpUrl: string }): RemoteSelection {
  const target = checkCallbackUrl(mcpUrl);
  if (!target.ok) return { ok: false, code: "no_remote" };
  const candidates = member(card, "remotes");
  const remotes: readonly unknown[] = Array.isArray(candidates) ? candidates : [];
  let best: Record<string, unknown> | null = null;
  let bestTier = 0;
  let bestLength = -1;
  for (const entry of remotes) {
    const remote = record(entry);
    if (remote === null || typeof remote.url !== "string" || remote.url.includes("{")) continue;
    const checked = checkCallbackUrl(remote.url);
    if (!checked.ok || checked.host !== target.host || checked.port !== target.port) continue;
    let tier = 1;
    let length = 0;
    if (checked.path === target.path) {
      tier = 3;
    } else if (target.path.startsWith(checked.path)) {
      tier = 2;
      length = checked.path.length;
    }
    if (tier > bestTier || (tier === bestTier && length > bestLength)) {
      best = remote;
      bestTier = tier;
      bestLength = length;
    }
  }
  return best === null ? { ok: false, code: "no_remote" } : { ok: true, remote: best };
}

/** The selected remote's signing-key data, raw JWK entries, advisory egress ranges and original URL. */
export type WebhookInfo =
  | {
      readonly ok: true;
      readonly signingKeys: unknown;
      readonly cardKeys: readonly unknown[];
      readonly egressIpRanges: readonly unknown[];
      readonly remoteUrl: string;
    }
  | { readonly ok: false; readonly code: "no_remote" };

/** Reads webhook metadata without inferring Events support from its presence (spec 06 R7.1). */
export function webhookInfo(card: unknown, options: { readonly mcpUrl: string }): WebhookInfo {
  const selected = selectRemote(card, options);
  if (!selected.ok) return selected;
  const extension = member(selected.remote.extensionsInfo, EVENTS_EXTENSION);
  const webhooks = record(member(extension, "webhooks"));
  const ranges = webhooks?.egressIpRanges;
  const signingKeys = record(webhooks?.signingKeys);
  const keys = signingKeys?.keys;
  return {
    ok: true,
    signingKeys,
    cardKeys: Array.isArray(keys) ? keys : [],
    egressIpRanges: Array.isArray(ranges) ? ranges : [],
    remoteUrl: selected.remote.url as string,
  };
}
