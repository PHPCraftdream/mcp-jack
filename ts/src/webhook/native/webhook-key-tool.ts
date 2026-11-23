import { Code, JackError } from "../../core/errors.js";
import { TOOL_WEBHOOK_KEY } from "../../server/verify.js";
import type { NativeCall, NativeResult, NativeTools } from "../../server/verify.js";

export { TOOL_WEBHOOK_KEY };

/** The configured webhook JWK set and advisory egress ranges to publish. */
export interface WebhookKeyToolOptions {
  readonly signingKeys: { readonly keys: readonly unknown[] };
  readonly egressIpRanges?: readonly string[];
}

/** Publishes exactly the configured key set. A receiver MAY require the R7.6 cross-check with the Server Card. */
export class WebhookKeyTool implements NativeTools {
  constructor(private readonly options: WebhookKeyToolOptions) {}

  /** Returns the configured JWKs as given, and only to an authenticated caller. */
  call(c: NativeCall): NativeResult {
    if (c.caller === undefined || c.tool !== TOOL_WEBHOOK_KEY) {
      throw new JackError(403, Code.OPERATION_DENIED, "operation is not permitted");
    }
    const { signingKeys, egressIpRanges = [] } = this.options;
    return {
      structured: {
        webhook_key: {
          signing_keys: { keys: signingKeys.keys },
          egress_ip_ranges: egressIpRanges,
        },
      },
    };
  }
}
