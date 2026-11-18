import { Code, JackError } from "../core/errors.js";
import { decodeRotationServerKeyArguments, rotationServerKeyPage, validateRotationServerKeyCursor } from "../rotation/snapshot/server-key.js";
import type { RotationServerProvider } from "../rotation/server/provider.js";
import type { RotationServerStore } from "../rotation/server/store.js";
import { TOOL_SERVER_KEY } from "./verify.js";
import type { NativeCall, NativeResult, NativeTools } from "./verify.js";

// TOOL_SERVER_KEY ("jack.server.key") lives in verify.ts next to the other TOOL_* constants.

function refusal(status: number, code: string): JackError {
  return new JackError(status, code, "server key request unavailable");
}

/**
 * Serves only the explicit candidate route `jack.server.key`, never forwards the request further.
 * One committed snapshot, a fresh server ClockGuard, and the selected signer; page fields are not mixed.
 * Errors: 403 operation_denied, 400 invalid_params, 409 rotation_checkpoint_unavailable,
 * 503 rotation_state_unavailable; storage/signer details are never exposed.
 */
export class ServerKeyTool implements NativeTools {
  constructor(private readonly store: RotationServerStore, private readonly provider: RotationServerProvider) {}

  call(c: NativeCall): NativeResult {
    if (c.tool !== TOOL_SERVER_KEY || c.caller === undefined) throw refusal(403, Code.OPERATION_DENIED);
    let cursor: ReturnType<typeof decodeRotationServerKeyArguments>;
    try { cursor = decodeRotationServerKeyArguments(c.arguments); }
    catch { throw refusal(400, Code.INVALID_PARAMS); }
    let release: () => void;
    try { release = this.store.acquireServingLease(); }
    catch { throw refusal(503, "rotation_state_unavailable"); }
    try {
      const { snapshot } = this.store.snapshot();
      if (c.aud !== snapshot.trust.binding.aud) throw refusal(503, "rotation_state_unavailable");
      try { validateRotationServerKeyCursor(snapshot, cursor); }
      catch { throw refusal(409, "rotation_checkpoint_unavailable"); }
      // All proof/hash operations complete before the authoritative sample.
      const signer = this.provider.selectSigner(snapshot, this.store.checkSnapshotClock(snapshot));
      return { structured: rotationServerKeyPage(snapshot, cursor, signer.publicKeyB64u) };
    } catch (error) {
      if (error instanceof JackError) throw error;
      throw refusal(503, "rotation_state_unavailable");
    } finally {
      release();
    }
  }
}
