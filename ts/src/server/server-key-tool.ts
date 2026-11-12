import { Code, JackError } from "../errors.js";
import { decodeRotationServerKeyArguments, rotationServerKeyPage, validateRotationServerKeyCursor } from "../rotation-server-key.js";
import type { RotationServerProvider } from "../rotation-server-provider.js";
import type { RotationServerStore } from "../rotation-server-store.js";
import type { NativeCall, NativeResult, NativeTools } from "./verify.js";

/** Candidate read-only tool; не входит в 11 current-v1 native tools и не достижим через Native. */
export const TOOL_SERVER_KEY = "jack.server.key";

function refusal(status: number, code: string): JackError {
  return new JackError(status, code, "server key request unavailable");
}

/**
 * Обслуживает только явный candidate route `jack.server.key`, никогда не передаёт запрос дальше.
 * Один committed snapshot, свежий server ClockGuard и выбранный signer; поля страницы не смешиваются.
 * Ошибки: 403 operation_denied, 400 invalid_params, 409 rotation_checkpoint_unavailable,
 * 503 rotation_state_unavailable; подробности storage/signer наружу не попадают.
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
      // Все proof/hash операции завершены до authoritative sample.
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
