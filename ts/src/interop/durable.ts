// Durable nonce store wiring for the interop server: validation of the
// --durable-dir / --durable-window / --durable-init flags, the --durable-init
// out-of-band initialization and the serve-mode store open. When --durable-dir
// is absent every path here is bypassed by server.ts (zero behaviour change).
import { join } from "node:path";
import { DurableNonceAdmission } from "../server/durable/admission.js";
import { DurableNonceStore } from "../server/durable/store.js";

/** Validated durable options of one process. */
export interface DurableSettings {
  readonly dir: string;
  readonly window: number;
}

/** Opened store plus its verifier-facing admission seam. */
export interface DurableHandle {
  readonly store: DurableNonceStore;
  readonly admission: DurableNonceAdmission;
  readonly window: number;
}

/** The store FILE path under the durable directory. */
function storePath(dir: string): string {
  return join(dir, "nonces");
}

/** Validates --durable-window: decimal integer, 1..120 seconds. */
export function parseDurableWindow(text: string): number {
  if (!/^[0-9]+$/.test(text)) {
    throw new Error("--durable-window must be an integer number of seconds");
  }
  const window = Number(text);
  if (!Number.isSafeInteger(window) || window < 1 || window > 120) {
    throw new Error("--durable-window must be between 1 and 120 seconds");
  }
  return window;
}

/**
 * Validates the durable flags; undefined when --durable-dir is absent (the
 * window text is still validated so a stray --durable-window fails startup).
 */
export function durableSettings(durableDir: string, durableWindow: string): DurableSettings | undefined {
  const window = parseDurableWindow(durableWindow);
  if (durableDir === "") return undefined;
  return { dir: durableDir, window };
}

/**
 * --durable-init: initialize an unused store for the deployment and exit.
 * Throws on any error; the caller reports it on stderr without stdout output.
 */
export function durableInit(settings: DurableSettings, deploymentId: string): void {
  DurableNonceStore.initializeUnused(storePath(settings.dir), { deploymentId, window: settings.window });
}

/**
 * Opens the store for serve mode. Throws on failure (dirty store after a
 * crash, owner marker left by a killed process, deployment/window mismatch);
 * the caller must fail startup BEFORE any ready line.
 */
export function durableOpen(settings: DurableSettings, deploymentId: string, now: () => number): DurableHandle {
  const store = DurableNonceStore.open(storePath(settings.dir), { deploymentId, window: settings.window });
  return { store, admission: new DurableNonceAdmission({ store, now }), window: settings.window };
}
