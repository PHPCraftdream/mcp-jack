import type { DurableStoreOptions } from "./durable-store.js";

export interface DurableStoreInternalOptions extends DurableStoreOptions {
  readonly injectTransactionFailure?: (phase: "intent" | "final") => "commit" | "abort" | undefined;
  readonly injectOperationId?: () => string;
}
