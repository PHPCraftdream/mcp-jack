import { bodyHash } from "./encoding.js";
import { decodeRotationServerSnapshot, encodeRotationServerSnapshot, validateRotationServerSnapshot } from "./rotation-server-state.js";
import type { RotationServerSnapshot } from "./rotation-server-state.js";
import { anchorSnapshot, invalidStore, packBundle, unpackBundle } from "./rotation-store-format.js";
import type { RotationStoreOptions, StoreBundle } from "./rotation-store-format.js";
import type { RotationClockTuple } from "./rotation-trust.js";

const SERVER_DOMAIN = "mcp-jack/server-ring/private-file/v1";

/** Независимый OOB profile плюс opaque handle подписанта anchor key; handle не key authority. */
export interface RotationServerStoreOptions extends RotationStoreOptions {
  readonly anchorReference: string;
}

/** Anchor ring: один checkpoint key с его opaque reference, revision 1, clock ещё не sampled. */
export function anchorServerSnapshot(options: RotationServerStoreOptions): RotationServerSnapshot {
  const trust = anchorSnapshot(options);
  return validateRotationServerSnapshot({ formatVersion: 1, trust,
    signerReferences: [{ kid: trust.checkpoint.kid, reference: options.anchorReference }] }, trust.binding, trust.window, trust.checkpoint);
}

export function encodedServer(snapshot: RotationServerSnapshot, options: RotationStoreOptions): string {
  return Buffer.from(encodeRotationServerSnapshot(snapshot, options.binding, options.window, options.checkpoint)).toString("utf8");
}

export function serverProfile(anchor: RotationServerSnapshot, options: RotationStoreOptions): string {
  return bodyHash(Buffer.from(encodedServer(anchor, options), "utf8"));
}

export function packServer(bundle: StoreBundle): Uint8Array {
  return packBundle(bundle, SERVER_DOMAIN);
}

export function unpackServer(bytes: Uint8Array, options: RotationStoreOptions, profile: string):
  { readonly bundle: StoreBundle; readonly clock: RotationClockTuple; readonly snapshot: RotationServerSnapshot } {
  const { bundle, clock } = unpackBundle(bytes, options, profile, SERVER_DOMAIN);
  const snapshot = decodeRotationServerSnapshot(Buffer.from(bundle.snapshotBytes, "utf8"), options.binding, options.window, options.checkpoint);
  // Copied clock внутри snapshot не опережает authoritative guard.
  if (snapshot.trust.clock.highWater > clock.highWater || snapshot.trust.clock.revision > clock.revision) invalidStore();
  return { bundle, clock, snapshot };
}
