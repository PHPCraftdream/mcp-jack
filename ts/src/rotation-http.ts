import { parseRequestAuth } from "./auth-header.js";
import { randomNonce, signRequest } from "./client/auth.js";
import type { Signer } from "./client/signer.js";
import { checkDestination } from "./client/url-policy.js";
import { JackError } from "./errors.js";
import { RotationController } from "./rotation-controller.js";
import type { RotationRefreshResult, RotationResponse } from "./rotation-controller.js";
import { RotationDeadline, exchange, requestError } from "./rotation-http-wire.js";
import { RotationError, ROTATION_MAX_ORDINAL } from "./rotation-record.js";
import { ROTATION_MAX_RETAINED_KEYS } from "./rotation-chain.js";
import { RotationTrustStore } from "./rotation-store.js";
import { encodeRotationTrustSnapshot } from "./rotation-trust-json.js";
import type { RotationTrustSnapshot } from "./rotation-trust.js";

export interface RotationHTTPReply {
  readonly status: number;
  readonly body: Uint8Array;
}

function mapped(error: unknown): JackError {
  return requestError(error instanceof JackError || error instanceof RotationError ? error.code : "rotation_request_unavailable");
}

function capacity(snapshot: RotationTrustSnapshot, now: number): void {
  if (snapshot.revision < 1 || snapshot.revision > ROTATION_MAX_ORDINAL || snapshot.keys.length > ROTATION_MAX_RETAINED_KEYS) throw requestError("rotation_state_changed");
  let pending = 0;
  let retired = 0;
  for (const key of snapshot.keys) {
    if (key.notBefore > now) pending++;
    else if (key.knownCutoff !== null && key.knownCutoff <= now) retired++;
  }
  if (pending > 128 || retired > 1024) throw requestError("rotation_state_changed");
}

/** Candidate single-attempt POST client; caller владеет store и явным refresh. */
export class RotationHTTPClient {
  private readonly controller: RotationController;
  private readonly endpoint: URL;
  private readonly target: string;
  private readonly profile: Pick<RotationTrustSnapshot, "binding" | "window" | "checkpoint">;

  constructor(private readonly store: RotationTrustStore, private readonly signer: Signer, private readonly timeoutMs: number) {
    try {
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw requestError("rotation_state_unknown");
      const snapshot = store.snapshot().snapshot;
      this.profile = Object.freeze({ binding: snapshot.binding, window: snapshot.window, checkpoint: snapshot.checkpoint });
      const raw = this.profile.binding.endpoint;
      checkDestination(raw);
      this.endpoint = new URL(raw);
      const authority = /^[A-Za-z]+:\/\/[^/?#]+/.exec(raw)?.[0];
      if (authority === undefined) throw requestError("rotation_state_unknown");
      const suffix = raw.slice(authority.length).split("#", 1)[0] ?? "";
      this.target = suffix.startsWith("/") ? suffix : "/" + suffix;
      this.controller = new RotationController(store);
    } catch (error) {
      throw requestError(error instanceof JackError || error instanceof RotationError ? error.code : "rotation_state_unknown");
    }
  }

  private encoded(snapshot: RotationTrustSnapshot): Buffer {
    return Buffer.from(encodeRotationTrustSnapshot(snapshot, this.profile.binding, this.profile.window, this.profile.checkpoint));
  }

  private async send(body: Uint8Array, limit: number, deadline: RotationDeadline, expected?: RotationTrustSnapshot): Promise<RotationResponse> {
    deadline.check();
    if (!(body instanceof Uint8Array) || body.length > 1024 * 1024) throw requestError("rotation_result_invalid");
    const owned = Buffer.from(body);
    const snapshot = this.store.snapshot().snapshot;
    if (expected !== undefined && !this.encoded(snapshot).equals(this.encoded(expected))) throw requestError("rotation_state_changed");
    const clock = this.store.checkSnapshotClock(snapshot);
    capacity(snapshot, clock.highWater);
    const header = signRequest(this.signer, this.profile.binding.aud, "POST", this.target, owned, randomNonce(), clock.highWater);
    const auth = parseRequestAuth([header]);
    // Signer callback не даёт отправить request после потери store lifetime.
    const dispatch = this.store.checkSnapshotClock(snapshot);
    capacity(snapshot, dispatch.highWater);
    if (Math.abs(dispatch.highWater - auth.ts) > this.profile.window) throw requestError("timestamp_out_of_window");
    deadline.check();
    return exchange(this.endpoint, this.target, header, auth.sig, owned, limit, deadline);
  }

  /** Ровно один POST; ordinary response не расширяет trust автоматически. */
  async call(body: Uint8Array, signal?: AbortSignal): Promise<RotationHTTPReply> {
    const deadline = new RotationDeadline(this.timeoutMs, signal);
    try {
      const response = await this.send(body, 1024 * 1024, deadline);
      deadline.check();
      const verified = this.controller.verifyResponse(response);
      deadline.check();
      return Object.freeze({ status: response.status, body: verified });
    } catch (error) { throw mapped(error); }
    finally { deadline.close(); }
  }

  /** Одна explicit страница от ACKed cursor; никакой pagination/retry. */
  async refresh(signal?: AbortSignal): Promise<RotationRefreshResult> {
    const deadline = new RotationDeadline(this.timeoutMs, signal);
    try {
      deadline.check();
      const snapshot = this.store.snapshot().snapshot;
      const body = Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
        params: { name: "jack.server.key", arguments: { after_ordinal: snapshot.head.ordinal, after_hash: snapshot.head.hash } } }));
      const response = await this.send(body, 256 * 1024, deadline, snapshot);
      deadline.check();
      const result = this.controller.acceptRefresh(response, 1, snapshot.head);
      deadline.check();
      return result;
    } catch (error) { throw mapped(error); }
    finally { deadline.close(); }
  }
}
