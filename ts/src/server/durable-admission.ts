/**
 * Durable admission seam (candidate profile, spec/candidate/durable-nonces.md
 * sections 1, 2 and 5), mirroring the Go reference in server/admission.go:
 * reserveDurable runs AFTER the signature verifies and BEFORE any
 * authorization, state change or dispatch, the volatile nonce store is not
 * used for the request, and the reservation's serving lease is released
 * idempotently after the response is produced (Go Result.Done in the
 * middleware). Refusals map one-to-one onto the spec section 5 statuses and
 * codes; replayed_nonce stays unsigned (no nonce-recorded receipt).
 */
import { bodyHash } from "../encoding.js";
import { Code, JackError } from "../errors.js";
import type { RegistryEntry } from "./state.js";
import type { DurableNonceReservation, DurableNonceStore } from "./durable-store.js";
import { DURABLE_MAX_TIMESTAMP } from "./durable-format.js";

/** Whether now is inside the entry's validity interval (spec 02 section 1). */
function entryActive(e: RegistryEntry, now: number): boolean {
  return (
    (e.notBefore === undefined || e.notBefore === null || e.notBefore <= now) &&
    (e.notAfter === undefined || e.notAfter === null || now < e.notAfter)
  );
}

/** Everything the admission needs about one already signature-verified request. */
export interface DurableAdmissionRequest {
  readonly kid: string;
  readonly nonce: string;
  /** Authenticated base64url signature (already decoded and checked once). */
  readonly signature: string;
  /** Exact UTF-8 v1 request signing bytes S. */
  readonly signingBytes: string;
  readonly timestamp: number;
  /** The verifier's configured window; must equal the store's immutable W. */
  readonly window: number;
  /** Registry entry of the caller; undefined for the enrollment exception. */
  readonly caller: RegistryEntry | undefined;
}

/** One durable admission outcome (Go reserveDurable's Result prefix). */
export type DurableAdmissionOutcome =
  | { readonly accepted: true; /** Raw post-commit sample; the request time for authorization. */
      readonly finalNow: number; readonly finish: () => void }
  | { readonly accepted: false; readonly httpStatus: number; readonly code: string; readonly message: string;
      /** True only once the reservation committed (signed refusals). */
      readonly nonceRecorded: boolean; readonly finish: () => void };

/** The verifier-facing seam (Go Config.DurableNonces). */
export interface DurableAdmission {
  reserveForVerify(request: DurableAdmissionRequest): DurableAdmissionOutcome;
}

/** Raw post-commit clock; invalid samples fail closed like the verifier's. */
export interface DurableNonceAdmissionOptions {
  readonly store: DurableNonceStore;
  readonly now: () => number;
}

const noop = (): void => {};

/** Idempotent once-wrapper around the store's own idempotent release. */
function onceRelease(release: () => void): () => void {
  let done = false;
  return (): void => {
    if (done) return;
    done = true;
    release();
  };
}

/**
 * Adapter binding a DurableNonceStore into the verifier. Order of operations
 * per request (spec section 2): the caller captured the immutable key/enrollment
 * snapshot before crypto; the store's validate closure revalidates it at every
 * authoritative sample; reserve() runs its entry/intent/final samples and
 * transactions; one post-commit freshness sample decides dispatch. A stale
 * post-commit sample answers 401 timestamp_out_of_window unsigned-dispatch
 * (never dispatched) and keeps the committed reservation.
 */
export class DurableNonceAdmission implements DurableAdmission {
  constructor(private readonly options: DurableNonceAdmissionOptions) {}

  reserveForVerify(request: DurableAdmissionRequest): DurableAdmissionOutcome {
    const { store, now } = this.options;
    const ts = request.timestamp;
    const window = request.window;
    const outOfWindow = (committed: boolean, finish: () => void): DurableAdmissionOutcome => ({
      accepted: false, httpStatus: 401, code: Code.TIMESTAMP_OUT_OF_WINDOW,
      message: "timestamp is outside the acceptance window", nonceRecorded: committed, finish,
    });
    const unavailable = (committed: boolean, finish: () => void): DurableAdmissionOutcome => ({
      accepted: false, httpStatus: 503, code: "durability_unavailable",
      message: "durable admission is unavailable", nonceRecorded: committed, finish,
    });
    // Signed ts domain / checked expiry (spec section 2 step 3): 401, no reservation.
    if (!Number.isSafeInteger(ts) || ts < 0 || ts > DURABLE_MAX_TIMESTAMP - window) {
      return outOfWindow(false, noop);
    }
    // Immutable snapshot captured before crypto, shallow-copied so a later
    // registry mutation can never reach the validate closure; revalidated at
    // every authoritative sample (spec section 2).
    const caller = request.caller === undefined ? undefined : { ...request.caller };
    const validate = (sample: number): boolean =>
      sample >= 0 && sample <= DURABLE_MAX_TIMESTAMP && (caller === undefined || entryActive(caller, sample));

    let reservation: DurableNonceReservation;
    try {
      reservation = store.reserve({
        kid: request.kid, nonce: request.nonce, signature: request.signature,
        signingBytes: request.signingBytes, timestamp: ts, window, validate,
      });
    } catch (error) {
      if (!(error instanceof JackError)) throw error;
      // Non-definite storage refusals fence out of band (Go definiteStorageRefusal).
      if (error.code === "durability_unavailable" || error.code === "clock_unsafe") store.fence();
      if (error.httpStatus === 401 && (error.code === Code.REPLAYED_NONCE || error.code === Code.TIMESTAMP_OUT_OF_WINDOW)) {
        // Unsigned: no nonce-recorded receipt (spec section 5).
        return { accepted: false, httpStatus: 401, code: error.code,
          message: "request was not admitted", nonceRecorded: false, finish: noop };
      }
      if (error.httpStatus === 503 && ["state_changed", "capacity_exhausted", "clock_unsafe", "durability_unavailable"].includes(error.code)) {
        return { accepted: false, httpStatus: 503, code: error.code,
          message: "durable admission is unavailable", nonceRecorded: false, finish: noop };
      }
      return unavailable(false, noop);
    }
    const finish = onceRelease(reservation.release);
    // Receipt equality against the exact request (Go receiptMatches); any
    // mismatch fences and refuses without dispatch.
    const receipt = reservation.receipt;
    if (receipt.kid !== request.kid || receipt.nonce !== request.nonce || receipt.signature !== request.signature ||
      receipt.timestamp !== ts || receipt.retainUntil !== ts + window ||
      receipt.requestHash !== bodyHash(Buffer.from(request.signingBytes, "utf8"))) {
      store.fence();
      return unavailable(false, finish);
    }
    // One post-commit freshness sample before dispatch (spec section 2);
    // the committed reservation stays whatever this decides.
    const finalNow = now();
    if (!Number.isSafeInteger(finalNow) || finalNow < 0 || finalNow > DURABLE_MAX_TIMESTAMP || finalNow < receipt.highWater) {
      store.fence();
      return unavailable(true, finish);
    }
    if (!validate(finalNow)) {
      return { accepted: false, httpStatus: 503, code: "state_changed",
        message: "verification state changed", nonceRecorded: true, finish };
    }
    const distance = finalNow - ts;
    if (distance > window || -distance > window) {
      return outOfWindow(true, finish);
    }
    return { accepted: true, finalNow, finish };
  }
}

// ---------------------------------------------------------------------------
// Post-response finish plumbing (Go Result.Done called by the middleware).
// finish handles travel WITHOUT changing VerifyResult's public shape: a
// WeakMap keyed by the result object, so zero behaviour change when the
// durable option is absent and no field for deep-equality tests to trip over.
// ---------------------------------------------------------------------------

const resultFinishes = new WeakMap<object, () => void>();

/** Associates the idempotent finish with a VerifyResult (internal). */
export function rememberResultFinish(result: object, finish: (() => void) | undefined): void {
  if (finish === undefined) return;
  resultFinishes.set(result, finish);
}

/** Takes the finish of a VerifyResult, if any (internal; removes the entry). */
export function takeResultFinish(result: object): (() => void) | undefined {
  const finish = resultFinishes.get(result);
  if (finish !== undefined) resultFinishes.delete(result);
  return finish;
}

const responseFinishes = new WeakMap<Response, () => void>();

/** Attaches the finish handle to a produced Response for the node adapter. */
export function markResponseFinish(response: Response, finish: (() => void) | undefined): void {
  if (finish === undefined) return;
  responseFinishes.set(response, finish);
}

/**
 * Finishes the admission after the response is produced/written (Go defer
 * res.Done()); idempotent, and a Response without an association is a no-op,
 * so adapters never change behaviour when the durable option is absent.
 */
export function finishResponseAdmission(response: Response): void {
  responseFinishes.get(response)?.();
}
