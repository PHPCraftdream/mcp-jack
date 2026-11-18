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
