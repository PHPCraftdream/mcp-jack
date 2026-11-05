/**
 * Replay protection: a (kid, nonce) cache with caller-supplied retention and purge.
 * Times are Unix seconds supplied by the caller; the store never reads a clock
 * (spec 01). Same polarity as the Go and Rust SDKs: checkAndRecord returns
 * true on a live replay and false when the pair was recorded as fresh.
 */
export class NonceStore {
  private readonly seen = new Map<string, number>();
  private lastPurge = 0;

  /**
   * Returns true when (kid, nonce) is a live replay, leaving the stored
   * retention unchanged (a replay must not extend retention); otherwise records
   * the pair and returns false.
   * Expired entries are purged lazily, at most once per second of the
   * injected `now`.
   */
  checkAndRecord(kid: string, nonce: string, now: number, retainUntil: number): boolean {
    // JS is single-threaded and this method is synchronous, so Go's mutex has
    // no TS counterpart.
    // A full scan on every request would be quadratic in the number of live
    // entries; expired entries are never consulted (the liveness test below is
    // explicit), so purging once per second of injected now bounds memory.
    if (now > this.lastPurge) {
      // Deleting the current entry while iterating a Map is safe in JS.
      for (const [key, until] of this.seen) {
        if (until < now) this.seen.delete(key);
      }
      this.lastPurge = now;
    }
    const until = this.seen.get(kid + "\x00" + nonce);
    if (until !== undefined && now <= until) return true;
    this.seen.set(kid + "\x00" + nonce, retainUntil);
    return false;
  }

  /**
   * Deletes every entry with retainUntil < now and returns how many were
   * deleted. Does not touch the lazy-purge bookkeeping (Go parity).
   */
  purge(now: number): number {
    let deleted = 0;
    // Safe to delete the current entry during Map iteration.
    for (const [key, until] of this.seen) {
      if (until < now) {
        this.seen.delete(key);
        deleted++;
      }
    }
    return deleted;
  }

  /** Number of held entries, including expired ones not yet purged. */
  len(): number {
    return this.seen.size;
  }
}
