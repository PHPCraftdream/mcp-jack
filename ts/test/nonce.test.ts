/** Tests for NonceStore, ported from Go's nonce_test.go. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { NonceStore } from "../src/server/nonce.js";

test("same nonce wins exactly once", () => {
  const store = new NonceStore();
  let wins = 0;
  for (let i = 0; i < 64; i++) {
    if (!store.checkAndRecord("kidA", "nonceX", 100, 130)) wins++;
  }
  assert.equal(wins, 1);
  assert.equal(store.len(), 1);
});

test("distinct nonces each win once", () => {
  const store = new NonceStore();
  for (let i = 0; i < 64; i++) {
    assert.equal(store.checkAndRecord("kidA", `nonce-${i}`, 100, 130), false);
  }
});

test("boundary now==retainUntil still blocks", () => {
  const store = new NonceStore();
  assert.equal(store.checkAndRecord("kidA", "n1", 100, 130), false);
  assert.equal(store.checkAndRecord("kidA", "n1", 130, 500), true);
});

test("past retention no longer blocks", () => {
  const store = new NonceStore();
  assert.equal(store.checkAndRecord("kidA", "n1", 100, 130), false);
  assert.equal(store.checkAndRecord("kidA", "n1", 131, 500), false);
});

test("replay does not extend retention", () => {
  const store = new NonceStore();
  assert.equal(store.checkAndRecord("kidA", "n1", 100, 130), false);
  // Far-future retainUntil must be rejected without updating stored retention.
  assert.equal(store.checkAndRecord("kidA", "n1", 110, 1000), true);
  // Retention stayed 130, so at now=131 the pair records again.
  assert.equal(store.checkAndRecord("kidA", "n1", 131, 999), false);
});

test("per-kid scoping", () => {
  const store = new NonceStore();
  assert.equal(store.checkAndRecord("kidA", "shared-nonce", 100, 130), false);
  assert.equal(store.checkAndRecord("kidB", "shared-nonce", 100, 130), false);
  assert.equal(store.checkAndRecord("kidA", "shared-nonce", 110, 130), true);
  assert.equal(store.checkAndRecord("kidB", "shared-nonce", 110, 130), true);
  assert.equal(store.len(), 2);
});

test("purge removes expired entries", () => {
  const store = new NonceStore();
  for (let i = 0; i < 500; i++) {
    store.checkAndRecord(`kid-${i}`, `nonce-${i}`, 100, 100);
  }
  assert.equal(store.len(), 500);
  assert.equal(store.purge(101), 500);
  assert.equal(store.len(), 0);
  assert.equal(store.checkAndRecord("kidA", "nonceX", 200, 300), false);
  assert.equal(store.len(), 1);
});

test("lazy purge on checkAndRecord", () => {
  const store = new NonceStore();
  for (let i = 0; i < 10; i++) {
    store.checkAndRecord(`kid-${i}`, `nonce-${i}`, 10, 50);
  }
  // now=60 triggers the lazy purge before recording the new pair.
  assert.equal(store.checkAndRecord("kidNew", "nonceNew", 60, 120), false);
  assert.equal(store.len(), 1);
  // The once-per-second gate does not purge live entries.
  assert.equal(store.checkAndRecord("kidNew2", "nonceNew2", 60, 120), false);
  assert.equal(store.len(), 2);
});
