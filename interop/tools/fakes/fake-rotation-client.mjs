// Self-test only. Minimal stand-in for an SDK interop rotation client;
// emulates the rotation-client harness contract for the rotation matrix
// driver's checks. NO network, NO real signature/record verification: the
// outcome per --step is a contract-faithful state machine persisted in the
// --store file. Usage:
//   node fake-rotation-client.mjs --step <call|refresh|wire|state> --url <u>
//     --aud <aud> --seed-hex <hex> --store <f> --clock-file <f> --anchor <b64u>
//     [--cursor <o>:<h>] [--tool <name>] [--window <s>] [--timeout-ms <ms>]
//
// Harness channel: the driver exports JACK_ROTATION_MODE_FILE pointing at the
// fake peer's mode file; real SDK clients ignore that environment variable.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..', '..');
const DEV = process.env.JACK_ROTATION_DEVIATE ?? '';
const HEAD43 = 'a'.repeat(43);

function parseArgs(argv) {
  const out = {};
  const hasValue = (j) => j < argv.length && !argv[j].startsWith('--');
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const key = argv[i].slice(2);
    if (hasValue(i + 1)) out[key] = argv[++i];
    else out[key] = true;
  }
  return out;
}

// Fixture kids for the harness identities (TEST ONLY seeds, same as the
// matrix driver uses). Needed because the driver's expectations name the
// signing kid (svc before the cutoff, erin from the cutoff onward).
function fixtureKid(name) {
  try {
    const keys = JSON.parse(readFileSync(join(REPO_ROOT, 'spec', 'fixtures', 'keys.json'), 'utf8')).keys;
    return keys.find((k) => k.name === name)?.kid ?? null;
  } catch {
    return null;
  }
}

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
  process.exit(0);
}

function main() {
  const a = parseArgs(process.argv.slice(2));
  const step = a.step ?? '';
  const svcKid = fixtureKid('svc');
  const erinKid = fixtureKid('erin') ?? svcKid;
  const readMode = () => {
    const p = process.env.JACK_ROTATION_MODE_FILE;
    if (!p || !existsSync(p)) return '';
    return readFileSync(p, 'utf8').trim();
  };
  const readClock = () => {
    try { return parseInt(readFileSync(a['clock-file'], 'utf8').trim(), 10); } catch { return 0; }
  };
  const loadStore = () => {
    try { return { head_ordinal: 0, revision: 1, ...JSON.parse(readFileSync(a.store, 'utf8')) }; }
    catch { return { head_ordinal: 0, revision: 1 }; }
  };
  const saveStore = (st) => {
    try { writeFileSync(a.store, JSON.stringify(st) + '\n'); } catch { /* best effort */ }
  };
  // The driver's cutoff is A = T + 172800 with T ~ start time + 120; a client
  // clock at/after now+172800 therefore means the successor key is active.
  const successorActive = () => readClock() >= Math.floor(Date.now() / 1000) + 172800;

  if (step === 'call') {
    const mode = readMode();
    // G9 r1/r2 contract: the server store is latched; the call is refused.
    if (mode === 'clock-rollback') {
      return emit({ scenario: 'call', outcome: 'rejected', http_status: 503, code: 'rotation_state_unavailable', data: null });
    }
    // G9 r4 contract: the client store is latched at open; SDK clients exit
    // nonzero with stderr only, never a JSON line.
    if (mode === 'clock-client-latch') {
      process.stderr.write('rotation store: rotation_clock_unsafe\n');
      process.exit(1);
    }
    // Old-key peer response after the cutoff: must be refused.
    if (mode === 'old-key') {
      if (DEV === 's5-old-key-after-cutoff') {
        return emit({ scenario: 'call', outcome: 'ok', http_status: 200, code: null, data: { signed_by: erinKid } });
      }
      return emit({ scenario: 'call', outcome: 'client_error', http_status: null, code: 'rotation_key_interval', data: null });
    }
    // Deviation hook: the pre-rotation call is wrongly rejected.
    if (DEV === 's1-pre-rotation') {
      const st = loadStore();
      if (!st.s1_rejected) {
        st.s1_rejected = true;
        saveStore(st);
        return emit({ scenario: 'call', outcome: 'rejected', http_status: 401, code: 'bad_signature', data: null });
      }
    }
    return emit({ scenario: 'call', outcome: 'ok', http_status: 200, code: null, data: { signed_by: successorActive() ? erinKid : svcKid } });
  }

  if (step === 'refresh') {
    const mode = readMode();
    const st = loadStore();
    // Tampered page: parseable but proof/kid checks fail -> never committed.
    if (mode === 'page-tamper') {
      if (DEV === 'n5b-tamper-no-commit') {
        // Illegal commit lie: mutate the store as if the tampered page landed.
        st.head_ordinal = 1;
        st.revision = 2;
        saveStore(st);
      }
      return emit({ scenario: 'refresh', outcome: 'client_error', http_status: null, code: 'rotation_record_invalid', data: null });
    }
    st.head_ordinal = 1;
    st.revision = 2;
    saveStore(st);
    const committed = DEV !== 's2-refresh-overlap';
    return emit({
      scenario: 'refresh', outcome: 'ok', http_status: 200, code: null,
      data: { committed, head_ordinal: 1, head_hash: HEAD43, terminal_ordinal: 1, complete: true, revision: 2 },
    });
  }

  if (step === 'wire') {
    // Wrong-tool probe (used as the wrong-audience control) is unauthorized.
    if ((a.tool ?? 'jack.server.key') !== 'jack.server.key') {
      return emit({ scenario: 'wire', outcome: 'rejected', http_status: 401, code: 'bad_signature', data: null });
    }
    const m = /^(\d+):([A-Za-z0-9_-]{43})$/.exec(a.cursor ?? '');
    if (m && parseInt(m[1], 10) >= 1) {
      // Cursor beyond head (2:<h>) and cursor the fresh ring lacks (1:<h>).
      return emit({ scenario: 'wire', outcome: 'rejected', http_status: 409, code: 'rotation_checkpoint_unavailable', data: null });
    }
    return emit({ scenario: 'wire', outcome: 'rejected', http_status: 400, code: 'invalid_params', data: null });
  }

  if (step === 'state') {
    // G9 r5 contract: a restart on a latched store fails closed even with the
    // clock moved forward (no catch-up recovery).
    if (readMode() === 'clock-client-latch') {
      process.stderr.write('rotation store: rotation_clock_unsafe\n');
      process.exit(1);
    }
    const st = loadStore();
    return emit({
      scenario: 'state', outcome: 'ok', http_status: null, code: null,
      data: { head_ordinal: st.head_ordinal ?? 0, head_hash: '-', revision: st.revision ?? 1 },
    });
  }

  emit({ scenario: step || '', outcome: 'client_error', http_status: null, code: 'invalid_params', data: null });
}

main();
