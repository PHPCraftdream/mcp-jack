// Harness-only fake: implements the sign-only client contract minimally so the
// durable.mjs self-test can run the whole matrix without any SDK. NOT SDK
// evidence. Prints the canonical one-line JSON result and exits 0.
// Deviation hook: with JACK_FAKE_DEVIATE=nonce-mismatch the emitted header
// carries a nonce that does NOT match the --nonce argument (a harness contract
// violation, exit 2).
import { randomBytes } from 'node:crypto';

const args = process.argv.slice(2);
const value = (name) => {
  const i = args.indexOf(`--${name}`);
  return i !== -1 && i + 1 < args.length ? args[i + 1] : '';
};
const ts = value('ts');
let nonce = value('nonce');
if (!ts || !nonce) {
  process.stderr.write('fake-durable-client: --ts and --nonce are required\n');
  process.exit(1);
}
if (process.env.JACK_FAKE_DEVIATE === 'nonce-mismatch') nonce = randomBytes(16).toString('base64url');
const result = {
  scenario: 'sign-only',
  outcome: 'ok',
  http_status: 200,
  code: null,
  data: { signing_string: '', jack_auth: `FAKE ${ts} ${nonce} dev`, kid: 'fake' },
};
process.stdout.write(JSON.stringify(result) + '\n');
process.exit(0);
