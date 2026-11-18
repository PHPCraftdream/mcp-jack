
import { USAGE, fail } from './config.mjs';
// ---- cli --------------------------------------------------------------------

export function parseArgs(argv) {
  const out = { clients: null, servers: null, list: false, keep: false, allowSkipTsServer: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const val = () => {
      i += 1;
      if (i >= argv.length) fail(`missing value for ${flag}\n${USAGE}`);
      return argv[i];
    };
    switch (flag) {
      case '--clients': out.clients = val(); break;
      case '--servers': out.servers = val(); break;
      case '--list': out.list = true; break;
      case '--keep': out.keep = true; break;
      case '--allow-skip-ts-server': out.allowSkipTsServer = true; break;
      default: fail(`unknown flag: ${flag}\n${USAGE}`);
    }
  }
  return out;
}

export function splitLangs(value, all, flag) {
  if (value === null) return [...all];
  const parts = value.split(',').map((s) => s.trim()).filter(Boolean);
  for (const p of parts) {
    if (!all.includes(p)) fail(`unknown ${flag} language '${p}' (known: ${all.join(', ')})\n${USAGE}`);
  }
  return parts;
}
