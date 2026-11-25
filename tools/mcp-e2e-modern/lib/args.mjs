import {
  CLIENTS, DEADLINES, PATHS, SERVERS, TIMEOUT_FLAGS, resolveConfig,
} from './config.mjs';

export const usage = 'usage: node tools/mcp-e2e-modern/run.mjs [--clients go,ts] [--servers go,ts] [--paths direct,bridge-modern,bridge-auto-both,scripted-control] [--jack-bin <path>] [--artifacts <dir>] [--list] [--self-test] [--keep]';

const arrays = { clients: CLIENTS, servers: SERVERS, paths: PATHS };

export function parseArgs(argv) {
  const flags = { clients: [...CLIENTS], servers: [...SERVERS], paths: [...PATHS], ...resolveConfig(), list: false, selfTest: false, keep: false };
  const errors = [];
  const timeoutFlags = Object.fromEntries(Object.entries(TIMEOUT_FLAGS).map(([key, name]) => [name, key]));
  const value = (i, flag) => {
    if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) {
      errors.push(`missing value for ${flag}`);
      return [null, i];
    }
    return [argv[i + 1], i + 1];
  };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    if (flag in timeoutFlags) {
      const [raw, next] = value(i, flag); i = next;
      if (raw === null) continue;
      if (!/^\d+$/.test(raw) || Number(raw) < 1) errors.push(`invalid value for ${flag}: ${raw}`);
      else flags[timeoutFlags[flag]] = Number(raw);
    } else if (flag === '--jack-bin' || flag === '--artifacts' || flag === '--clients' || flag === '--servers' || flag === '--paths') {
      const [raw, next] = value(i, flag); i = next;
      if (raw === null) continue;
      if (flag === '--jack-bin') flags.jackBin = raw;
      else if (flag === '--artifacts') flags.artifacts = raw;
      else {
        const key = flag.slice(2);
        const allowed = arrays[key];
        const parts = raw.split(',').map((part) => part.trim());
        if (parts.some((part) => !part || !allowed.includes(part))) errors.push(`invalid ${flag} value: ${raw}`);
        else flags[key] = [...new Set(parts)];
      }
    } else if (flag === '--list') flags.list = true;
    else if (flag === '--self-test') flags.selfTest = true;
    else if (flag === '--keep') flags.keep = true;
    else errors.push(`unknown flag: ${flag}`);
  }
  if (!flags.clients.length || !flags.servers.length || !flags.paths.length) errors.push('client, server, and path selections must not be empty');
  return { flags: Object.freeze(flags), errors };
}
