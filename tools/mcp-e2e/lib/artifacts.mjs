import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT, TS_DIR, GO_DIR, RUST_DIR, fail } from './config.mjs';

// ---- artifact resolution -----------------------------------------------------------

// env override probe: {set, ok, path} so "set but missing" can downgrade the
// whole language to SKIP-able unavailability instead of silently building.
export function envArtifact(name) {
  const v = process.env[name];
  if (v === undefined || v === '') return { set: false, ok: false, path: null };
  return { set: true, ok: existsSync(v), path: v };
}

// Prebuilt probe for rust release binaries; cargo emits '<name>.exe' on Windows.
export function probeRustBinary(base) {
  if (existsSync(base)) return base;
  if (process.platform === 'win32' && existsSync(`${base}.exe`)) return `${base}.exe`;
  return null;
}

export function buildOr(cmd, args, cwd, what) {
  process.stderr.write(`building ${what}: ${cmd} ${args.join(' ')} (cwd ${cwd})\n`);
  try {
    execFileSync(cmd, args, { cwd, stdio: 'pipe' });
  } catch (e) {
    const tail = e.stderr ? e.stderr.toString().trim() : '';
    fail(`${what} build failed:\n${tail !== '' ? tail : e.message}`);
  }
}

export function resolveGoFixtures(ensureBuildDir, event) {
  const client = envArtifact('GO_CLIENT_BIN');
  const server = envArtifact('GO_SERVER_BIN');
  const envReason = client.set && !client.ok ? `GO_CLIENT_BIN set but missing: ${client.path}`
    : server.set && !server.ok ? `GO_SERVER_BIN set but missing: ${server.path}` : null;
  if (envReason !== null) return { ok: false, client: null, server: null, reason: envReason };
  if (client.ok && server.ok) {
    event(`go client: ${client.path}`);
    event(`go server: ${server.path}`);
    return { ok: true, client: client.path, server: server.path, reason: null };
  }
  if (!existsSync(join(GO_DIR, 'go.sum'))) {
    fail('missing tools/mcp-e2e/go/go.sum - the parent must generate and commit it');
  }
  const buildDir = ensureBuildDir();
  let outClient = client.path;
  let outServer = server.path;
  if (!client.ok) {
    outClient = join(buildDir, 'mcp-e2e-go-client');
    buildOr('go', ['build', '-o', outClient, './cmd/client'], GO_DIR, 'go client');
    event(`go client: ${outClient} (built)`);
  }
  if (!server.ok) {
    outServer = join(buildDir, 'mcp-e2e-go-server');
    buildOr('go', ['build', '-o', outServer, './cmd/server'], GO_DIR, 'go server');
    event(`go server: ${outServer} (built)`);
  }
  return { ok: true, client: outClient, server: outServer, reason: null };
}

export function resolveRustFixtures(event) {
  const client = envArtifact('RUST_CLIENT_BIN');
  const server = envArtifact('RUST_SERVER_BIN');
  const envReason = client.set && !client.ok ? `RUST_CLIENT_BIN set but missing: ${client.path}`
    : server.set && !server.ok ? `RUST_SERVER_BIN set but missing: ${server.path}` : null;
  if (envReason !== null) return { ok: false, client: null, server: null, reason: envReason };
  if (client.ok && server.ok) {
    event(`rust client: ${client.path}`);
    event(`rust server: ${server.path}`);
    return { ok: true, client: client.path, server: server.path, reason: null };
  }
  // Prebuilt probe first: use the release pair if both exist, no lockfile
  // required; only the build path demands a committed Cargo.lock.
  const probe = (kind) => probeRustBinary(join(RUST_DIR, 'target', 'release', `mcp-e2e-rust-${kind}`));
  let preClient = probe('client');
  let preServer = probe('server');
  if (preClient === null || preServer === null) {
    if (!existsSync(join(RUST_DIR, 'Cargo.lock'))) {
      fail('missing tools/mcp-e2e/rust/Cargo.lock - the parent must generate and commit it');
    }
    buildOr('cargo', ['build', '--locked', '--release'], RUST_DIR, 'rust fixtures');
    preClient = probe('client');
    preServer = probe('server');
    if (preClient === null || preServer === null) {
      fail('cargo build succeeded but tools/mcp-e2e/rust/target/release/mcp-e2e-rust-{client,server} not found');
    }
    event(`rust client: ${preClient} (built)`);
    event(`rust server: ${preServer} (built)`);
  } else {
    event(`rust client: ${preClient} (prebuilt)`);
    event(`rust server: ${preServer} (prebuilt)`);
  }
  return { ok: true, client: client.ok ? client.path : preClient, server: server.ok ? server.path : preServer, reason: null };
}

export function resolveTsFixtures(event) {
  const entry = join(TS_DIR, 'node_modules', '@modelcontextprotocol', 'client', 'package.json');
  if (!existsSync(entry)) {
    if (!existsSync(join(TS_DIR, 'package-lock.json'))) {
      fail('missing tools/mcp-e2e/ts/package-lock.json - the parent must generate and commit it');
    }
    buildOr('npm', ['ci', '--no-audit', '--no-fund'], TS_DIR, 'ts fixtures');
    if (!existsSync(entry)) fail('npm ci completed but tools/mcp-e2e/ts/node_modules/@modelcontextprotocol/client is still missing');
    event('ts fixtures: npm ci installed node_modules');
  } else {
    event(`ts fixtures: ${entry}`);
  }
  return { ok: true, client: join(TS_DIR, 'client.mjs'), server: join(TS_DIR, 'server.mjs'), reason: null };
}

// Only languages that at least one selected cell needs are resolved: a
// filtered run (--clients go --servers go) must not demand a rust toolchain.
// Tamper cells exist per server language, so no server fixture is force-added.
export function resolveArtifacts(workDir, needed) {
  let buildDir = null;
  const ensureBuildDir = () => {
    if (buildDir === null) {
      buildDir = join(workDir, 'build');
      mkdirSync(buildDir, { recursive: true, mode: 0o700 });
      chmodSync(buildDir, 0o700);
    }
    return buildDir;
  };
  const event = (line) => process.stderr.write(`artifact ${line}\n`);

  let jackBin = process.env.JACK_BIN;
  let jackBuilt = false;
  if (jackBin !== undefined && jackBin !== '') {
    if (!existsSync(jackBin)) fail(`JACK_BIN set but missing: ${jackBin}`);
    event(`jack: ${jackBin}`);
  } else {
    jackBin = join(ensureBuildDir(), 'jack');
    buildOr('go', ['build', '-o', jackBin, './cmd/jack'], REPO_ROOT, 'jack');
    jackBuilt = true;
    event(`jack: ${jackBin} (built)`);
  }

  const fixtures = {
    go: { ok: true, client: null, server: null, reason: null },
    ts: { ok: true, client: null, server: null, reason: null },
    rust: { ok: true, client: null, server: null, reason: null },
  };
  if (needed.has('go')) fixtures.go = resolveGoFixtures(ensureBuildDir, event);
  if (needed.has('rust')) fixtures.rust = resolveRustFixtures(event);
  if (needed.has('ts')) fixtures.ts = resolveTsFixtures(event);
  return { jack: jackBin, jackBuilt, fixtures };
}
