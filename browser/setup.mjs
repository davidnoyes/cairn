// Global setup: build the binary, boot a server on a temp data dir, create
// users, push the fixtures and write everything the specs need to a state file.
// Never uses port 8787 or the real CLI config.
import { execFileSync, spawn } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runCli } from './helpers.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES = path.join(ROOT, 'browser', 'fixtures');
const DOMAIN = 'e2e.test';

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(what, fn, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(100);
  }
}

// template copies a fixture into dir with __TOKEN__ placeholders filled in.
function template(name, dir, values) {
  const dest = path.join(dir, name);
  cpSync(path.join(FIXTURES, name), dest, { recursive: true });
  for (const f of readdirSync(dest)) {
    const p = path.join(dest, f);
    let text = readFileSync(p, 'utf8');
    for (const [k, v] of Object.entries(values)) text = text.replaceAll(`__${k}__`, v);
    writeFileSync(p, text);
  }
  return dest;
}

export default async function globalSetup() {
  const tmp = mkdtempSync(path.join(tmpdir(), 'cairn-e2e-'));
  const bin = path.join(tmp, 'cairn');
  const dataDir = path.join(tmp, 'data');
  const logPath = path.join(tmp, 'server.log');
  const statePath = path.join(tmp, 'state.json');
  writeFileSync(statePath, JSON.stringify({ tmp }));
  process.env.CAIRN_E2E_STATE = statePath;
  try {
    execFileSync('go', ['build', '-o', bin, './cmd/cairn'], { cwd: ROOT, stdio: 'inherit' });

    const port = await freePort();
    const appOrigin = `http://localhost:${port}`;
    const env = { ...process.env };
    delete env.CAIRN_HOST;
    delete env.CAIRN_API_KEY;
    const logFd = openSync(logPath, 'a');
    const server = spawn(bin, [
      'serve', '--addr', `127.0.0.1:${port}`, '--public-url', appOrigin, '--data-dir', dataDir,
      '--smtp-url', 'log://', '--signup-domain', DOMAIN, '--admin-email', `owner@${DOMAIN}`,
      // A small cap, so a spec can go over it.
      '--max-db-mb', '1',
    ], { env, stdio: ['ignore', logFd, logFd] });
    // Record the pid first, so teardown can kill the server even if setup fails below.
    const state = { tmp, bin, port, appOrigin, dataDir, logPath, pid: server.pid, users: {}, artifacts: {} };
    writeFileSync(statePath, JSON.stringify(state, null, 2));

    await waitFor('server /healthz', async () => {
      try {
        return (await fetch(`${appOrigin}/healthz`)).ok;
      } catch {
        return false;
      }
    });

    // Users: sign up, confirm with the link from the log:// mailer, sign in.
    for (const name of ['owner', 'editor', 'viewer']) {
      const email = `${name}@${DOMAIN}`;
      const password = `e2e-${name}-password-Qm47vz`;
      const config = path.join(tmp, 'config', name, 'config.json');
      mkdirSync(path.dirname(config), { recursive: true });
      runCli(bin, config, ['signup', '--host', appOrigin, '--email', email, '--password-stdin'], { input: `${password}\n` });
      const re = new RegExp(`${appOrigin}/verify#token=[A-Za-z0-9_-]+`, 'g');
      const link = await waitFor(`verification link for ${email}`, () => {
        const m = readFileSync(logPath, 'utf8').match(re);
        return m && m[m.length - 1];
      });
      runCli(bin, config, ['confirm-email', link]);
      runCli(bin, config, ['login', '--host', appOrigin, '--email', email, '--password-stdin'], { input: `${password}\n` });
      state.users[name] = { email, password, config };
    }

    const owner = (args) => runCli(bin, state.users.owner.config, args);
    const push = (dir, artifact) => {
      const out = JSON.parse(owner(['push', dir, '--artifact', artifact, '--create', '--json']));
      state.artifacts[artifact] = { id: out.artifact.id, version: out.version.id };
    };
    const fx = path.join(tmp, 'fixtures');
    mkdirSync(fx);

    push(template('marker', fx, {}), 'plain-doc');
    push(template('marker', fx, {}), 'tamper-doc');
    push(template('team', fx, {}), 'team-doc');
    push(template('hostile', fx, { PORT: String(port) }), 'hostile-doc');
    push(template('links', fx, { MARKER_ID: state.artifacts['plain-doc'].id }), 'links-doc');
    push(template('marker', fx, {}), 'data-doc');
    for (const example of ['guestbook', 'poll', 'drive']) push(path.join(ROOT, 'examples', example), example);

    owner(['share', 'plain-doc', state.users.viewer.email]);
    owner(['share', 'team-doc', state.users.editor.email, '--role', 'editor']);
    owner(['share', 'data-doc', state.users.editor.email, '--role', 'editor']);
    state.publicLink = JSON.parse(owner(['public', 'plain-doc', 'on', '--json'])).link;
    state.fixturesDir = fx;

    writeFileSync(statePath, JSON.stringify(state, null, 2));
  } catch (e) {
    // Teardown does not run when setup throws.
    const { default: teardown } = await import('./teardown.mjs');
    await teardown();
    throw e;
  }
}
