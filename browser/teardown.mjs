// Global teardown: stop the server, keep its log with the test results, and
// remove the temp dir.
import { copyFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';

export default async function globalTeardown() {
  const statePath = process.env.CAIRN_E2E_STATE;
  if (!statePath) return;
  let state;
  try {
    state = JSON.parse(readFileSync(statePath, 'utf8'));
  } catch {
    return;
  }
  if (state.pid) {
    try {
      process.kill(state.pid, 'SIGTERM');
    } catch {
      // Already gone.
    }
  }
  // CI uploads test-results/ when a run fails, so a failure comes with what
  // the server logged. It logs no requests, only errors and changes.
  if (state.logPath) {
    const results = path.join(import.meta.dirname, '..', 'test-results');
    try {
      mkdirSync(results, { recursive: true });
      copyFileSync(state.logPath, path.join(results, 'server.log'));
    } catch {
      // No log to keep.
    }
  }
  if (state.tmp) rmSync(state.tmp, { recursive: true, force: true });
}
