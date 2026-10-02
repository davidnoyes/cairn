// Global teardown: stop the server and remove the temp dir.
import { readFileSync, rmSync } from 'node:fs';

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
  if (state.tmp) rmSync(state.tmp, { recursive: true, force: true });
}
