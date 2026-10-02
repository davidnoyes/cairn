// Browser end-to-end suite. See design/e2e-execution-plan.md, "Browser end to end".
// Run with PLAYWRIGHT_BROWSERS_PATH pointing at the installed browsers if they
// are not in Playwright's default cache.
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'browser',
  testMatch: '*.spec.mjs',
  globalSetup: './browser/setup.mjs',
  globalTeardown: './browser/teardown.mjs',
  // The tests share one server and its data.
  workers: 1,
  fullyParallel: false,
  retries: 0,
  // Sign-in runs Argon2id in wasm, and the handshake adds more.
  timeout: 90_000,
  expect: { timeout: 20_000 },
  reporter: [['list']],
  use: {
    trace: 'on-first-retry',
    actionTimeout: 30_000,
    navigationTimeout: 60_000,
  },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
});
