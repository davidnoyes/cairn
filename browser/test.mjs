// The specs' `test`, with one signed-in owner context per worker, so Argon2id
// runs once per engine instead of once per test.
import { test as base } from '@playwright/test';
import { loadState, signIn } from './helpers.mjs';

export { expect } from '@playwright/test';

export const test = base.extend({
  ownerContext: [
    async ({ browser }, use) => {
      const context = await browser.newContext();
      const page = await context.newPage();
      const owner = loadState().users.owner;
      await signIn(page, owner.email, owner.password);
      await page.close();
      await use(context);
      await context.close();
    },
    { scope: 'worker' },
  ],
  ownerPage: async ({ ownerContext }, use) => {
    const page = await ownerContext.newPage();
    await use(page);
    await page.close();
  },
});
