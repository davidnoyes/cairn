// Milestone 7 browser tests: the successor. See design/e2e-api.md "Successor".
//
// The page's contract with these tests:
// - A Successor tab with #current-successor, #nominate-form (#nominate-user,
//   #nominate-code, #nominate-password, "Name successor"), #my-code, the
//   #successions rows (tr[data-user]) and #successor-status.
// - On every tab: #succession-banner with #refuse-succession while a request
//   is pending, and #rotate-banner once the successor is released.
// - /refuse: #email, input[name=mode] (password or recovery), #password,
//   #code, #submit, #error, #done-text and #deactivated. It needs no session.
//
// The tests run in order and build on each other: succ-* names heir-*, heir-*
// asks and is refused, then asks again and is released. The server's clock
// moves 15 days forward through the e2eclock offset file to release them.
import { readFileSync, writeFileSync } from 'node:fs';
import { expect, test } from './test.mjs';
import { MARKER, cli, contentFrame, loadState, signedInContext } from './helpers.mjs';

test.describe.configure({ mode: 'serial' });

async function openTab(page, name) {
  const s = loadState();
  if (!page.url().startsWith(`${s.appOrigin}/app`)) await page.goto(`${s.appOrigin}/app`);
  await page.getByRole('tab', { name, exact: true }).click();
}

// advanceClock moves the server's clock 15 days further on, past the 14 days a
// request waits. The offset only grows, so an earlier engine's moves stand.
function advanceClock() {
  const file = loadState().clockFile;
  let hours = 0;
  try {
    hours = parseInt(readFileSync(file, 'utf8'), 10) || 0;
  } catch {
    // no offset yet
  }
  writeFileSync(file, `${hours + 360}h\n`);
}

// heirCode reads heir-*'s code from their own Successor tab.
async function heirCode(browser, e) {
  const { context, page } = await signedInContext(browser, `heir-${e}`);
  try {
    await openTab(page, 'Successor');
    const code = page.locator('#my-code');
    await expect(code).toHaveText(/\S+-\S+/);
    return (await code.textContent()).trim();
  } finally {
    await context.close();
  }
}

// nominateByCli names heir-* as user's successor from the command line.
function nominateByCli(user, e) {
  const s = loadState();
  const code = cli(`heir-${e}`, ['successor', 'code']).trim();
  cli(user, ['successor', 'nominate', s.users[`heir-${e}`].email, '--code', code, '--password-stdin'], { input: `${s.users[user].password}\n` });
}

test('successor: a wrong code names nobody, and the heir\'s own code names them', async ({ browser, browserName: e }) => {
  const s = loadState();
  const heir = s.users[`heir-${e}`];
  const code = await heirCode(browser, e);
  const wrong = cli(`dead-${e}`, ['successor', 'code']).trim();
  expect(wrong).not.toBe(code);

  const { context, page } = await signedInContext(browser, `succ-${e}`);
  try {
    await openTab(page, 'Successor');
    await expect(page.locator('#current-successor')).toHaveText('You have not named a successor.');
    const submit = page.locator('#nominate-form').getByRole('button', { name: 'Name successor' });
    await page.locator('#nominate-user').fill(heir.email);
    await page.locator('#nominate-code').fill(wrong);
    await page.locator('#nominate-password').fill(s.users[`succ-${e}`].password);
    await submit.click();
    await expect(page.locator('#successor-status')).toHaveText(`The code does not match the keys the server lists for ${heir.email}.`);
    expect(JSON.parse(cli(`succ-${e}`, ['successor', 'status', '--json'])).successor).toBeNull();

    await page.locator('#nominate-code').fill(code);
    await page.locator('#nominate-password').fill(s.users[`succ-${e}`].password);
    await submit.click();
    await expect(page.locator('#successor-status')).toHaveText(new RegExp(`^${heir.email} is your successor\\.`));
    await expect(page.locator('#current-successor')).toContainText(heir.email);
    expect(JSON.parse(cli(`succ-${e}`, ['successor', 'status', '--json'])).successor.email).toBe(heir.email);
  } finally {
    await context.close();
  }
});

test('successor: a request shows the banner on every tab, and Refuse ends it', async ({ browser, browserName: e }) => {
  const s = loadState();
  const { context, page } = await signedInContext(browser, `succ-${e}`);
  try {
    const banner = page.locator('#succession-banner');
    await openTab(page, 'Artifacts');
    await expect(banner).toBeHidden();
    // A request made after the page loaded shows at the next tab change.
    cli(`heir-${e}`, ['successor', 'request', s.users[`succ-${e}`].email]);
    for (const tab of ['Artifacts', 'API keys', 'Successor', 'Account']) {
      await openTab(page, tab);
      await expect(banner).toBeVisible();
      await expect(page.locator('#succession-text')).toContainText('asked for access to your artifacts');
    }
    // The refusal stands even when the Successor tab then fails to refresh.
    await page.route('**/api/me/successor', (route) => route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"stubbed"}' }));
    await page.locator('#refuse-succession').click();
    await expect(banner).toBeHidden();
    await expect(page.locator('#app-status')).toHaveText('You refused the request. Your successor stays named, and was told.');
    await page.unroute('**/api/me/successor');
    await page.reload();
    await expect(page.locator('#tab-successor')).toBeVisible();
    await expect(banner).toBeHidden();
    expect(JSON.parse(cli(`succ-${e}`, ['successor', 'status', '--json'])).request).toBeNull();
  } finally {
    await context.close();
  }
});

test('successor: Refuse on a stale banner says why and clears the banner', async ({ browser, browserName: e }) => {
  const s = loadState();
  cli(`heir-${e}`, ['successor', 'request', s.users[`succ-${e}`].email]);
  const { context, page } = await signedInContext(browser, `succ-${e}`);
  try {
    // Signing in lands on /app; loading it again while it boots can lose its
    // script in WebKit.
    await expect(page).toHaveURL(`${s.appOrigin}/app`);
    const banner = page.locator('#succession-banner');
    await expect(banner).toBeVisible();
    // Another device refuses first, so this page's banner is stale.
    cli(`succ-${e}`, ['successor', 'refuse']);
    await page.locator('#refuse-succession').click();
    await expect(page.locator('#app-status')).toContainText('no request is pending');
    await expect(banner).toBeHidden();
  } finally {
    await context.close();
  }
});

test('successor: a deactivated user refuses from /refuse with no session, by password and by recovery code', async ({ browser, ownerPage, browserName: e }) => {
  const s = loadState();
  for (const user of [`dead-${e}`, `lost-${e}`]) {
    nominateByCli(user, e);
    cli(`heir-${e}`, ['successor', 'request', s.users[user].email]);
  }
  await ownerPage.goto(`${s.appOrigin}/app`);
  const disabled = await ownerPage.evaluate(async (emails) => {
    const users = await (await fetch('/api/admin/users')).json();
    const out = [];
    for (const u of users.filter((x) => emails.includes(x.email))) {
      const r = await fetch(`/api/admin/users/${u.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ disabled: true }) });
      out.push(r.ok);
    }
    return out;
  }, [s.users[`dead-${e}`].email, s.users[`lost-${e}`].email]);
  expect(disabled).toEqual([true, true]);

  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    const submit = async (u, mode, secret) => {
      await page.goto(`${s.appOrigin}/refuse`);
      await page.locator('#email').fill(u.email);
      // Firefox has, once on CI, dropped this click on a page that had just
      // loaded, with nothing shifting under it, so the choice is retried, and
      // a retry is recorded so a recurrence still shows in the report.
      const choice = page.locator(`input[name=mode][value=${mode}]`);
      let tries = 0;
      await expect(async () => {
        tries++;
        await choice.check({ timeout: 5_000 });
      }).toPass({ timeout: 20_000 });
      if (tries > 1) test.info().annotations.push({ type: 'retried', description: `the ${mode} choice took ${tries} clicks` });
      await page.locator(mode === 'password' ? '#password' : '#code').fill(secret);
      await page.locator('#submit').click();
    };
    // A wrong secret refuses nothing; the right one refuses; a second try
    // finds no request, which for a recovery code reads as a wrong code.
    const cases = [
      [`dead-${e}`, 'password', 'not the password', 'invalid email or password', 'no request is pending'],
      [`lost-${e}`, 'recovery', s.users[`dead-${e}`].recovery, 'or the account has no pending request', 'or the account has no pending request'],
    ];
    for (const [user, mode, wrong, wrongError, againError] of cases) {
      const u = s.users[user];
      const secret = mode === 'password' ? u.password : u.recovery;
      await submit(u, mode, wrong);
      await expect(page.locator('#error')).toContainText(wrongError);
      await expect(page.locator('#done')).toBeHidden();

      await submit(u, mode, secret);
      await expect(page.locator('#done-text')).toContainText(`You refused the request that ${s.users[`heir-${e}`].email} made on `);
      await expect(page.locator('#deactivated')).toBeVisible();
      await expect(page.locator('#deactivated')).toHaveText(/^An administrator deactivated your account on \d{4}-\d{2}-\d{2}, while the request was pending\.$/);
      await expect(page.locator('#error')).toBeEmpty();

      await submit(u, mode, secret);
      await expect(page.locator('#error')).toContainText(againError);
      await expect(page.locator('#done')).toBeHidden();
    }
  } finally {
    await context.close();
  }
});

test('successor: once released, the heir reads the owner\'s artifacts and nothing shared with them, and the owner is told to rotate', async ({ browser, browserName: e }) => {
  const s = loadState();
  cli(`heir-${e}`, ['successor', 'request', s.users[`succ-${e}`].email]);
  advanceClock();
  const succ = s.users[`succ-${e}`];
  const doc = s.artifacts[`succ-doc-${e}`].id;
  const plain = s.artifacts['plain-doc'].id;

  const heir = await signedInContext(browser, `heir-${e}`);
  try {
    const { page } = heir;
    await openTab(page, 'Successor');
    const row = page.locator('#successions tr', { hasText: succ.email });
    await expect(row).toContainText('released');
    await expect(row.locator(`a[href="/shared/${plain}"]`)).toHaveCount(0);
    await row.locator(`a[href="/shared/${doc}"]`).click();
    await expect(page).toHaveURL(`${s.appOrigin}/shared/${doc}`);
    await expect((await contentFrame(page)).locator('#marker')).toHaveText(MARKER);

    // What was shared with the owner stays theirs.
    await page.goto(`${s.appOrigin}/shared/${plain}`);
    await expect(page.locator('#status')).toContainText("You can't open this artifact.");
    expect(page.frames().filter((f) => f.url().includes('.localhost')), 'artifact frames').toEqual([]);
  } finally {
    await heir.context.close();
  }

  const owner = await signedInContext(browser, `succ-${e}`);
  try {
    await expect(owner.page).toHaveURL(`${s.appOrigin}/app`);
    await expect(owner.page.locator('#rotate-banner')).toBeVisible();
    await expect(owner.page.locator('#succession-text')).toHaveText(`${s.users[`heir-${e}`].email} can now read your artifacts.`);
    await expect(owner.page.locator('#refuse-succession')).toBeHidden();
  } finally {
    await owner.context.close();
  }
});
