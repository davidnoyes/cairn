// Groups in a real browser (R3a). The owner creates a group on the Groups
// tab, adds a member, makes them a manager, renames the group, removes them,
// and deletes it. The command-line tool reads the same signed chain at each
// step, and the member's own page lists the group with their role.
import { test, expect } from './test.mjs';
import { cliJson, freshUser, loadState, signIn } from './helpers.mjs';

// openGroups opens the Groups tab.
async function openGroups(page) {
  const s = loadState();
  await page.goto(`${s.appOrigin}/app`);
  await page.getByRole('tab', { name: 'Groups' }).click();
  const tab = page.locator('section#groups');
  await expect(tab).toBeVisible();
  return tab;
}

// shown reads a group from the owner's command-line tool, by name.
function shown(name) {
  return cliJson('owner', ['group', 'show', name]);
}

test('groups: create, add a member, make them a manager, rename, remove, and delete', async ({ browser, ownerPage, browserName }) => {
  const s = loadState();
  const domain = s.users.owner.email.split('@')[1];
  const stamp = `${browserName}-${Date.now()}`;
  const member = await freshUser(`grp-${stamp}`, domain);
  const name = `Team ${stamp}`;

  // Creating opens the new group, with the owner as its only manager.
  let tab = await openGroups(ownerPage);
  await tab.getByLabel('New group name').fill(name);
  await tab.getByRole('button', { name: 'New group' }).click();
  await expect(tab.locator('#groups-status')).toHaveText(`Created ${name}.`, { timeout: 30_000 });
  await expect(tab.locator('#group-title')).toHaveText(name);
  const members = tab.locator('#group-members tr');
  await expect(members).toHaveCount(1);
  await expect(members.first().locator('td.role')).toHaveText('manager');

  // Adding a member signs the next record.
  await tab.getByLabel('Email of the person to add').fill(member.email);
  await tab.getByRole('button', { name: 'Add member' }).click();
  const row = members.filter({ hasText: member.email });
  await expect(row.locator('td.role')).toHaveText('member', { timeout: 30_000 });
  let g = shown(name);
  expect(g.seq).toBe(2);
  expect(g.members.find((m) => m.email === member.email)?.role).toBe('member');

  // Making them a manager signs another.
  await row.getByLabel(`Role of ${member.email}`).selectOption('manager');
  await expect(row.locator('td.role')).toHaveText('manager', { timeout: 30_000 });
  expect(shown(name).members.find((m) => m.email === member.email)?.role).toBe('manager');

  // The member's own page lists the group with their role.
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await signIn(page, member.email, member.password);
  const theirs = await openGroups(page);
  await expect(theirs.locator('#groups-body tr').filter({ hasText: name }).locator('td.role')).toHaveText('manager');
  await ctx.close();

  // Renaming changes the name every client reads from the chain.
  const renamed = `${name} renamed`;
  await tab.getByLabel('Group name', { exact: true }).fill(renamed);
  await tab.getByRole('button', { name: 'Rename' }).click();
  await expect(tab.locator('#group-title')).toHaveText(renamed, { timeout: 30_000 });
  g = shown(renamed);
  expect(g.name).toBe(renamed);

  // Removing the member leaves the owner alone again.
  await row.getByRole('button', { name: 'Remove' }).click();
  await expect(row).toHaveCount(0, { timeout: 30_000 });
  g = shown(renamed);
  expect(g.members.map((m) => m.email)).toEqual([s.users.owner.email]);
  expect(g.seq).toBe(5);

  // Deleting asks again, then the group is gone from the list and the server.
  const del = tab.locator('#group-actions').getByRole('button', { name: /^Delete (group|for good\?)$/ });
  await del.click();
  await expect(del).toHaveText('Delete for good?');
  await del.click();
  await expect(tab.locator('#groups-status')).toHaveText(`Deleted ${renamed}.`, { timeout: 30_000 });
  tab = await openGroups(ownerPage);
  await expect(tab.locator('#groups-body tr').filter({ hasText: renamed })).toHaveCount(0);
  expect(cliJson('owner', ['group', 'list']).some((x) => x.name === renamed)).toBe(false);
});
