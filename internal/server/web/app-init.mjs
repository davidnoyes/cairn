// app-init.mjs — how the app page starts and which failures it shows.
// app.mjs passes in the DOM, network, and storage pieces, so this runs without
// any of them.

// UnauthenticatedError is what app.mjs's api() throws after it sends the
// browser to the sign-in page. Nothing needs to be shown for it.
export class UnauthenticatedError extends Error {
  constructor() {
    super('unauthenticated');
    this.name = 'UnauthenticatedError';
  }
}

// startApp checks the session and the unlocked keys, shows who is signed in,
// then loads every list on its own, so one list that fails does not hide the
// others or their errors. A session whose keys are not in this browser, or
// are another account's, is sent to sign in: the page never asks for the
// password itself. A failure of /api/me is shown in every list too, because
// the flash hides itself. It returns {me, keys}, or null if the page stops.
//
//   api(path)                  like app.mjs's api()
//   keyStore                   keystore.mjs's store
//   toLogin()                  sends the browser to sign in
//   lists                      [{name, load({me, keys}), admin}]; admin lists
//                              load only for an administrator
//   setUser(me)                shows the signed-in account
//   listFailed(name, err)      shows why one list did not load
//   fail(err)                  shows any other failure
export async function startApp({ api, keyStore, toLogin, lists, setUser, listFailed, fail }) {
  let me;
  try {
    me = await api('/api/me');
  } catch (err) {
    if (!(err instanceof UnauthenticatedError)) {
      fail(err);
      for (const { name } of lists) listFailed(name, err);
    }
    return null;
  }
  const keys = await keyStore.load().catch(() => null);
  if (!keys || keys.userId !== me.id) {
    toLogin();
    return null;
  }
  setUser(me);
  const ctx = { me, keys };
  await Promise.all(lists.filter((l) => !l.admin || me.isAdmin).map(async ({ name, load }) => {
    try {
      await load(ctx);
    } catch (err) {
      if (!(err instanceof UnauthenticatedError)) listFailed(name, err);
    }
  }));
  return ctx;
}
