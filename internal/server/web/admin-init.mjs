// admin-init.mjs — how the admin page starts and which failures it shows.
// admin.js passes in the DOM and network pieces, so this runs without either.

// UnauthenticatedError is what admin.js's api() throws after it sends the
// browser to the sign-in page. Nothing needs to be shown for it.
export class UnauthenticatedError extends Error {
  constructor() {
    super('unauthenticated');
    this.name = 'UnauthenticatedError';
  }
}

// startAdmin shows who is signed in, then loads every list on its own, so one
// list that fails does not hide the others or their errors.
//
//   api(path)                  like admin.js's api()
//   lists                      [{name, load}]
//   setWho(email)              shows the signed-in address
//   listFailed(name, err)      shows why one list did not load
//   fail(err)                  shows any other failure
export async function startAdmin({ api, lists, setWho, listFailed, fail }) {
  try {
    setWho((await api('/api/me')).email);
  } catch (err) {
    if (!(err instanceof UnauthenticatedError)) fail(err);
    return;
  }
  await Promise.all(lists.map(async ({ name, load }) => {
    try {
      await load();
    } catch (err) {
      if (!(err instanceof UnauthenticatedError)) listFailed(name, err);
    }
  }));
}
