# Roles, groups, and folders

Status: **plan, decisions agreed; R1 (viewer accounts) and R2 (managers) are
built**, and the rest is not yet. It extends the
[trust model](e2e-trust-model.md) and builds on
[Google sign-in and passkey unlock](google-signin.md).

## Goal

Cairn moves from a small trusted circle toward a team with structure:

- **Server roles** decide what a person may do on the server: publish, manage
  users, or only take part in what others share with them.
- **Groups** let people share with a set of colleagues by name.
- **Managers** let an owner hand the power to share to someone else.
- **Folders** organize artifacts into a tree. Sharing a folder shares
  everything in it, the way a shared folder in Google Drive does.

Every guarantee in the trust model still holds. A role, a group, or a folder
can stop someone reading, but it can never let anyone read without the
artifact's key sealed to them. Only someone who already holds that key can
seal it.

## Decisions taken

| Question | Decision |
| --- | --- |
| Server roles | Administrator, member, and viewer account: a viewer account can read what is shared with it and write nothing |
| Who creates groups | Any member; the creator manages the group |
| Group membership | Signed by a group manager, and checked by every client and the server |
| Who can share | The owner, and a new **manager** role the owner grants |
| Folder contents | Like Google Drive: editors of a folder can add artifacts they own |
| How folder sharing reaches contents | Copied onto each artifact's member list, now and when artifacts are added; each artifact keeps its own key |
| A child's access | More than its folder, never less; to shut someone out of one artifact, move it out of the folder |
| Deleting a folder | Like Google Drive: the owner's own items inside are deleted, and other people's items move to their owners' top level |
| Public folders | Out of scope |

## Two kinds of check

Each rule below is one of two kinds, and the kind decides what it can do:

- **A server check** refuses a request. It can stop an action at once:
  creating an artifact, managing users, or serving ciphertext to someone who
  lost access. It cannot grant reading, because the server holds no keys.
- **A key action** seals an artifact's key to someone, or replaces the key
  with a new epoch. Only a client that holds the key can do it, so it happens
  when an owner, manager, or editor next opens Cairn.

Granting access is always a key action. Taking it away is a server check at
once, followed by a key action that starts a new epoch, so the person loses
the content written after that too.

## Server roles

| Action | Administrator | Member | Viewer account |
| --- | --- | --- | --- |
| Open what is shared with them | Yes | Yes | Yes |
| Create API keys, and sign in with `cairn login` | Yes | Yes | Yes |
| Write a database or files, push a version, or write through public writes | Yes, where their role allows | Yes, where their role allows | No |
| Be listed as editor or manager of an artifact or folder | Yes | Yes | No |
| Create artifacts, folders, and groups | Yes | Yes | No |
| Be a group manager | Yes | Yes | No |
| Grant roles, deactivate accounts, and delete them | Yes | No | No |

- The role replaces the `is_admin` flag: `users.role` is `admin`, `member`,
  or `viewer`. Migration makes every current administrator `admin` and
  everyone else `member`. The server role is called a **viewer account** in
  the pages, so it reads differently from the viewer role on an artifact.
- **A viewer account is still a user.** It has keys, can be shared with,
  joins groups, and uses `cairn login` and API keys, for example for an agent
  that reads a dashboard. It just never writes.
- **Becoming a viewer account.** A new flag, `--viewer-domain`, names email
  domains whose sign-ups become viewer accounts, so outside readers can join.
  An address in a `--signup-domain` signs up as a member. An administrator can
  change anyone's role later.
- **Enforced twice.** The server refuses every write from a viewer account,
  whatever an artifact's member list says. The membership checks also refuse
  a new member list that lists a viewer account as editor or manager, so the
  share dialog offers only the viewer role for them.
- **Demotion.** Making a member a viewer account stops their writes at once.
  They keep what they own, but cannot change it. Member lists that still name
  them as editor are left as they are; the owner or a manager is prompted to
  change the entry to viewer the next time they open the artifact. No new
  epoch is needed, because they keep their read access. An administrator who
  wants their artifacts handled offers an ownership transfer, as today.
- An administrator still cannot read what is not shared with them. Roles are
  server checks only.

## Groups

A group is a named set of users that can be shared with as one principal.
Today's whole-team share becomes the built-in group **Everyone**.

- **Creating.** Any member or administrator creates a group and becomes its
  manager. A group's name is visible to every signed-in user, like the user
  directory, so it is not encrypted.
- **Managing.** A group manager adds and removes members and other managers,
  by signing a new group record. An administrator who is not a manager of the
  group cannot change its members, because they cannot sign its record. They
  can delete the group, which ends every share made through it at once.
- **Sharing with a group.** An owner or manager lists the group in a member
  list, with a role: viewer or editor. A group cannot be a manager.
- **Joining.** When someone joins a group, every artifact and folder shared
  with that group shows them as waiting. The next owner, manager, or editor to
  open it is asked to approve them, by name and fingerprint, and their client
  seals the key. This is today's team approval, generalized from one team to
  many groups.
- **Leaving.** When someone leaves a group, the server stops serving them
  anything shared only through that group at once. Each affected artifact
  then shows them as **still holding the key**, and the next owner or manager
  to open it starts a new epoch.

### Signed group records

Group membership is a signed chain, built like an artifact's member list:

- Each group record holds the group ID, a sequence number, and the members
  and managers, each with the fingerprint the signer saw for them. The
  creator signs the first record. Each later record is signed by a manager
  listed in the previous one.
- The server accepts a record only when its signer is a manager in the
  previous record and its sequence number is the next one. It stores the
  chain, and serves it with every share that names the group.
- A client checks the whole chain before it trusts a group: before it lists a
  newcomer for approval, before it seals a key to one, and before it shows a
  group's members. Each client remembers the newest record it has seen for
  each group, and refuses an older one, so the server cannot roll a group
  back to a member list that suits it.
- The approver still sees the newcomer's name and fingerprint, and the client
  compares that fingerprint with the one in the group record. A mismatch is a
  key-change warning, as for any share.
- A group record goes through the same three checks as a member list, in the
  server, the command-line tool, and the browser, tied by shared test vectors.

### Risks of groups

- **A group manager can add anyone to the group.** They still cannot grant
  reading by themselves; an approver for each artifact must agree.
- **A new device has no record of a group's newest version**, so it accepts
  whatever chain the server serves first, as with a keyring today.

## The manager role

A manager can do what the owner does with sharing, and nothing about
ownership:

| Action | Owner | Manager | Editor | Viewer |
| --- | --- | --- | --- | --- |
| Read content, database, and files | Yes | Yes | Yes | Yes |
| Write database and files, push versions | Yes | Yes | Yes | No |
| Share and unshare with users and groups, approve newcomers | Yes | Yes | Approve only, as today | No |
| Make public or private | Yes | Yes | No | No |
| Start a new epoch | Yes | Yes | No | No |
| Add or remove managers | Yes | No | No | No |
| Transfer ownership, delete | Yes | No | No | No |

**This changes the trust model.** Today only the owner signs member lists.
With managers, a member list is accepted when its signer is the owner, or a
manager listed in the previous accepted record. Three places check it, and
all three change together, tied by new test vectors:

- the server's acceptance rules in `internal/membership`;
- the command-line tool's chain check in `internal/e2e` and `internal/client`;
- the browser's chain check in `e2e.mjs` and `sharing.mjs`.

Further rules:

- A record signed by a manager must keep the owner, keep every manager, and
  keep the owner as the only one who can change the set of managers. The
  checks refuse a manager's record that does otherwise.
- **The owner's estate copy.** The owner reaches each epoch's key through
  their estate key, which a manager cannot use. A manager's new epoch seals
  the key to the owner's public key instead. The owner's client adds the
  estate copy the next time it opens the artifact, and the successor reads
  through that copy only from then on.
- **Removing a manager** starts a new epoch, as removing an editor does, and
  lists the member-list changes that manager signed, for the owner to review.

## Folders

### A folder is an artifact with no content

A folder reuses the artifact machinery: an owner, a signed member list,
epochs, its own key, and encrypted metadata. It has no versions, database, or
files.

- `artifacts.kind` is `artifact` or `folder`.
- `artifacts.parent_id` names the folder an artifact or folder sits in, or is
  empty at the top level. The tree's shape is visible to the server; names are
  encrypted, so it sees which items sit together but not what they are called.
- A folder's key seals only its own metadata. Each artifact inside keeps its
  own key.
- A folder cannot be public in this plan. An artifact inside one can be.
- Folders nest up to 16 deep.

### What a folder's members can do

| Action | Owner | Manager | Editor | Viewer |
| --- | --- | --- | --- | --- |
| See the folder and its contents | Yes | Yes | Yes | Yes |
| Create a folder inside | Yes | Yes | Yes | No |
| Add an artifact or folder they own | Yes | Yes | Yes | No |
| Remove any item, which moves it to its owner's top level | Yes | Yes | Yes | No |
| Rename the folder | Yes | Yes | Yes | No |
| Share and unshare the folder | Yes | Yes | No | No |
| Delete the folder | Yes | No | No | No |

A viewer account can only be a folder's viewer, so it sees the folder and
changes nothing in it.

### Inherited access

An item's access is its own member list plus the member list of every folder
that contains it. A child can add people; it cannot drop someone a containing
folder lists.

- **Recorded in each member list.** When a folder is shared, each item inside
  it gets a new signed member list that includes the inherited entries,
  marked with the folder they come from. A client displays them as
  inherited, and refuses a record that drops an inherited entry while the
  item still sits in that folder.
- **Applied at once where the actor can sign.** The client sharing the folder
  writes new member lists for every item inside it that its user owns or
  manages, sealing each item's key to the new members.
- **Applied later where they cannot.** For an item owned by someone else,
  which Drive-style contents allow, the server queues an **inheritance
  update**. The next time that item's owner or a manager of it opens Cairn,
  their client applies the update: new member list, keys sealed. Until then,
  the new members see the item listed but cannot open it, and the page says
  who has yet to apply the share.
- **Taking access away is immediate on the server.** Unsharing a folder, or
  removing an item from it, makes the server stop serving that item to anyone
  who had it only through the folder. The new epoch follows when the item's
  owner or a manager next opens it.

### Moving

- Moving an item into a folder needs editor access to the folder and
  ownership of the item, or manager access to it. Its member list then gains
  the folder's inherited entries.
- Moving an item out, or removing it, needs editor access to the folder it
  leaves. People who had it only through that folder lose it, as described earlier.
- Moving a folder moves its whole subtree; every item inside gains and loses
  inherited entries in one pass.

### Deleting a folder

Deleting a folder works as in Google Drive. Only the folder's owner can do it,
and the page first lists what happens to everything inside:

- Items the owner owns, folders included, are deleted with it.
- Items other people own move to the top level of their owners, with their
  own folders and contents intact. People who had them only through the
  deleted folder lose them at once on the server, and each item moves to a
  new epoch when its owner or a manager next opens it.
- The owner confirms once, then the client deletes and moves item by item,
  showing progress and resuming if interrupted.

### Cost

Sharing a folder writes one signed member list for each item inside it.
Unsharing also re-encrypts each item's latest version, database, and files
under a new epoch. A folder of hundreds of artifacts therefore takes a while
to unshare. The browser and the command-line tool show progress and can
resume, because each item lands on its own.

## Pages and commands

- The **Artifacts** tab becomes a tree: folders first, then artifacts, with
  breadcrumbs. Drag to move, or **Move to…** from a menu.
- The share dialog lists users and groups, with roles viewer, editor, and
  manager, and shows inherited entries grayed, with the folder they come from.
- A new **Groups** tab lists the groups a person belongs to or manages.
  Administrators see every group on the **Admin** tab.
- Commands, all with `--json`:
  - `cairn folder create NAME [--in FOLDER]`, `cairn folder list [FOLDER]`,
    `cairn move ITEM --to FOLDER|--top`.
  - `cairn push DIR --artifact NAME --create --in FOLDER`.
  - `cairn group create NAME`, `cairn group add GROUP USER`,
    `cairn group remove GROUP USER`, `cairn group list`.
  - `cairn share ITEM GROUP|USER --role viewer|editor|manager`, extending
    today's share command.
  - `cairn apply`, which applies every pending inheritance update and approval
    the caller can, for headless use.

## Milestones

Each milestone ships with its tests, leaves the server working, and passes the
review gate. Tests are written at design time, before the code they cover.

| # | Milestone | Proof it works |
| --- | --- | --- |
| R1 | Server roles: `users.role`, viewer accounts, `--viewer-domain`, the role table on every endpoint, the **Admin** tab, and commands | Integration tests for every cell of the role table; a viewer account reads what is shared with it and uses an API key, and every write it tries is refused, even where a member list still names it editor |
| R2 | Manager role: acceptance rules, both chain checks, test vectors, the estate-copy catch-up, the share dialog, and commands | Go and JavaScript check the same vectors; a manager's record is accepted, and one that changes the managers, drops the owner, or comes from a removed manager is refused; the owner's client adds the estate copy after a manager's epoch |
| R3 | Groups: signed group records with their three checks and test vectors, management, sharing with a group, approval of newcomers, immediate server cut-off when someone leaves; **Everyone** replaces the team share | Go and JavaScript check the same group-record vectors; a record from a non-manager or a rolled-back chain is refused; a newcomer cannot read until approved; someone who leaves gets 404 at once and a new epoch follows; a browser walkthrough of creating a group and sharing with it |
| F1 | Folders as content-less artifacts: create, rename, nest, move, list, delete with the folder owner's items, encrypted names, the tree on the **Artifacts** tab, and `cairn folder` | Names are ciphertext on disk; moves respect the folder table; depth over 16 is refused; a browser walkthrough of the tree |
| F2 | Inherited access for items the actor can sign: fan-out on share, new epochs on unshare and on moving out, inherited entries in member lists | Sharing a folder lets a member open every item inside it; unsharing ends their access at once and moves each item to a new epoch; a record that drops an inherited entry is refused |
| F3 | Drive-style contents: editors add their own items, inheritance updates queued for other owners, deleting a folder that holds other people's items, `cairn apply`, the "yet to apply" notices | An item another user owns becomes readable only after its owner applies the update; removal is immediate either way; deleting the folder moves that item to its owner and deletes the rest; a browser walkthrough with two owners |

R1 is independent and small. R2 comes before F2, because inherited access
needs managers to sign member lists. R3 and F1 can proceed in parallel after
R2.

## Out of scope

- Public folders. One would need a link key for every item inside it.
- Custom roles defined by administrators.
- Group membership synced from Google Workspace.
