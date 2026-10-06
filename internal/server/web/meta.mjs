// meta.mjs — the encrypted metadata fields of an artifact and of its versions:
// the artifact's name and description, a version's name and changelog. Each
// field is one sealed blob under the epoch's AK, covered by a signed record,
// and the server holds only ciphertext. The rules are in design/e2e-api.md
// ("Encrypted metadata and the app UI"). A field is read the way a stored
// file's record is, with the checks of data.mjs; one that fails any check is
// unreadable, and never throws.
//
// Nothing here reads a browser global. Each function takes `deps` as
// viewer.mjs does: fetch, keyStore, storage, and origin.
import * as e2e from './e2e.mjs';
import { call, openArtifact, writerKeys } from './viewer.mjs';
import { checkSigned } from './data.mjs';

// META_FIELDS lists the fields of each scope: an artifact's, and a version's.
export const META_FIELDS = {
  artifact: ['name', 'description'],
  version: ['name', 'changelog'],
};

// MAX_META_PLAINTEXT is the longest field value, in bytes of UTF-8: 16 KiB.
const MAX_META_PLAINTEXT = 16 * 1024;

const encoder = new TextEncoder();
// ignoreBOM keeps a leading byte-order mark as the character it is, so the
// value reads back as it was written.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

// MetaError is a write the client refuses before sending it.
export class MetaError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MetaError';
  }
}

function fieldsOf(versionId) {
  return versionId === '' ? META_FIELDS.artifact : META_FIELDS.version;
}

// openMetaItem runs every read check on one item of a view's meta object:
// {record, signerKey, blob}. keys is what data.mjs's checkSigned takes
// (artifact, version, aks by epoch, writers, publicWrites). It returns
// {value, epoch}, or throws for any failure. The record must be signed by a
// writer under a key the record's chain lists, decode strictly, and name this
// artifact, version, kind meta, and field; the blob must match its sha256 and
// open under the record's epoch's AK for the same four; the plaintext must be
// at most 16 KiB of valid UTF-8.
export async function openMetaItem(keys, versionId, field, item) {
  if (typeof item !== 'object' || item === null || typeof item.signerKey !== 'string' || typeof item.blob !== 'string') {
    throw new Error('the item is not {record, signerKey, blob}');
  }
  const env = e2e.decodeEnvelope(JSON.stringify(item.record));
  const blob = e2e.unb64(item.blob);
  // The epoch is read only to say which AK to open the blob with: checkSigned
  // verifies the signature before it trusts any field, this one included.
  const { epoch } = e2e.decodeStrict(e2e.unb64(env.body), e2e.BODY_SCHEMAS.record);
  const { ak } = await checkSigned(keys, 'record', env, item.signerKey, { epoch, kind: 'meta', name: field, blob });
  const plain = await e2e.openBlob(ak, { artifact: keys.artifact, version: versionId, kind: 'meta', name: field }, blob);
  if (plain.length > MAX_META_PLAINTEXT) throw new Error('the value is over 16 KiB');
  return { value: decoder.decode(plain), epoch };
}

// readMeta reads the fields of one scope from a view's meta object: the
// artifact's when versionId is empty, else that version's. opened is what
// openArtifact returns. A field nobody wrote is in neither list.
export async function readMeta(deps, opened, meta, versionId = '') {
  const aks = {};
  for (const [epoch, ak] of opened.aks) aks[String(epoch)] = e2e.b64(ak);
  // A public writer may not write metadata, so publicWrites is never on here.
  const keys = { artifact: opened.artifact, version: versionId, epoch: 1, aks, writers: await writerKeys(deps, opened), publicWrites: false };
  const values = {};
  const unreadable = [];
  for (const field of fieldsOf(versionId)) {
    if (!meta || !Object.hasOwn(meta, field)) continue;
    try {
      values[field] = (await openMetaItem(keys, versionId, field, meta[field])).value;
    } catch {
      unreadable.push(field);
    }
  }
  return { values, unreadable };
}

// describeArtifact is an artifact as the app's list shows it: view is its
// entry in GET /api/artifacts. It opens the artifact as a member to read the
// encrypted name and description, and never throws: an artifact that does not
// open, or whose name fails a check or is blank, shows under its ID, named is
// false, and error says why when something failed.
export async function describeArtifact(deps, view) {
  const out = { name: view.id, description: '', named: false, error: null };
  try {
    const opened = await openArtifact(deps, { artifact: view.id, link: null });
    const { values, unreadable } = await readMeta(deps, opened, view.meta);
    if (values.name?.trim()) Object.assign(out, { name: values.name, named: true });
    out.description = values.description ?? '';
    if (unreadable.length > 0) out.error = new Error(`Could not read the ${unreadable.join(' and ')} of this artifact.`);
  } catch (err) {
    out.error = err;
  }
  return out;
}

// mayWriteMeta says whether the caller is the latest record's owner or an
// editor, signed in as a member: a link holder is never one.
function mayWriteMeta(opened) {
  if (opened.mode !== 'member' || !opened.record) return false;
  const id = opened.record.userId;
  return opened.latest.owner === id || opened.latest.members.some((m) => m.user === id && m.role === 'editor');
}

// writeMeta seals value under the current epoch's AK, signs the record, and
// sends it. It refuses a field the scope does not have, a value that is not a
// well-formed string of at most 16 KiB of UTF-8, a caller who is not owner or
// editor, and a caller with no key for the current epoch, all before sending.
export async function writeMeta(deps, opened, versionId, field, value) {
  if (!fieldsOf(versionId).includes(field)) throw new MetaError(`${versionId === '' ? 'an artifact' : 'a version'} has no field ${field}`);
  if (typeof value !== 'string' || !value.isWellFormed()) throw new MetaError('a field value is a string of valid text');
  const plain = encoder.encode(value);
  if (plain.length > MAX_META_PLAINTEXT) throw new MetaError('a field value is at most 16 KiB');
  if (!mayWriteMeta(opened)) throw new MetaError('only the artifact\'s owner or an editor can change its details');
  const epoch = opened.latest.epoch;
  const ak = opened.aks.get(epoch);
  if (!ak) throw new MetaError(`you hold no key for the artifact's current epoch ${epoch}`);
  const blob = await e2e.sealBlob(ak, { artifact: opened.artifact, version: versionId, kind: 'meta', name: field }, plain);
  const body = { v: 1, artifact: opened.artifact, version: versionId, kind: 'meta', name: field, epoch, sha256: await e2e.bodyHash(blob) };
  const record = await e2e.newEnvelope(opened.record.ed25519, opened.record.userId, 'record', encoder.encode(JSON.stringify(body)));
  const prefix = `/api/artifacts/${opened.artifact}${versionId === '' ? '' : `/versions/${versionId}`}`;
  await call(deps, null, 'PUT', `${prefix}/meta/${field}`, { body: { record, blob: e2e.b64(blob) } });
}
