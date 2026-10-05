#!/usr/bin/env bash
# End-to-end smoke test: builds the binary, boots a server on a temp data dir,
# then drives it through the CLI and plain HTTP the way a user/agent would.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
PORT="${CAIRN_E2E_PORT:-8797}"
HOST="http://127.0.0.1:$PORT"
BIN="$WORK/cairn"
export CAIRN_CONFIG="$WORK/config/cairn/config.json"   # keep CLI login state isolated
# These override CAIRN_CONFIG, so a value left in the shell would send every
# command below to that server instead of the one started here.
unset CAIRN_HOST CAIRN_API_KEY

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗ %s\033[0m\n' "$1"; exit 1; }

cleanup() {
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/cairn)
pass "built $BIN"

echo "== serve"
SERVER_LOG="$WORK/server.log"
"$BIN" serve --addr ":$PORT" --data-dir "$WORK/data" \
  --smtp-url log:// --admin-email admin@e2e.test --signup-domain e2e.test --public-url "$HOST" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 50); do
  curl -sf "$HOST/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -sf "$HOST/healthz" >/dev/null || fail "server did not start"
pass "server healthy on $HOST"

echo "== auth"
# Sign up, confirm by pulling the verification link out of the log:// mailer,
# then sign in. cairn login creates a device API key and saves it.
echo "e2e-password-1" | "$BIN" signup --host "$HOST" --email admin@e2e.test --password-stdin >/dev/null
VERIFY_LINK=$(grep -oE "$HOST/verify#token=[A-Za-z0-9_-]+" "$SERVER_LOG" | tail -1)
[[ -n "$VERIFY_LINK" ]] || fail "no verification link in server log"
"$BIN" confirm-email "$VERIFY_LINK" >/dev/null
echo "e2e-password-1" | "$BIN" login --host "$HOST" --email admin@e2e.test --password-stdin >/dev/null
"$BIN" whoami | grep admin@e2e.test >/dev/null || fail "whoami"
pass "CLI signup + confirm-email + login + whoami"

# Headless use: the config file holds the full four-part API key; only the
# two-part bearer `cairn_<keyId>_<authSecret>` ever goes on the wire; the
# keySecret never leaves this machine.
API_KEY=$(python3 -c "import json;print(json.load(open('$CAIRN_CONFIG'))['apiKey'])")
BEARER=$(echo "$API_KEY" | cut -d'_' -f1-3)
CAIRN_HOST="$HOST" CAIRN_API_KEY="$API_KEY" "$BIN" whoami | grep admin@e2e.test >/dev/null || fail "API key auth"
pass "API key auth"

echo "== push"
"$BIN" push "$ROOT/examples/guestbook" --artifact guestbook --create \
  --name v1 --changelog "first" --json > "$WORK/push1.json"
AID=$(python3 -c "import json;print(json.load(open('$WORK/push1.json'))['artifact']['id'])")
VID=$(python3 -c "import json;print(json.load(open('$WORK/push1.json'))['version']['id'])")
pass "pushed guestbook ($AID / $VID)"

echo "== resource reference"
# Artifacts are private from creation, so plain HTTP reads carry the bearer.
AUTH=(-H "Authorization: Bearer $BEARER")
curl -sf -X POST "$HOST/api/artifacts/$AID/resources" \
  "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"type":"claude-session","value":"sess-e2e"}' >/dev/null
curl -sf "${AUTH[@]}" "$HOST/api/artifacts/sess-e2e" | grep "$AID" >/dev/null || fail "API lookup by resource value"
pass "API resolves resource value to artifact"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$HOST/api/artifacts/sess-e2e")
[[ "$STATUS" == "404" ]] || fail "anonymous lookup of a private artifact ($STATUS)"
pass "anonymous lookup of a private artifact is not found"
"$BIN" artifact show sess-e2e | grep "$AID" >/dev/null || fail "CLI lookup by resource value"
pass "CLI resolves resource value"

echo "== serving"
# The app origin serves no artifact file: the old paths go to the shared page.
for from in "$AID" "$AID/$VID" "$AID/$VID/" "$AID/$VID/sub/page.html"; do
  LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "${AUTH[@]}" "$HOST/artifacts/$from")
  [[ "$LOC" == "$HOST/shared/$from" || "$LOC" == "/shared/$from" ]] || fail "/artifacts/$from redirect ($LOC)"
done
pass "/artifacts/... redirects to /shared/..."
# grep without -q reads the whole body. With -q it exits at the first match,
# curl then fails writing to the closed pipe (exit 23), and pipefail reports
# the pipeline as failed, which is how "cairn.js injected" flaked.
curl -sf -D "$WORK/shell.headers" "${AUTH[@]}" "$HOST/shared/$AID" > "$WORK/shell.html" || fail "shared shell"
grep "data-content-origin=\"http://$AID.localhost:$PORT\"" "$WORK/shell.html" >/dev/null || fail "shared shell content origin: $(cat "$WORK/shell.html")"
grep -i "^content-security-policy:.*frame-src http://\*.localhost:$PORT" "$WORK/shell.headers" >/dev/null || fail "shell frame-src: $(cat "$WORK/shell.headers")"
pass "the shared shell names the content origin and its CSP frames only content hosts"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$HOST/full/$AID")
[[ "$STATUS" == "200" ]] || fail "full-screen page ($STATUS)"
pass "the full-screen page renders"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$HOST/shared/not-a-uuid")
[[ "$STATUS" == "404" ]] || fail "/shared/not-a-uuid ($STATUS)"
pass "a shell page for an ID that is no artifact is not found"
# The artifact's content origin is <id>.localhost on the public URL's port.
CONTENT_HOST="$AID.localhost:$PORT"
curl -s -D "$WORK/boot.headers" -o "$WORK/boot.html" --resolve "$CONTENT_HOST:127.0.0.1" \
  "http://$CONTENT_HOST/_cairn/boot" || fail "content origin did not answer"
grep -i "^content-security-policy: frame-ancestors $HOST" "$WORK/boot.headers" >/dev/null || fail "boot page frame-ancestors: $(cat "$WORK/boot.headers")"
grep "cairn-app-origin" "$WORK/boot.html" >/dev/null || fail "boot page: $(cat "$WORK/boot.html")"
pass "the content origin serves the boot page, framed only by the app"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' --resolve "$CONTENT_HOST:127.0.0.1" "${AUTH[@]}" "http://$CONTENT_HOST/api/keys")
[[ "$STATUS" == "404" ]] || fail "content origin /api/keys ($STATUS)"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' --resolve "$CONTENT_HOST:127.0.0.1" "${AUTH[@]}" "http://$CONTENT_HOST/api/me")
[[ "$STATUS" == "401" ]] || fail "content origin /api/me with an API key ($STATUS)"
pass "the content origin refuses routes outside the allowlist, and API keys"

echo "== client-side database"
OCTET='Content-Type: application/octet-stream'  # the CSRF guard lets an anonymous write through only as JSON or octet-stream
# The CLI downloads the latest revision, runs the SQL on its own copy, and
# uploads a new encrypted revision when the statement wrote.
"$BIN" db query --artifact guestbook \
  "CREATE TABLE entries (id INTEGER PRIMARY KEY, message TEXT NOT NULL, author TEXT NOT NULL, created_at TEXT NOT NULL)" >/dev/null
"$BIN" db query --artifact guestbook \
  --params '["hello from e2e","e2e","2026-01-01T00:00:00Z"]' \
  "INSERT INTO entries (message, author, created_at) VALUES (?, ?, ?)" >/dev/null
"$BIN" db query --artifact guestbook "SELECT message FROM entries" | grep "hello from e2e" >/dev/null || fail "db round trip"
pass "SQL write + read through CLI"

"$BIN" db revisions --artifact guestbook --json | jq -e 'length == 2 and .[0].revision == 2 and .[0].epoch == 1' >/dev/null \
  || fail "db revisions: a read must not add one"
pass "each write is a revision, and a read adds none"

echo '[{"sql":"INSERT INTO entries (message, author, created_at) VALUES (?, ?, ?)","params":["from a batch","e2e","2026-01-02T00:00:00Z"]},{"sql":"SELECT count(*) AS n FROM entries"}]' \
  | "$BIN" db batch --artifact guestbook --json | jq -e 'length == 2 and .[1].rows[0][0] == 2' >/dev/null || fail "db batch"
pass "db batch runs a script in one transaction, one result per statement"

if "$BIN" db query --artifact guestbook "SELECT 1; DROP TABLE entries" >/dev/null 2>"$WORK/multi.err"; then
  fail "a statement string with two statements ran"
fi
grep -q "only one SQL statement" "$WORK/multi.err" || fail "multi-statement refusal: $(cat "$WORK/multi.err")"
pass "a statement string holding two statements is refused"

"$BIN" db download --artifact guestbook --out "$WORK/guestbook.db" >/dev/null
[[ "$(head -c 15 "$WORK/guestbook.db")" == "SQLite format 3" ]] || fail "db download is not a SQLite file"
"$BIN" db restore --artifact guestbook --revision 2 --json | jq -e '.restored == 2 and .revision == 4' >/dev/null || fail "db restore"
pass "db download writes the plaintext, and db restore uploads an old revision as a new one"

# The server holds ciphertext only: no entry text anywhere under dbs/, and an
# anonymous caller finds nothing on a private artifact.
if grep -rqa "hello from e2e" "$WORK/data/dbs"; then fail "plaintext database under the data dir"; fi
pass "no plaintext under the data dir's dbs/"
curl -sf -D "$WORK/db.headers" -o "$WORK/db.bin" "${AUTH[@]}" "$HOST/api/artifacts/$AID/versions/$VID/db" || fail "bearer read of the latest revision"
[[ "$(head -c 4 "$WORK/db.bin")" == "CRNB" ]] || fail "the revision is not a blob"
grep -qi '^x-cairn-revision: 4' "$WORK/db.headers" || fail "revision header: $(cat "$WORK/db.headers")"
grep -qi '^etag: "4"' "$WORK/db.headers" || fail "etag header: $(cat "$WORK/db.headers")"
pass "the server serves the latest revision as a sealed blob with its record"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$HOST/api/artifacts/$AID/versions/$VID/db")
[[ "$STATUS" == "404" ]] || fail "anonymous read of a private database ($STATUS)"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'If-Match: "0"' -H "$OCTET" "$HOST/api/artifacts/$AID/versions/$VID/db")
[[ "$STATUS" == "404" ]] || fail "anonymous write of a private database ($STATUS)"
pass "anonymous read and write on a private artifact are not found"

echo "== file storage"
echo "hello file" > "$WORK/note.txt"
"$BIN" files put "$WORK/note.txt" --artifact guestbook --path notes/hello.txt >/dev/null
"$BIN" files list --artifact guestbook | grep "notes/hello.txt" >/dev/null || fail "file list"
"$BIN" files get notes/hello.txt --artifact guestbook | grep "hello file" >/dev/null || fail "file get"
pass "file put + list + get through CLI"
# The server keeps no name: its list shows an address and an encrypted blob.
curl -sf "${AUTH[@]}" "$HOST/api/artifacts/$AID/versions/$VID/files" > "$WORK/files.json" || fail "bearer file list"
jq -e 'length == 1 and (.[0].address | test("^[0-9a-f]{64}$")) and .[0].epoch == 1' "$WORK/files.json" >/dev/null || fail "file list shape: $(cat "$WORK/files.json")"
if grep -q "hello" "$WORK/files.json"; then fail "the file list names the file"; fi
if grep -rqa "hello" "$WORK/data/files"; then fail "plaintext or a name under the data dir's files/"; fi
pass "the server lists an address and ciphertext, and keeps no name"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$HOST/api/artifacts/$AID/versions/$VID/files")
[[ "$STATUS" == "404" ]] || fail "anonymous file list not refused ($STATUS)"
pass "anonymous file list on a private artifact is not found"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$OCTET" \
  "$HOST/api/artifacts/$AID/versions/$VID/files/$(printf 'a%.0s' $(seq 1 64))" --data-binary 'x')
[[ "$STATUS" == "404" ]] || fail "anonymous file write not rejected ($STATUS)"
pass "anonymous file write rejected"
"$BIN" files delete notes/hello.txt --artifact guestbook >/dev/null
"$BIN" files list --artifact guestbook --json | jq -e 'length == 0' >/dev/null || fail "deleted file still listed"
if "$BIN" files get notes/hello.txt --artifact guestbook >/dev/null 2>&1; then fail "deleted file still served"; fi
pass "file delete"

echo "== re-upload + cross-version read"
"$BIN" push "$ROOT/examples/guestbook" --artifact guestbook --name v2 --changelog "second" --json > "$WORK/push2.json"
VID2=$(python3 -c "import json;print(json.load(open('$WORK/push2.json'))['version']['id'])")
[[ "$VID2" != "$VID" ]] || fail "second push created no new version"
# v2's database is fresh; the old version's data is still reachable.
"$BIN" db query --artifact guestbook --version "$VID2" "SELECT name FROM sqlite_master" | grep -v '^name$' | grep . >/dev/null \
  && fail "v2's database is not empty"
"$BIN" db query --artifact guestbook --version "$VID" "SELECT message FROM entries" \
  | grep "hello from e2e" >/dev/null || fail "old version data lost"
pass "per-version databases isolated; old data readable"
"$BIN" push "$ROOT/examples/guestbook" --artifact guestbook --overwrite latest --changelog "rewritten" >/dev/null
pass "re-upload (overwrite latest)"

echo "== encrypted content"
curl -sf "${AUTH[@]}" "$HOST/api/artifacts/$AID/versions/$VID" \
  | jq -e '.epoch == 1 and (.manifestHash | test("^[0-9a-f]{64}$")) and (.pushedBy | length > 0)' >/dev/null \
  || fail "version epoch, manifestHash, and pushedBy"
curl -sf -D "$WORK/manifest.headers" -o "$WORK/manifest.bin" "${AUTH[@]}" "$HOST/api/artifacts/$AID/versions/$VID/manifest" \
  || fail "manifest read"
grep -qi '^content-type: application/octet-stream' "$WORK/manifest.headers" || fail "manifest content type"
grep -qi '^cache-control: no-store' "$WORK/manifest.headers" || fail "manifest cache control"
[[ "$(head -c 4 "$WORK/manifest.bin")" == "CRNB" ]] || fail "manifest is not a blob"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$HOST/api/artifacts/$AID/versions/$VID/blobs/$(printf 'a%.0s' $(seq 1 32))")
[[ "$STATUS" == "404" ]] || fail "an unknown blob ($STATUS)"
if grep -rq "Guestbook" "$WORK/data/content"; then fail "plaintext under the data dir"; fi
pass "a push stores a blob manifest and ciphertext only"
echo "not a zip" > "$WORK/old.zip"
STATUS=$(curl -s -o "$WORK/oldclient.json" -w '%{http_code}' -X POST "${AUTH[@]}" -F "archive=@$WORK/old.zip" "$HOST/api/artifacts/$AID/versions")
[[ "$STATUS" == "400" ]] && grep -q "update the cairn tool" "$WORK/oldclient.json" || fail "old zip push not refused ($STATUS)"
pass "a zip push is refused with a pointer to update the cairn tool"

echo "== private gating"
# The shell page carries no artifact data and checks no access; the API does.
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: text/html' "$HOST/shared/$AID/$VID")
[[ "$STATUS" == "200" ]] || fail "shell page of a private artifact ($STATUS)"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$HOST/api/artifacts/$AID/versions/$VID/manifest")
[[ "$STATUS" == "404" ]] || fail "private manifest not gated ($STATUS)"
pass "private artifact: the page is open and carries nothing, the manifest is not found"

echo "== artifact create"
"$BIN" artifact create notes --description "e2e notes" --json > "$WORK/notes.json"
NID=$(python3 -c "import json;print(json.load(open('$WORK/notes.json'))['id'])")
curl -sf "${AUTH[@]}" "$HOST/api/artifacts/$NID/membership" > "$WORK/membership.json" || fail "membership read"
python3 - "$WORK/membership.json" <<'PY' || fail "membership chain"
import base64, json, sys
m = json.load(open(sys.argv[1]))
assert len(m["records"]) == 1, m
body = json.loads(base64.urlsafe_b64decode(m["records"][0]["body"] + "=="))
assert body["epoch"] == 1 and body["seq"] == 1 and body["members"] == [], body
assert body["team"] == "none" and not body["public"] and body["ownerFp"] in m["owners"], body
PY
curl -sf "${AUTH[@]}" "$HOST/api/artifacts/$NID/keys" \
  | python3 -c "import json,sys;k=json.load(sys.stdin);assert k['wraps']==[] and [e['epoch'] for e in k['estate']]==[1], k" \
  || fail "estate copy"
pass "artifact create signs the first record and stores the estate copy"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$HOST/api/artifacts/$NID/membership")
[[ "$STATUS" == "404" ]] || fail "anonymous membership read ($STATUS)"
pass "anonymous membership read is not found"

echo "== sharing"
# A second account, with its own CLI config so admin@e2e.test stays signed in
# in the main one.
CONFIG2="$WORK/config2/config.json"
echo "share-flow-strong-pw-1" | CAIRN_CONFIG="$CONFIG2" "$BIN" signup --host "$HOST" --email share@e2e.test --password-stdin >/dev/null
VERIFY_LINK3=$(grep -oE "$HOST/verify#token=[A-Za-z0-9_-]+" "$SERVER_LOG" | tail -1)
CAIRN_CONFIG="$CONFIG2" "$BIN" confirm-email "$VERIFY_LINK3" >/dev/null
echo "share-flow-strong-pw-1" | CAIRN_CONFIG="$CONFIG2" "$BIN" login --host "$HOST" --email share@e2e.test --password-stdin >/dev/null
BEARER2=$(python3 -c "import json;print('_'.join(json.load(open('$CONFIG2'))['apiKey'].split('_')[:3]))")
AUTH2=(-H "Authorization: Bearer $BEARER2")
"$BIN" push "$ROOT/examples/guestbook" --artifact notes --name v1 --json > "$WORK/notes-push.json"
NVID=$(python3 -c "import json;print(json.load(open('$WORK/notes-push.json'))['version']['id'])")
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH2[@]}" "$HOST/api/artifacts/$NID/versions/$NVID/manifest")
[[ "$STATUS" == "404" ]] || fail "a stranger reads the artifact before the share ($STATUS)"
pass "the second account cannot read the artifact before the share"

"$BIN" share notes share@e2e.test > "$WORK/share.txt" || fail "share: $(cat "$WORK/share.txt")"
grep -q "new; pinned unverified" "$WORK/share.txt" || fail "share did not pin the new key: $(cat "$WORK/share.txt")"
grep -q "added as viewer of notes" "$WORK/share.txt" || fail "share output: $(cat "$WORK/share.txt")"
"$BIN" members notes | grep -E "viewer +share@e2e.test +unverified" >/dev/null || fail "members after share"
pass "cairn share adds a viewer and pins their key unverified"
"$BIN" pin share@e2e.test --verified >/dev/null
"$BIN" members notes | grep -E "viewer +share@e2e.test +verified" >/dev/null || fail "members after pin --verified"
pass "cairn pin --verified shows in cairn members"

curl -sf "${AUTH2[@]}" "$HOST/shared/$NID/$NVID" | grep "data-artifact=\"$NID\"" >/dev/null || fail "the member cannot open the shell page"
curl -sf "${AUTH2[@]}" "$HOST/api/artifacts/$NID/versions/$NVID/manifest" >/dev/null || fail "the member cannot read the artifact"
curl -sf "${AUTH2[@]}" "$HOST/api/artifacts/$NID/keys" \
  | python3 -c "import json,sys;k=json.load(sys.stdin);assert [w['epoch'] for w in k['wraps']]==[1] and k['estate']==[], k" \
  || fail "the member holds no wrap of epoch 1"
CAIRN_CONFIG="$CONFIG2" "$BIN" members "$NID" | grep -E "owner +admin@e2e.test +unverified" >/dev/null || fail "members as the new viewer"
pass "the new viewer reads the artifact, holds the epoch 1 wrap, and verifies the chain"
"$BIN" share notes share@e2e.test --role editor | grep "promoted to editor" >/dev/null || fail "promotion"
pass "promotion succeeds"

# Demoting and unsharing start new epochs. They run on their own artifact, so
# the state the checks below read is left as it is.
"$BIN" artifact create epochdoc --json > "$WORK/epochdoc.json"
EID=$(jq -r .id "$WORK/epochdoc.json")
"$BIN" share epochdoc share@e2e.test --role editor >/dev/null || fail "sharing epochdoc with the editor"
"$BIN" share epochdoc share@e2e.test --role viewer > "$WORK/demote.txt" || fail "demotion: $(cat "$WORK/demote.txt")"
grep -q "demoted to viewer of epochdoc" "$WORK/demote.txt" || fail "demotion output: $(cat "$WORK/demote.txt")"
grep -q "started epoch 2" "$WORK/demote.txt" || fail "demotion did not start epoch 2: $(cat "$WORK/demote.txt")"
curl -sf "${AUTH2[@]}" "$HOST/api/artifacts/$EID/keys" \
  | python3 -c "import json,sys;k=json.load(sys.stdin);assert [w['epoch'] for w in k['wraps']]==[1,2], k" \
  || fail "the demoted viewer does not hold the wraps of epochs 1 and 2"
pass "demoting an editor starts epoch 2, and the viewer holds both wraps"

"$BIN" unshare epochdoc share@e2e.test --json > "$WORK/unshare.json" || fail "unshare: $(cat "$WORK/unshare.json")"
jq -e '.artifact == "'"$EID"'" and .epoch == 3 and .newEpoch == true and .link == ""
  and (.excluded | length == 1) and .excluded[0].email == "share@e2e.test" and .excluded[0].reason == "removed"' \
  "$WORK/unshare.json" >/dev/null || fail "unshare --json fields: $(cat "$WORK/unshare.json")"
[[ "$(curl -s -o /dev/null -w '%{http_code}' "${AUTH2[@]}" "$HOST/api/artifacts/$EID/keys")" != "200" ]] || fail "the removed member still reads their keys"
"$BIN" members epochdoc | grep "share@e2e.test" >/dev/null && fail "the removed member is still listed"
pass "cairn unshare starts epoch 3, excludes the member, and ends their access"
"$BIN" share epochdoc share@e2e.test | grep "dropped the exclusion of share@e2e.test" >/dev/null || fail "sharing by name did not drop the exclusion"
pass "sharing by name lists an excluded user again"

CAIRN_CONFIG="$CONFIG2" "$BIN" logout >/dev/null
python3 -c "import json;c=json.load(open('$CONFIG2'));assert c['apiKey']=='' and len(c['anchors'])==1, c" \
  || fail "logout dropped the keyring anchor"
echo "share-flow-strong-pw-1" | CAIRN_CONFIG="$CONFIG2" "$BIN" login --host "$HOST" --email share@e2e.test --password-stdin >/dev/null
CAIRN_CONFIG="$CONFIG2" "$BIN" members "$NID" | grep -E "editor +share@e2e.test +self" >/dev/null || fail "members after signing in again"
pass "logout keeps the keyring anchor, and signing in again reads the keyring against it"

echo "== keyring refusals"
"$BIN" members notes --json > "$WORK/members.json" || fail "members --json"
jq -e '(.artifact | type == "string") and (.epoch | type == "number") and (.seq | type == "number")
  and (.members | type == "array" and length == 2)
  and all(.members[]; has("user") and has("name") and has("email") and has("role") and has("fp") and has("state"))' \
  "$WORK/members.json" >/dev/null || fail "members --json fields: $(cat "$WORK/members.json")"
"$BIN" pin share@e2e.test --json > "$WORK/pin.json" || fail "pin --json"
jq -e '.email == "share@e2e.test" and (.user | length > 0) and (.fp | length == 64) and .prior == "verified" and .state == "verified"' \
  "$WORK/pin.json" >/dev/null || fail "pin --json fields: $(cat "$WORK/pin.json")"
pass "members --json and pin --json carry the fields an agent reads"

if "$BIN" share notes nobody@e2e.test >/dev/null 2>"$WORK/unknown.err"; then
  fail "share with an unknown email succeeded"
fi
grep -q "no user with that email or id" "$WORK/unknown.err" || fail "share failed for another reason: $(cat "$WORK/unknown.err")"
pass "share with an unknown email is refused"

# Roll the admin's keyring back in the server's own database, as a restore
# from backup would. Reading and writing the row straight in sqlite is the
# attack the anchor exists for.
keyring_row() {  # get, or put REV HEX
  python3 - "$WORK/data/cairn.db" "$@" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1], timeout=10)
who = "(SELECT id FROM users WHERE email = 'admin@e2e.test')"
if sys.argv[2] == "get":
    rev, kr = db.execute(f"SELECT rev, keyring FROM user_keyrings WHERE user_id = {who}").fetchone()
    print(rev, kr.hex())
else:
    db.execute(f"UPDATE user_keyrings SET rev = ?, keyring = ? WHERE user_id = {who}", (int(sys.argv[3]), bytes.fromhex(sys.argv[4])))
    db.commit()
PY
}
OLD_ROW=$(keyring_row get)
"$BIN" artifact create rollback-probe >/dev/null     # writes the keyring, so the anchor moves past OLD_ROW
NEW_ROW=$(keyring_row get)
[[ "$OLD_ROW" != "$NEW_ROW" ]] || fail "creating an artifact did not change the keyring"
keyring_row put $OLD_ROW
if "$BIN" members notes >/dev/null 2>"$WORK/rollback.err"; then
  fail "members accepted a rolled-back keyring"
fi
grep -q "older or altered keyring" "$WORK/rollback.err" || fail "rollback refused without the recovery message: $(cat "$WORK/rollback.err")"
grep -q "$CAIRN_CONFIG" "$WORK/rollback.err" || fail "the recovery message does not name the config file: $(cat "$WORK/rollback.err")"
grep -q "$HOST " "$WORK/rollback.err" || fail "the recovery message does not name the anchors entry: $(cat "$WORK/rollback.err")"
pass "a rolled-back keyring is refused, with how to recover"
keyring_row put $NEW_ROW
"$BIN" members notes >/dev/null || fail "members after the keyring was put back"
pass "the same keyring, put back, is accepted again"

echo "== team share"
# A new artifact, so the notes artifact above keeps the two members the
# checks before this section count. The editor is share@e2e.test; a third
# account, team@e2e.test, is the team member who waits for approval.
"$BIN" artifact create teamdoc --json > "$WORK/teamdoc.json"
TID=$(python3 -c "import json;print(json.load(open('$WORK/teamdoc.json'))['id'])")
"$BIN" push "$ROOT/examples/guestbook" --artifact teamdoc --name v1 --json > "$WORK/teamdoc-push.json"
TVID=$(python3 -c "import json;print(json.load(open('$WORK/teamdoc-push.json'))['version']['id'])")
"$BIN" share teamdoc share@e2e.test --role editor >/dev/null || fail "sharing teamdoc with the editor"
CONFIG3="$WORK/config3/config.json"
echo "team-flow-strong-pw-1" | CAIRN_CONFIG="$CONFIG3" "$BIN" signup --host "$HOST" --email team@e2e.test --password-stdin >/dev/null
VERIFY_LINK4=$(grep -oE "$HOST/verify#token=[A-Za-z0-9_-]+" "$SERVER_LOG" | tail -1)
CAIRN_CONFIG="$CONFIG3" "$BIN" confirm-email "$VERIFY_LINK4" >/dev/null
echo "team-flow-strong-pw-1" | CAIRN_CONFIG="$CONFIG3" "$BIN" login --host "$HOST" --email team@e2e.test --password-stdin >/dev/null
BEARER3=$(python3 -c "import json;print('_'.join(json.load(open('$CONFIG3'))['apiKey'].split('_')[:3]))")
AUTH3=(-H "Authorization: Bearer $BEARER3")
# team_batch makes a write as team@e2e.test through the CLI, each one a new
# table so it is always a write, and prints 200 or the status the server refused it with.
team_batch() {
  if CAIRN_CONFIG="$CONFIG3" "$BIN" db query --artifact teamdoc --version "$TVID" \
      "CREATE TABLE team_probe_$RANDOM$RANDOM (x INTEGER)" >/dev/null 2>"$WORK/team-write.err"; then
    echo 200
  else
    sed -n 's/.*(\([0-9][0-9][0-9]\))$/\1/p' "$WORK/team-write.err" | tail -1
  fi
}

"$BIN" team teamdoc viewer | grep "team set to viewer for teamdoc" >/dev/null || fail "cairn team viewer"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH3[@]}" "$HOST/api/artifacts/$TID/versions/$TVID/manifest")
[[ "$STATUS" == "404" ]] || fail "a team member reads before an approval ($STATUS)"
pass "a team share gives a new member nothing until they are approved"

"$BIN" approve teamdoc --json > "$WORK/pending.json" || fail "approve (list)"
jq -e '.artifact == "'"$TID"'" and (.pending | map(select(.email == "team@e2e.test")) | length == 1)
  and all(.pending[]; has("user") and has("name") and has("email") and has("fp") and has("state"))
  and (.pending[] | select(.email == "team@e2e.test") | .state == "new" and (.fp | length == 64))' \
  "$WORK/pending.json" >/dev/null || fail "approve --json fields: $(cat "$WORK/pending.json")"
CAIRN_CONFIG="$CONFIG2" "$BIN" approve teamdoc | grep -E "^new +.*team@e2e.test" >/dev/null || fail "the editor does not see the new member"
pass "cairn approve lists the new member, to the owner and to an editor"

CAIRN_CONFIG="$CONFIG2" "$BIN" approve teamdoc team@e2e.test > "$WORK/approve.txt" || fail "approve: $(cat "$WORK/approve.txt")"
grep -q "approved for teamdoc" "$WORK/approve.txt" || fail "approve output: $(cat "$WORK/approve.txt")"
grep -q "they can read it now" "$WORK/approve.txt" || fail "approve output says nothing of reading: $(cat "$WORK/approve.txt")"
curl -sf "${AUTH3[@]}" "$HOST/shared/$TID/$TVID" | grep "data-artifact=\"$TID\"" >/dev/null || fail "the approved member cannot open the shell page"
curl -sf "${AUTH3[@]}" "$HOST/api/artifacts/$TID/versions/$TVID/manifest" >/dev/null || fail "the approved member cannot read"
curl -sf "${AUTH3[@]}" "$HOST/api/artifacts/$TID/keys" \
  | python3 -c "import json,sys;k=json.load(sys.stdin);assert [w['epoch'] for w in k['wraps']]==[1], k" \
  || fail "the approved member holds no wrap of epoch 1"
[[ "$(team_batch)" == "403" ]] || fail "an approved member writes before the owner lists them"
pass "an editor's approval lets the member read, and not write"

"$BIN" approve teamdoc --json | jq -e '.pending[] | select(.email == "team@e2e.test") | .state == "approved"' >/dev/null \
  || fail "the owner does not see the approval"
"$BIN" approve teamdoc | grep "the owner's next cairn team $TID viewer|editor or cairn share lists them" >/dev/null \
  || fail "the owner's list does not say how an approved member is listed"
if CAIRN_CONFIG="$CONFIG2" "$BIN" approve teamdoc --json | jq -e '.pending[] | select(.email == "team@e2e.test")' >/dev/null; then
  fail "the editor still sees an approved member"
fi
pass "an approved member shows to the owner only"

"$BIN" team teamdoc editor > "$WORK/team-editor.txt" || fail "team editor: $(cat "$WORK/team-editor.txt")"
grep -q "listed approved team member team@e2e.test" "$WORK/team-editor.txt" || fail "team editor did not list the member: $(cat "$WORK/team-editor.txt")"
"$BIN" members teamdoc | grep -E "editor +team@e2e.test" >/dev/null || fail "members after the owner listed the team member"
[[ "$(team_batch)" == "200" ]] || fail "a listed member cannot write"
pass "the owner's next record lists the approved member, who can then write"

"$BIN" unshare teamdoc team@e2e.test > "$WORK/team-unshare.txt" || fail "unshare of the team member: $(cat "$WORK/team-unshare.txt")"
grep -q "started epoch 2" "$WORK/team-unshare.txt" || fail "unshare did not start epoch 2: $(cat "$WORK/team-unshare.txt")"
[[ "$(team_batch)" != "200" ]] || fail "an unshared team member still writes"
pass "unshare on a team artifact removes the member in a new epoch"

echo "== public link"
# A new artifact, private until cairn public turns the link on. team@e2e.test
# is a signed-in non-member. The link token is derived from the AK in the
# link's fragment the way e2e.LinkToken does: HKDF-SHA256, no salt, with
# info = Enc("cairn/v1/link-token", artifact, epoch).
"$BIN" artifact create pubdoc --json > "$WORK/pubdoc.json"
PID=$(jq -r .id "$WORK/pubdoc.json")
"$BIN" push "$ROOT/examples/guestbook" --artifact pubdoc --name v1 --json > "$WORK/pubdoc-push.json"
PVID=$(jq -r .version.id "$WORK/pubdoc-push.json")
pub_status() { # pub_status METHOD PATH [CURL ARGS...]
  local method="$1" path="$2"; shift 2
  curl -s -o /dev/null -w '%{http_code}' -X "$method" "$@" "$HOST$path"
}
STATUS=$(pub_status GET "/api/artifacts/$PID/membership")
[[ "$STATUS" == "404" ]] || fail "an anonymous caller reads a private artifact ($STATUS)"

"$BIN" public pubdoc on --json > "$WORK/pub.json" || fail "cairn public on"
jq -e '.artifact == "'"$PID"'" and .public == true and .publicWrites == false and .epoch == 1 and .unchanged == false' \
  "$WORK/pub.json" >/dev/null || fail "public --json fields: $(cat "$WORK/pub.json")"
LINK=$(jq -r .link "$WORK/pub.json")
[[ "$LINK" == "$HOST/shared/$PID#k="* ]] || fail "unexpected public link: $LINK"
LINK_TOKEN=$(python3 - "$LINK" "$PID" <<'PY'
import base64, hashlib, hmac, re, struct, sys
link, artifact = sys.argv[1:3]
m = re.fullmatch(r".*#k=([A-Za-z0-9_-]{43})&e=([1-9][0-9]*)&o=([0-9a-f]{64})", link)
assert m, link
pad = lambda s: s + "=" * (-len(s) % 4)
ak = base64.urlsafe_b64decode(pad(m.group(1)))
assert len(ak) == 32
enc = lambda *fields: b"".join(struct.pack(">I", len(f)) + f for f in fields)
info = enc(b"cairn/v1/link-token", artifact.encode(), m.group(2).encode())
prk = hmac.new(b"\0" * 32, ak, hashlib.sha256).digest()
okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
print(base64.urlsafe_b64encode(okm).rstrip(b"=").decode())
PY
)
[[ -n "$LINK_TOKEN" ]] || fail "could not derive the link token"
LINKH=(-H "X-Cairn-Link-Token: $LINK_TOKEN")
WRONGH=(-H "X-Cairn-Link-Token: $(printf 'A%.0s' $(seq 1 43))")
pass "cairn public on prints a link whose fragment holds the key, the epoch, and o"

[[ "$(pub_status GET "/api/artifacts/$PID/membership" "${LINKH[@]}")" == "200" ]] || fail "the right token does not read the membership"
[[ "$(pub_status GET "/api/artifacts/$PID/membership")" == "404" ]] || fail "no token reads the membership"
[[ "$(pub_status GET "/api/artifacts/$PID/membership" "${WRONGH[@]}")" == "404" ]] || fail "a wrong token reads the membership"
curl -sf "${LINKH[@]}" "$HOST/shared/$PID/$PVID" | grep "data-artifact=\"$PID\"" >/dev/null || fail "the shell page does not open"
curl -sf "${LINKH[@]}" "$HOST/api/artifacts/$PID/versions/$PVID/manifest" >/dev/null || fail "the right token does not read the content"
[[ "$(pub_status GET "/api/artifacts/$PID/versions/$PVID/manifest" "${WRONGH[@]}")" != "200" ]] || fail "a wrong token reads the content"
curl -sf "${LINKH[@]}" "$HOST/api/artifacts/$PID/membership" \
  | jq -e '.records | length == 2' >/dev/null || fail "the link's membership holds the public record"
pass "an anonymous caller reads with the right token, and gets 404 with none or a wrong one"

# A write needs a signed multipart body, which curl cannot make, so these
# probes send an empty PUT: the access gate answers 403 or 404 before the body
# is read, and a write the gate admits is refused as malformed, with 400.
PUB_DB="/api/artifacts/$PID/versions/$PVID/db"
pub_put() { pub_status PUT "$PUB_DB" -H 'If-Match: "0"' -H "$OCTET" "$@"; }
[[ "$(pub_put "${LINKH[@]}")" == "403" ]] || fail "an anonymous write with the token is not refused"
[[ "$(pub_put "${AUTH3[@]}" "${LINKH[@]}")" == "403" ]] || fail "a signed-in link holder writes while writes are off"
pass "public writes are refused while the switch is off, and to an anonymous caller"

"$BIN" public pubdoc on --writes on --json > "$WORK/pub-writes.json" || fail "cairn public on --writes on"
jq -e '.public == true and .publicWrites == true and .unchanged == false and .link == "'"$LINK"'"' \
  "$WORK/pub-writes.json" >/dev/null || fail "public --writes on --json: $(cat "$WORK/pub-writes.json")"
[[ "$(pub_put "${AUTH3[@]}" "${LINKH[@]}")" == "400" ]] || fail "the gate does not admit a signed-in link holder with writes on"
[[ "$(pub_put "${LINKH[@]}")" == "403" ]] || fail "an anonymous write with the token passes the gate with writes on"
[[ "$(pub_put "${AUTH3[@]}")" == "404" ]] || fail "a session without the token passes the gate"
[[ "$(pub_status GET "/api/artifacts/$PID/membership" "${LINKH[@]}")" == "200" ]] || fail "the link stopped working after the writes switch"
pass "cairn public --writes on lets a signed-in link holder write, with the same link"

"$BIN" public pubdoc on | grep "already public; nothing changed" >/dev/null || fail "a second public on wrote a record"
"$BIN" public pubdoc off --json > "$WORK/pub-off.json" || fail "cairn public off: $(cat "$WORK/pub-off.json")"
jq -e '.public == false and .newEpoch == true and .epoch == 2 and .link == "" and .unchanged == false' \
  "$WORK/pub-off.json" >/dev/null || fail "public off --json fields: $(cat "$WORK/pub-off.json")"
[[ "$(pub_status GET "/api/artifacts/$PID/membership" "${LINKH[@]}")" == "404" ]] || fail "the old link works after public off"
"$BIN" public pubdoc on --json > "$WORK/pub-again.json" || fail "cairn public on after off"
jq -e '.epoch == 2 and .link != "'"$LINK"'"' "$WORK/pub-again.json" >/dev/null || fail "public on after off kept the old link: $(cat "$WORK/pub-again.json")"
[[ "$(pub_status GET "/api/artifacts/$PID/membership" "${LINKH[@]}")" == "404" ]] || fail "the old link works under the new link"
pass "public off starts epoch 2; turned on again, the artifact has a new link and the old one stays dead"

echo "== backup"
"$BIN" backup --data-dir "$WORK/data" --out "$WORK/backup" >/dev/null
[[ -f "$WORK/backup/cairn.db" ]] || fail "backup missing metadata db"
pass "backup produced"

echo "== keys + password reset"
"$BIN" keys list | grep "(device)" >/dev/null || fail "keys list"
pass "keys list shows the device key"

# A second account, so resetting its password doesn't disturb admin@e2e.test's
# session above.
SIGNUP2_OUT="$WORK/signup2.txt"
echo "reset-flow-strong-pw-1" | "$BIN" signup --host "$HOST" --email reset@e2e.test --password-stdin >"$SIGNUP2_OUT"
RECOVERY_CODE=$(sed -n 's/^  \([A-Z2-7-]\{1,\}\)$/\1/p' "$SIGNUP2_OUT" | head -1)
[[ -n "$RECOVERY_CODE" ]] || fail "no recovery code in signup output"
VERIFY_LINK2=$(grep -oE "$HOST/verify#token=[A-Za-z0-9_-]+" "$SERVER_LOG" | tail -1)
"$BIN" confirm-email "$VERIFY_LINK2" >/dev/null
pass "second account signed up, with a saved recovery code"

if echo "password1" | "$BIN" signup --host "$HOST" --email weak@e2e.test --password-stdin >/dev/null 2>"$WORK/weak.err"; then
  fail "signup with a weak password succeeded"
fi
grep -q "too weak" "$WORK/weak.err" || fail "weak signup failed for another reason: $(cat "$WORK/weak.err")"
pass "signup with a weak password is refused"

"$BIN" forgot --host "$HOST" --email reset@e2e.test >/dev/null
RESET_LINK=$(grep -oE "$HOST/reset#token=[A-Za-z0-9_-]+" "$SERVER_LOG" | tail -1)
[[ -n "$RESET_LINK" ]] || fail "no reset link in server log"
echo "reset-flow-even-stronger-pw-2" | "$BIN" reset "$RESET_LINK" --recovery-code "$RECOVERY_CODE" --password-stdin >/dev/null
pass "password reset via recovery code"

if echo "reset-flow-strong-pw-1" | "$BIN" login --host "$HOST" --email reset@e2e.test --password-stdin >/dev/null 2>"$WORK/oldpw.err"; then
  fail "login with the old password succeeded after the reset"
fi
grep -q "invalid email or password" "$WORK/oldpw.err" || fail "old-password login failed for another reason: $(cat "$WORK/oldpw.err")"
pass "the old password no longer logs in"

echo "reset-flow-even-stronger-pw-2" | "$BIN" login --host "$HOST" --email reset@e2e.test --password-stdin >/dev/null
"$BIN" whoami | grep reset@e2e.test >/dev/null || fail "login with the new password"
pass "login with the reset password"

LOGOUT_KEY=$(python3 -c "import json;print(json.load(open('$CAIRN_CONFIG'))['apiKey'])")
[[ -n "$LOGOUT_KEY" ]] || fail "no stored API key before logout"
CAIRN_HOST="$HOST" CAIRN_API_KEY="$LOGOUT_KEY" "$BIN" whoami >/dev/null || fail "the device key does not authenticate before logout"
"$BIN" logout >/dev/null
if "$BIN" whoami >/dev/null 2>&1; then
  fail "whoami succeeded after logout"
fi
pass "logout clears the stored login; whoami now fails"
if CAIRN_HOST="$HOST" CAIRN_API_KEY="$LOGOUT_KEY" "$BIN" whoami >/dev/null 2>&1; then
  fail "the logged-out device key still authenticates"
fi
pass "logout revoked the device key on the server"

echo "== browser account pages"
for page in signup verify login forgot reset; do
  curl -s -D - -o /dev/null "$HOST/$page" | grep -i "^content-security-policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'" >/dev/null \
    || fail "/$page lacks the app CSP"
  script=$(curl -s "$HOST/$page" | grep -oE 'src="/[a-z0-9-]+\.js"' | tail -1 | cut -d'"' -f2)
  curl -s -D - -o /dev/null "$HOST$script" | grep -i '^content-type: text/javascript' >/dev/null \
    || fail "$script is not served as JavaScript"
done
pass "account pages send the app CSP and their scripts load"

echo "== browser account flows"
# The same flows the account pages run (account.mjs), with real Argon2id,
# against this server: sign up, verify, sign in, reset with the recovery code.
command -v node >/dev/null || fail "node is required for the browser account flows"
node "$ROOT/scripts/e2e-accounts.mjs" "$HOST" "$SERVER_LOG" admin@e2e.test e2e-password-1 \
  || fail "browser account flows"
pass "browser sign-up, verify, sign-in, reset, sign-out"
echo "browser-flow-even-stronger-pw-2" | "$BIN" login --host "$HOST" --email web@e2e.test --password-stdin >/dev/null \
  || fail "CLI login to the browser-created account"
"$BIN" whoami | grep web@e2e.test >/dev/null || fail "whoami for the browser-created account"
pass "CLI signs in to the account the browser created and reset"

echo
echo "all e2e checks passed"
