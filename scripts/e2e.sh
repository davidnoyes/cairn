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
"$BIN" whoami | grep -q admin@e2e.test || fail "whoami"
pass "CLI signup + confirm-email + login + whoami"

# Headless use: the config file holds the full four-part API key; only the
# two-part bearer `cairn_<keyId>_<authSecret>` ever goes on the wire; the
# keySecret never leaves this machine.
API_KEY=$(python3 -c "import json;print(json.load(open('$CAIRN_CONFIG'))['apiKey'])")
BEARER=$(echo "$API_KEY" | cut -d'_' -f1-3)
CAIRN_HOST="$HOST" CAIRN_API_KEY="$API_KEY" "$BIN" whoami | grep -q admin@e2e.test || fail "API key auth"
pass "API key auth"

echo "== push"
"$BIN" push "$ROOT/examples/guestbook" --artifact guestbook --create --public \
  --name v1 --changelog "first" --json > "$WORK/push1.json"
AID=$(python3 -c "import json;print(json.load(open('$WORK/push1.json'))['artifact']['id'])")
VID=$(python3 -c "import json;print(json.load(open('$WORK/push1.json'))['version']['id'])")
pass "pushed guestbook ($AID / $VID)"

echo "== resource reference"
curl -sf -X POST "$HOST/api/artifacts/$AID/resources" \
  -H "Authorization: Bearer $BEARER" -H 'Content-Type: application/json' \
  -d '{"type":"claude-session","value":"sess-e2e"}' >/dev/null
curl -sf "$HOST/api/artifacts/sess-e2e" | grep -q "$AID" || fail "API lookup by resource value"
pass "API resolves resource value to artifact"
"$BIN" artifact show sess-e2e | grep -q "$AID" || fail "CLI lookup by resource value"
pass "CLI resolves resource value"

echo "== serving"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$HOST/artifacts/$AID")
[[ "$LOC" == "$HOST/artifacts/$AID/$VID/" || "$LOC" == "/artifacts/$AID/$VID/" ]] || fail "latest redirect ($LOC)"
pass "artifact redirects to latest version"
curl -sf "$HOST/artifacts/$AID/$VID/" | grep -q "Guestbook" || fail "index served"
pass "index.html served"
curl -sf "$HOST/artifacts/$AID/$VID/cairn.js" | grep -q "cairn.js" || fail "cairn.js injected"
pass "cairn.js available inside version"
curl -sf "$HOST/shared/$AID" | grep -q "iframe" || fail "shared shell"
pass "shared shell renders"

echo "== shared database"
"$BIN" db query --artifact guestbook \
  "CREATE TABLE entries (id INTEGER PRIMARY KEY, message TEXT NOT NULL, author TEXT NOT NULL, created_at TEXT NOT NULL)" >/dev/null
"$BIN" db query --artifact guestbook \
  --params '["hello from e2e","e2e","2026-01-01T00:00:00Z"]' \
  "INSERT INTO entries (message, author, created_at) VALUES (?, ?, ?)" >/dev/null
"$BIN" db query --artifact guestbook "SELECT message FROM entries" | grep -q "hello from e2e" || fail "db round trip"
pass "SQL write + read through CLI"

# Anonymous read works (public artifact), anonymous write is rejected.
curl -sf -X POST "$HOST/api/artifacts/$AID/versions/$VID/db/query" \
  -H 'Content-Type: application/json' -d '{"sql":"SELECT COUNT(*) FROM entries"}' | grep -q '\[\[1\]\]' \
  || fail "anonymous read"
pass "anonymous read on public artifact"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/api/artifacts/$AID/versions/$VID/db/query" \
  -H 'Content-Type: application/json' -d '{"sql":"DELETE FROM entries"}')
[[ "$STATUS" == "400" ]] || fail "anonymous write not rejected ($STATUS)"
pass "anonymous write rejected"

echo "== file storage"
echo "hello file" > "$WORK/note.txt"
"$BIN" files put "$WORK/note.txt" --artifact guestbook --path notes/hello.txt >/dev/null
"$BIN" files list --artifact guestbook | grep -q "notes/hello.txt" || fail "file list"
"$BIN" files get notes/hello.txt --artifact guestbook | grep -q "hello file" || fail "file get"
pass "file put + list + get through CLI"
curl -sf "$HOST/api/artifacts/$AID/versions/$VID/files/notes/hello.txt" | grep -q "hello file" \
  || fail "anonymous file read"
pass "anonymous file read on public artifact"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H 'Content-Type: application/octet-stream' \
  "$HOST/api/artifacts/$AID/versions/$VID/files/evil.txt" --data-binary 'x')
[[ "$STATUS" == "401" ]] || fail "anonymous file write not rejected ($STATUS)"
pass "anonymous file write rejected"
"$BIN" files delete notes/hello.txt --artifact guestbook >/dev/null
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$HOST/api/artifacts/$AID/versions/$VID/files/notes/hello.txt")
[[ "$STATUS" == "404" ]] || fail "deleted file still served ($STATUS)"
pass "file delete"

echo "== re-upload + cross-version read"
"$BIN" push "$ROOT/examples/guestbook" --artifact guestbook --name v2 --changelog "second" --json > "$WORK/push2.json"
VID2=$(python3 -c "import json;print(json.load(open('$WORK/push2.json'))['version']['id'])")
[[ "$VID2" != "$VID" ]] || fail "second push created no new version"
# v2's database is fresh; the old version's data is still reachable read-only.
curl -sf -X POST "$HOST/api/artifacts/$AID/versions/$VID/db/query" \
  -H 'Content-Type: application/json' -d '{"sql":"SELECT message FROM entries"}' \
  | grep -q "hello from e2e" || fail "old version data lost"
pass "per-version databases isolated; old data readable"
"$BIN" push "$ROOT/examples/guestbook" --artifact guestbook --overwrite latest --changelog "rewritten" >/dev/null
pass "re-upload (overwrite latest)"

echo "== private gating"
"$BIN" artifact update guestbook --public false >/dev/null
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: text/html' "$HOST/artifacts/$AID/$VID/")
[[ "$STATUS" == "302" ]] || fail "private page not gated ($STATUS)"
pass "private artifact redirects to login"

echo "== backup"
"$BIN" backup --data-dir "$WORK/data" --out "$WORK/backup" >/dev/null
[[ -f "$WORK/backup/cairn.db" ]] || fail "backup missing metadata db"
pass "backup produced"

echo "== keys + password reset"
"$BIN" keys list | grep -q "(device)" || fail "keys list"
pass "keys list shows the device key"

# A second account, so resetting its password doesn't disturb admin@e2e.test's
# session above.
SIGNUP2_OUT="$WORK/signup2.txt"
echo "reset-flow-strong-pw-1" | "$BIN" signup --host "$HOST" --email reset@e2e.test --password-stdin >"$SIGNUP2_OUT"
RECOVERY_CODE=$(sed -n 's/^  \([A-Z2-7-]\{1,\}\)$/\1/p' "$SIGNUP2_OUT")
[[ -n "$RECOVERY_CODE" ]] || fail "no recovery code in signup output"
VERIFY_LINK2=$(grep -oE "$HOST/verify#token=[A-Za-z0-9_-]+" "$SERVER_LOG" | tail -1)
"$BIN" confirm-email "$VERIFY_LINK2" >/dev/null
pass "second account signed up, with a saved recovery code"

if echo "password1" | "$BIN" signup --host "$HOST" --email weak@e2e.test --password-stdin >/dev/null 2>&1; then
  fail "signup with a weak password succeeded"
fi
pass "signup with a weak password is refused"

"$BIN" forgot --host "$HOST" --email reset@e2e.test >/dev/null
RESET_LINK=$(grep -oE "$HOST/reset#token=[A-Za-z0-9_-]+" "$SERVER_LOG" | tail -1)
[[ -n "$RESET_LINK" ]] || fail "no reset link in server log"
echo "reset-flow-even-stronger-pw-2" | "$BIN" reset "$RESET_LINK" --recovery-code "$RECOVERY_CODE" --password-stdin >/dev/null
pass "password reset via recovery code"

if echo "reset-flow-strong-pw-1" | "$BIN" login --host "$HOST" --email reset@e2e.test --password-stdin >/dev/null 2>&1; then
  fail "login with the old password succeeded after the reset"
fi
pass "the old password no longer logs in"

echo "reset-flow-even-stronger-pw-2" | "$BIN" login --host "$HOST" --email reset@e2e.test --password-stdin >/dev/null
"$BIN" whoami | grep -q reset@e2e.test || fail "login with the new password"
pass "login with the reset password"

LOGOUT_KEY=$(python3 -c "import json;print(json.load(open('$CAIRN_CONFIG'))['apiKey'])")
[[ -n "$LOGOUT_KEY" ]] || fail "no stored API key before logout"
"$BIN" logout >/dev/null
if "$BIN" whoami >/dev/null 2>&1; then
  fail "whoami succeeded after logout"
fi
pass "logout clears the stored login; whoami now fails"
if CAIRN_HOST="$HOST" CAIRN_API_KEY="$LOGOUT_KEY" "$BIN" whoami >/dev/null 2>&1; then
  fail "the logged-out device key still authenticates"
fi
pass "logout revoked the device key on the server"

echo
echo "all e2e checks passed"
