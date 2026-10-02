#!/usr/bin/env bash
# Checks the token exchange for people (#28, #34) against the real GitHub API
# and a real Cloudflare account, with the broker running under `wrangler dev`:
#   - A person with write access gets a token for a repo, by name and by ID,
#     named cf-oidc:user:<login>:<repo>, and can revoke it.
#   - team_id matches only a team they're in, in the pinned org.
#   - Repos in another org, or that they can't see, are refused, and so is an
#     Actions profile.
#   - Installation tokens, rejected tokens, no token and bad bodies are refused,
#     and a gh token doesn't pass as a job's OIDC token.
#   - The removed /v1 routes are a 404.
# Each case checks the HTTP status and the reason in the broker's audit log.
#
# Usage:
#   scripts/test-user-tokens.sh [owner/repo]
#
# The repo (default cf-contrib/cf-oidc-auth) must be one you can write to. Its
# owner becomes github.owner_id. Run it inside the dev shell (`nix develop`).
#
# Needs:
#   - CLOUDFLARE_ACCOUNT_ID: the account the broker mints in.
#   - The broker token in the local Secrets Store, under the store_id and
#     secret_name in packages/cf-oidc-broker/wrangler.toml:
#       cd packages/cf-oidc-broker
#       wrangler secrets-store secret create 00000000000000000000000000000000 --name cf-auth-broker-token --scopes workers
#   - gh, logged in. The script uses gh's own login, ignoring GITHUB_TOKEN and
#     GH_TOKEN, as `env -u GITHUB_TOKEN -u GH_TOKEN gh auth token` would.
#   - Optional TEST_PERMISSION: the permission group the test tokens get
#     (default "Account Settings Read").
#   - Optional TEST_PORT: the port for wrangler dev (default 8787).
#   - Optional TEST_PERSIST_TO: wrangler's local state directory, if the secret
#     was created with --persist-to (default .wrangler/state).
#   - Optional TEST_READ_ONLY_REPO: an owner/repo in the same org where you're
#     only a reader or triager, to check that a profile needing write refuses it.
#
# It replaces src/policy.json while it runs and puts yours back afterwards.
# Every token it mints is revoked before it exits.
#
# Prints no secrets: the output is safe to share.
set -euo pipefail

for arg in "$@"; do
  case $arg in
    -h | --help)
      sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
      exit 0
      ;;
    -*)
      echo "unknown option: $arg (see --help)" >&2
      exit 2
      ;;
  esac
done
REPO=${1:-cf-contrib/cf-oidc-auth}
OWNER=${REPO%%/*}
PERMISSION=${TEST_PERMISSION:-Account Settings Read}
PORT=${TEST_PORT:-8787}
BROKER="http://localhost:$PORT"

die() {
  echo "error: $*" >&2
  exit 1
}

for tool in gh jq curl pnpm; do command -v "$tool" >/dev/null || die "$tool is required"; done
[[ ${CLOUDFLARE_ACCOUNT_ID:-} =~ ^[0-9a-f]{32}$ ]] || die "set CLOUDFLARE_ACCOUNT_ID to the account's 32-character ID"
[[ $REPO =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die "the repo must be owner/name"

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BROKER_DIR="$ROOT/packages/cf-oidc-broker"
POLICY="$BROKER_DIR/src/policy.json"
WORK=$(mktemp -d)
LOG="$WORK/wrangler.log"
WRANGLER_PID=""
MINTED=()

# ---------------------------------------------------------------------------
# GitHub: who's running this, and the IDs the policy pins
# ---------------------------------------------------------------------------

GH_USER_TOKEN=$(env -u GITHUB_TOKEN -u GH_TOKEN gh auth token) || die "gh isn't logged in; run gh auth login"
[[ $GH_USER_TOKEN == ghs_* ]] && die "gh's token is an installation token; log in as a person"
gh_api() { env -u GITHUB_TOKEN -u GH_TOKEN gh api "$@"; }

LOGIN=$(gh_api user --jq .login)
REPO_JSON=$(gh_api "repos/$REPO") || die "can't see $REPO"
REPO_ID=$(jq -r .id <<<"$REPO_JSON")
OWNER_ID=$(jq -r .owner.id <<<"$REPO_JSON")
jq -e '.permissions.push' <<<"$REPO_JSON" >/dev/null || die "$LOGIN can't write to $REPO; pick a repo you can"
TEAM_ID=$(gh_api 'user/teams?per_page=100' --jq "[.[] | select(.organization.id == $OWNER_ID)][0].id // empty")
echo "gh login: $LOGIN (token ${GH_USER_TOKEN:0:4}…), repo $REPO ($REPO_ID), owner $OWNER ($OWNER_ID), team ${TEAM_ID:-none}"

# ---------------------------------------------------------------------------
# Policy and broker
# ---------------------------------------------------------------------------

# Runs on every exit. Nothing in it may fail: under set -e, a failing command would
# end the trap early and leave the test policy in place of yours.
cleanup() {
  set +e
  local tok
  for tok in "${MINTED[@]}"; do
    revoke "$tok" >/dev/null
  done
  if [[ -f $WORK/policy.json.saved ]]; then mv "$WORK/policy.json.saved" "$POLICY"; else rm -f "$POLICY"; fi
  if [[ -n $WRANGLER_PID ]]; then
    kill "$WRANGLER_PID" 2>/dev/null
    wait "$WRANGLER_PID" 2>/dev/null
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

[[ -f $POLICY ]] && cp "$POLICY" "$WORK/policy.json.saved"

jq -n \
  --arg audience "$BROKER" --arg owner "$OWNER_ID" --arg repo "$REPO_ID" --arg team "$TEAM_ID" \
  --arg permission "$PERMISSION" --arg account "com.cloudflare.api.account.$CLOUDFLARE_ACCOUNT_ID" '
  { policies: [{ permissions: [$permission], resources: { ($account): "*" } }] } as $token
  | {
      version: 1,
      github: { audience: $audience, owner_id: $owner },
      profiles: ([
        { name: "ci", match: { repository_id: $repo }, token: $token },
        { name: "me", subject: "users", match: { repository_permission: "write" }, token: $token },
        { name: "me-bad-team", subject: "users", match: { team_id: "1", repository_permission: "read" }, token: $token }
      ] + if $team == "" then [] else [
        { name: "me-team", subject: "users", match: { team_id: $team, repository_permission: "read" }, token: $token }
      ] end)
    }' >"$POLICY"

curl -s -o /dev/null "$BROKER/" && die "something already listens on port $PORT; stop it or set TEST_PORT"

STORE_ID=$(sed -n 's/^store_id *= *"\([^"]*\)".*/\1/p' "$BROKER_DIR/wrangler.toml")
SECRET_NAME=$(sed -n 's/^secret_name *= *"\([^"]*\)".*/\1/p' "$BROKER_DIR/wrangler.toml")
LIST_ARGS=(secrets-store secret list "$STORE_ID")
[[ -n ${TEST_PERSIST_TO:-} ]] && LIST_ARGS+=(--persist-to "$TEST_PERSIST_TO")
(cd "$BROKER_DIR" && pnpm exec wrangler "${LIST_ARGS[@]}" 2>&1) | grep -q "$SECRET_NAME" ||
  die "no $SECRET_NAME secret in the local store $STORE_ID; create it from packages/cf-oidc-broker (see --help)"

echo "starting wrangler dev on $BROKER"
DEV_ARGS=(--port "$PORT" --show-interactive-dev-session=false --var "CF_OIDC_BROKER_ACCOUNT_ID:$CLOUDFLARE_ACCOUNT_ID")
[[ -n ${TEST_PERSIST_TO:-} ]] && DEV_ARGS+=(--persist-to "$TEST_PERSIST_TO")
(cd "$BROKER_DIR" && exec pnpm exec wrangler dev "${DEV_ARGS[@]}") >"$LOG" 2>&1 &
WRANGLER_PID=$!

for _ in $(seq 60); do
  status=$(curl -s -o /dev/null -w '%{http_code}' "$BROKER/healthz" || true)
  [[ $status == 200 ]] && break
  if [[ $status == 500 ]]; then
    sed -n 's/.*\("reason":"[^"]*"\).*/\1/p; /policy.invalid/p' "$LOG" | tail -5 >&2
    die "/healthz returned 500: is the broker token in the local Secrets Store? (see --help)"
  fi
  kill -0 "$WRANGLER_PID" 2>/dev/null || { tail -20 "$LOG" >&2; die "wrangler dev exited"; }
  sleep 1
done
[[ $status == 200 ]] || { tail -20 "$LOG" >&2; die "the broker didn't come up"; }

# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

PASSED=0
FAILED=0

GRANT=urn:ietf:params:oauth:grant-type:token-exchange
ACCESS=urn:ietf:params:oauth:token-type:access_token
ID_TOKEN=urn:ietf:params:oauth:token-type:id_token

# request <subject_token|-> <subject_token_type> <fields|-> sets STATUS, REASON and,
# on a 200, TOKEN_ID. <fields> is a JSON object of the broker's own parameters. The
# token goes to curl on stdin, never on argv (printf is a builtin); the response
# stays in $WORK.
request() {
  local token=$1 type=$2 fields=$3 before extra=""
  before=$(wc -l <"$LOG")
  [[ $fields != - ]] && { extra=${fields#\{}; extra=${extra%\}}; }
  [[ -n $extra ]] && extra=",$extra"
  local subject=""
  [[ $token != - ]] && subject=$(printf ',"subject_token":"%s"' "$token")
  STATUS=$(printf '{"grant_type":"%s","subject_token_type":"%s"%s%s}' "$GRANT" "$type" "$subject" "$extra" |
    curl -s -o "$WORK/body" -w '%{http_code}' -X POST -H 'content-type: application/json' --data-binary @- "$BROKER/oauth/token")
  sleep 0.5 # let wrangler flush the audit line
  REASON=$(tail -n +"$((before + 1))" "$LOG" | sed -n 's/.*"event":"token.deny".*"reason":"\([^"]*\)".*/\1/p' | tail -1)
  TOKEN_ID=""
  if [[ $STATUS == 200 ]]; then
    local tok
    tok=$(jq -r '.access_token // empty' "$WORK/body")
    [[ -n $tok ]] && MINTED+=("$tok")
    TOKEN_ID=$(jq -r '.token_id // empty' "$WORK/body")
  fi
  rm -f "$WORK/body"
}

# revoke <token> prints the status of POST /oauth/revoke. The token goes on stdin.
revoke() {
  printf 'token=%s' "$1" | curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H 'content-type: application/x-www-form-urlencoded' --data-binary @- "$BROKER/oauth/revoke"
}

pass() { PASSED=$((PASSED + 1)); printf 'PASS  %-62s %s %s\n' "$1" "$STATUS" "$REASON"; }
fail() {
  FAILED=$((FAILED + 1))
  printf 'FAIL  %-62s got %s %s, want %s %s\n' "$1" "$STATUS" "${REASON:-(no reason)}" "$2" "${3:-}"
}

# check <description> <subject_token|-> <subject_token_type> <fields|-> <status> [reason]
check() {
  local what=$1 want_status=$5 want_reason=${6:-}
  request "$2" "$3" "$4"
  if [[ $STATUS == "$want_status" && (-z $want_reason || $REASON == "$want_reason") ]]; then
    pass "$what"
  else
    fail "$what" "$want_status" "$want_reason"
  fi
}

# gone <path> checks that a removed route is a 404.
gone() {
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BROKER$1") REASON=""
  if [[ $STATUS == 404 ]]; then pass "removed POST $1"; else fail "removed POST $1" 404; fi
}

user() { check "$1" "$GH_USER_TOKEN" "$ACCESS" "$2" "${@:3}"; }

echo
user "writer gets a token for $REPO" "{\"profile\":\"me\",\"repository\":\"$REPO\"}" 200
# The name is only visible in Cloudflare, not in the response or the audit log.
[[ -n $TOKEN_ID ]] && echo "      minted $TOKEN_ID: in the dashboard it's named cf-oidc:user:$LOGIN:$REPO"
user "by numeric repository ID" "{\"profile\":\"me\",\"repository\":\"$REPO_ID\"}" 200
if [[ -n $TEAM_ID ]]; then
  user "member of team $TEAM_ID" "{\"profile\":\"me-team\",\"repository\":\"$REPO\"}" 200
else
  echo "SKIP  member of a team (you're in no team of $OWNER)"
fi
user "not a member of the team" "{\"profile\":\"me-bad-team\",\"repository\":\"$REPO\"}" 403 profile_mismatch
user "repo in another org (cli/cli)" '{"profile":"me","repository":"cli/cli"}' 403 repository_forbidden
user "repo that doesn't exist" "{\"profile\":\"me\",\"repository\":\"$OWNER/does-not-exist-$RANDOM\"}" 403 repository_forbidden
user "Actions profile, asked for by a person" "{\"profile\":\"ci\",\"repository\":\"$REPO\"}" 403 profile_mismatch
if [[ -n ${TEST_READ_ONLY_REPO:-} ]]; then
  user "write needed, only read on $TEST_READ_ONLY_REPO" "{\"profile\":\"me\",\"repository\":\"$TEST_READ_ONLY_REPO\"}" 403 profile_mismatch
else
  echo "SKIP  write needed, only read (set TEST_READ_ONLY_REPO)"
fi
check "installation token (ghs_)" ghs_notARealInstallationToken000000000000 "$ACCESS" \
  "{\"repository\":\"$REPO\"}" 401 installation_token
check "token GitHub rejects" gho_notARealToken000000000000000000000000 "$ACCESS" \
  "{\"repository\":\"$REPO\"}" 401 invalid_user_token
check "no token" - "$ACCESS" "{\"repository\":\"$REPO\"}" 400 invalid_body
user "no repository" '{"profile":"me"}' 400 invalid_body
user "malformed repository" '{"profile":"me","repository":"a/b/c"}' 400 invalid_body
check "gh token passed off as a job's OIDC token" "$GH_USER_TOKEN" "$ID_TOKEN" '{"profile":"ci"}' 401 invalid_jwt
for path in /v1/token /v1/actions/token /v1/users/token /v1/revoke; do gone "$path"; done

echo
echo "revoking ${#MINTED[@]} minted token(s)"
REVOKED=0
for tok in "${MINTED[@]}"; do
  code=$(revoke "$tok")
  if [[ $code == 200 ]]; then REVOKED=$((REVOKED + 1)); else echo "FAIL  revoke returned $code"; FAILED=$((FAILED + 1)); fi
done
MINTED=()
echo "revoked $REVOKED"

echo
echo "$PASSED passed, $FAILED failed"
[[ $FAILED == 0 ]]
