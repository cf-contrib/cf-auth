#!/usr/bin/env bash
# Checks R2 temporary credentials against a real account, with a throwaway token
# set up like the broker token and two throwaway buckets:
#   - The token can mint prefix-limited credentials as its own parent (#23).
#   - The credentials stay inside their bucket and prefix, read-only means
#     read-only, and no prefixes means the whole bucket.
#   - The shortest ttlSeconds the API accepts.
#   - OpenTofu's s3 backend works inside a prefix: lock file and workspaces.
#   - Several buckets as named AWS profiles, one per bucket (#26): each profile
#     reaches only its bucket, with the AWS CLI and with the s3 backend's
#     `profile`, and whether the config file is needed next to the credentials
#     file.
#   - Deleting the parent token cuts off issued credentials (--revoke).
#
# Usage:
#   nix shell nixpkgs#awscli2 nixpkgs#jq nixpkgs#opentofu --command \
#     scripts/test-r2-temp-credentials.sh [--revoke] [bucket [second-bucket]]
#
# Needs:
#   - CLOUDFLARE_ACCOUNT_ID.
#   - Two throwaway buckets, by default cf-oidc-r2-test and cf-oidc-r2-test-2:
#       wrangler r2 bucket create cf-oidc-r2-test
#       wrangler r2 bucket create cf-oidc-r2-test-2
#   - A throwaway account-owned token (Manage Account > Account API Tokens) named
#     cf-oidc-r2-test-<anything>, with "Account API Tokens: Edit" plus the R2
#     permission under test, e.g. "Workers R2 Storage: Edit". The script prompts
#     for it and ignores CLOUDFLARE_API_TOKEN. Any other token name is refused, so
#     the real broker token can't be used, or deleted by --revoke, by mistake.
#
# --revoke deletes the test token at the end, to see whether the credentials stop
# working. Without it, delete the token yourself afterwards.
#
# Prints no secrets: the output is safe to share.
set -euo pipefail

REVOKE=false
BUCKETS=()
for arg in "$@"; do
  case $arg in
    --revoke) REVOKE=true ;;
    -h | --help)
      sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
      exit 0
      ;;
    -*)
      echo "unknown option: $arg (see --help)" >&2
      exit 2
      ;;
    *) BUCKETS+=("$arg") ;;
  esac
done
BUCKET=${BUCKETS[0]:-cf-oidc-r2-test}
BUCKET2=${BUCKETS[1]:-cf-oidc-r2-test-2}
[[ $BUCKET != "$BUCKET2" ]] || { echo "the two buckets must differ" >&2; exit 2; }

die() {
  echo "error: $*" >&2
  exit 1
}

for tool in curl jq aws tofu; do
  command -v "$tool" >/dev/null || die "$tool not found; run it with: nix shell nixpkgs#awscli2 nixpkgs#jq nixpkgs#opentofu --command $0"
done

ACCOUNT_ID=${CLOUDFLARE_ACCOUNT_ID:-}
[[ $ACCOUNT_ID =~ ^[0-9a-f]{32}$ ]] || die "set CLOUDFLARE_ACCOUNT_ID"
API="https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID"

# The layout the broker's github.com/{repository}/ prefixes produce.
PREFIX="github.com/example-org/r2-test/"
SIBLING="github.com/example-org/r2-test-old/" # a repo whose name starts with r2-test

# Only the credentials under test: nothing from the environment, ~/.aws or an earlier step.
unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_ENDPOINT_URL
no_env_creds() { unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN; }
no_files() { export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null; }
no_env_creds
no_files
export AWS_PAGER=""
export AWS_ENDPOINT_URL_S3="https://$ACCOUNT_ID.r2.cloudflarestorage.com" AWS_REGION=auto AWS_DEFAULT_REGION=auto
# Newer AWS CLIs add CRC checksums R2 may not accept; only send them when required.
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required

WORK=$(mktemp -d)
echo "cf-oidc r2 test" >"$WORK/probe.txt"
rw=""
rw2=""
PURGED=false

RESULTS=()
FAILED=0
record() { # record <PASS|FAIL|INFO> <message>
  RESULTS+=("$1  $2")
  echo "$1  $2"
  if [[ $1 == FAIL ]]; then FAILED=$((FAILED + 1)); fi
  return 0
}
say() { printf '\n== %s\n' "$*"; }

# Cloudflare API with the test token. cf <method> <path> [json-body]
cf() {
  local args=(-sS -X "$1" "$API$2" -H "Authorization: Bearer $TOKEN")
  if [[ $# -ge 3 ]]; then args+=(-H "Content-Type: application/json" --data "$3"); fi
  curl "${args[@]}"
}
errors() { jq -r '[.errors[]? | "\(.code): \(.message)"] | join("; ") | if . == "" then "no error message" else . end' <<<"$1"; }

# Asks for credentials the way the broker does. temp_creds <bucket> <permission> <ttlSeconds> [prefix]
temp_creds() {
  local body
  body=$(jq -nc --arg bucket "$1" --arg parent "$TOKEN_ID" --arg permission "$2" \
    --argjson ttl "$3" --arg prefix "${4-}" \
    '{bucket: $bucket, parentAccessKeyId: $parent, permission: $permission, ttlSeconds: $ttl}
      + (if $prefix == "" then {} else {prefixes: [$prefix]} end)')
  cf POST /r2/temp-access-credentials "$body"
}
ok() { [[ $(jq -r '.success // false' <<<"$1") == true ]]; }
use_creds() { # use_creds <temp_creds response>: the credentials go in the environment, as the action exports them
  AWS_ACCESS_KEY_ID=$(jq -r .result.accessKeyId <<<"$1")
  AWS_SECRET_ACCESS_KEY=$(jq -r .result.secretAccessKey <<<"$1")
  AWS_SESSION_TOKEN=$(jq -r .result.sessionToken <<<"$1")
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

# Runs an S3 call and compares the outcome. expect <allowed|denied|refused> <description> <s3api args...>
# "refused" is anything but allowed, e.g. no credentials found.
expect() {
  local want=$1 what=$2 out got
  shift 2
  if out=$(aws s3api "$@" 2>&1 >/dev/null); then
    got=allowed
  elif grep -qE 'AccessDenied|Forbidden|\(403\)' <<<"$out"; then
    got=denied
  else
    got="error: $(grep -v '^$' <<<"$out" | tail -1)"
  fi
  if [[ $got == "$want" || ($want == refused && $got != allowed) ]]; then
    record PASS "$what: $got"
  else
    record FAIL "$what: expected $want, got $got"
  fi
}

# Deletes what the test wrote in one bucket. purge_bucket <bucket> <read-write temp_creds response>
purge_bucket() {
  [[ -n $2 ]] || return 0
  local keys key
  no_files
  use_creds "$2"
  keys=$(aws s3api list-objects-v2 --bucket "$1" --prefix "$PREFIX" --query 'Contents[].Key' --output text 2>/dev/null || true)
  for key in $keys "${SIBLING}probe.txt" probe.txt; do
    [[ $key == None ]] || aws s3api delete-object --bucket "$1" --key "$key" >/dev/null 2>&1 || true
  done
}
# Needs the read-write credentials, so it runs before --revoke deletes their parent.
purge() {
  [[ $PURGED == false ]] || return 0
  PURGED=true
  purge_bucket "$BUCKET" "$rw"
  purge_bucket "$BUCKET2" "$rw2"
}
trap 'purge; rm -rf "$WORK"' EXIT

summary() {
  printf '\n== Summary (no secrets; safe to share)\n'
  echo "buckets:     $BUCKET, $BUCKET2"
  echo "token:       ${TOKEN_NAME:-?}"
  echo "permissions: ${TOKEN_PERMS:-?}"
  printf '%s\n' "${RESULTS[@]}"
  echo "failed: $FAILED"
}

# A scratch OpenTofu root with the backend setup from the action README. The endpoint
# comes from AWS_ENDPOINT_URL_S3; the rest from -backend-config. tofu_root <dir>
tofu_root() {
  mkdir -p "$1"
  cat >"$1/main.tf" <<'EOF'
terraform {
  backend "s3" {
    region       = "auto"
    use_lockfile = true

    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_metadata_api_check     = true
    skip_s3_checksum            = true
    use_path_style              = true
  }
}

resource "terraform_data" "probe" {
  input = "cf-oidc r2 test"
}
EOF
}
# tofu_step <dir> <PASS-or-INFO-on-failure> <description> <tofu args...>
tofu_step() {
  local dir=$1 on_failure=$2 what=$3
  shift 3
  if tofu -chdir="$dir" "$@" >"$dir/tofu.log" 2>&1; then
    record PASS "tofu $what"
  else
    record "$on_failure" "tofu $what: $(sed 's/\x1b\[[0-9;]*m//g' "$dir/tofu.log" | grep -m1 -iE 'error|denied|forbidden' || tail -1 "$dir/tofu.log")"
    return 1
  fi
}

printf 'Test token, from Account API Tokens (input hidden): ' >&2
read -rs TOKEN
echo >&2
[[ -n $TOKEN ]] || die "no token given"

say "1. The test token"
verify=$(cf GET /tokens/verify)
TOKEN_ID=$(jq -r '.result.id // empty' <<<"$verify")
[[ -n $TOKEN_ID ]] || die "tokens/verify failed ($(errors "$verify")). Is it an account-owned token for account $ACCOUNT_ID?"
details=$(cf GET "/tokens/$TOKEN_ID")
TOKEN_NAME=$(jq -r '.result.name // empty' <<<"$details")
[[ $TOKEN_NAME == cf-oidc-r2-test* ]] ||
  die "refusing token \"${TOKEN_NAME:-unreadable}\": use a throwaway token named cf-oidc-r2-test-<anything>"
TOKEN_PERMS=$(jq -r '[.result.policies[]? | "\(.effect) \([.permission_groups[] | .name // .id] | join(", ")) on \([.resources | keys[]] | join(", "))"] | join(" | ")' <<<"$details")
echo "id:          $TOKEN_ID (also its R2 access key ID; not secret)"
echo "name:        $TOKEN_NAME"
echo "permissions: $TOKEN_PERMS"
# Without one, a refusal below says nothing about whether the broker token could work.
[[ $TOKEN_PERMS == *R2* ]] ||
  die "the token has no R2 permission; add e.g. \"Workers R2 Storage: Edit\" to it and run this again"

say "2. object-read-write credentials for $BUCKET, limited to $PREFIX, with the token as its own parent"
rw=$(temp_creds "$BUCKET" object-read-write 900 "$PREFIX")
if ! ok "$rw"; then
  record FAIL "temp-access-credentials refused the token: $(errors "$rw")"
  rw=""
  summary
  exit 1
fi
record PASS "temp-access-credentials accepted the token as its own parent"
if [[ $(jq -r .result.accessKeyId <<<"$rw") == "$TOKEN_ID" ]]; then
  record INFO "the credentials' access key ID is the parent's token ID"
else
  record INFO "the credentials' access key ID is not the parent's token ID"
fi

say "3. What the read-write credentials reach"
use_creds "$rw"
expect allowed "put inside the prefix" put-object --bucket "$BUCKET" --key "${PREFIX}probe.txt" --body "$WORK/probe.txt"
expect allowed "get inside the prefix" get-object --bucket "$BUCKET" --key "${PREFIX}probe.txt" /dev/null
expect allowed "list the prefix" list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX"
expect allowed "delete inside the prefix" delete-object --bucket "$BUCKET" --key "${PREFIX}probe.txt"
expect denied "put under a sibling repo's prefix ($SIBLING)" put-object --bucket "$BUCKET" --key "${SIBLING}probe.txt" --body "$WORK/probe.txt"
expect denied "put at the bucket root" put-object --bucket "$BUCKET" --key probe.txt --body "$WORK/probe.txt"
expect denied "list the whole bucket" list-objects-v2 --bucket "$BUCKET"
expect denied "list the owner's prefix (github.com/example-org/)" list-objects-v2 --bucket "$BUCKET" --prefix github.com/example-org/

say "4. object-read-only credentials"
use_creds "$rw"
aws s3api put-object --bucket "$BUCKET" --key "${PREFIX}probe.txt" --body "$WORK/probe.txt" >/dev/null 2>&1 || true
ro=$(temp_creds "$BUCKET" object-read-only 900 "$PREFIX")
if ok "$ro"; then
  use_creds "$ro"
  expect allowed "read-only: get inside the prefix" get-object --bucket "$BUCKET" --key "${PREFIX}probe.txt" /dev/null
  expect allowed "read-only: list the prefix" list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX"
  expect denied "read-only: put inside the prefix" put-object --bucket "$BUCKET" --key "${PREFIX}ro.txt" --body "$WORK/probe.txt"
else
  record FAIL "object-read-only credentials refused: $(errors "$ro")"
fi

say "5. Credentials without prefixes cover the whole bucket"
whole=$(temp_creds "$BUCKET" object-read-only 60)
if ok "$whole"; then
  use_creds "$whole"
  expect allowed "no prefixes: list the whole bucket" list-objects-v2 --bucket "$BUCKET"
else
  record FAIL "credentials without prefixes refused: $(errors "$whole")"
fi

say "6. Shortest ttlSeconds (the broker's minimum is 60)"
for ttl in 300 60 30 1 0; do
  probe=$(temp_creds "$BUCKET" object-read-only "$ttl" "$PREFIX")
  if ok "$probe"; then record INFO "ttlSeconds=$ttl: accepted"; else record INFO "ttlSeconds=$ttl: refused ($(errors "$probe"))"; fi
done

say "7. OpenTofu s3 backend inside the prefix, credentials in the environment ($(tofu version -json | jq -r .terraform_version))"
use_creds "$rw"
tofu_root "$WORK/env"
tofu_step "$WORK/env" FAIL "init" init -input=false \
  -backend-config="bucket=$BUCKET" \
  -backend-config="key=${PREFIX}terraform.tfstate" \
  -backend-config="workspace_key_prefix=${PREFIX}env:" &&
  tofu_step "$WORK/env" FAIL "apply (writes the state and its .tflock)" apply -input=false -auto-approve &&
  tofu_step "$WORK/env" FAIL "workspace new staging" workspace new staging &&
  tofu_step "$WORK/env" FAIL "apply in the staging workspace" apply -input=false -auto-approve &&
  tofu_step "$WORK/env" FAIL "workspace list" workspace list ||
  true
keys=$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX" --query 'Contents[].Key' --output text 2>/dev/null || true)
record INFO "keys tofu left under the prefix: $(tr '\t' ' ' <<<"$keys")"

say "8. Two buckets as named AWS profiles ($BUCKET, $BUCKET2)"
rw2=$(temp_creds "$BUCKET2" object-read-write 900 "$PREFIX")
if ! ok "$rw2"; then
  record FAIL "credentials for $BUCKET2 refused: $(errors "$rw2") (does the bucket exist?)"
  rw2=""
else
  # The files the action would write for a profile with several buckets.
  AWS_DIR="$WORK/aws"
  mkdir -p "$AWS_DIR"
  (
    umask 077
    printf '[profile %s]\nregion = auto\n\n[profile %s]\nregion = auto\n' "$BUCKET" "$BUCKET2" >"$AWS_DIR/config"
    for pair in "$BUCKET:$rw" "$BUCKET2:$rw2"; do
      name=${pair%%:*}
      creds=${pair#*:}
      jq -r --arg name "$name" '"[\($name)]\naws_access_key_id = \(.result.accessKeyId)\naws_secret_access_key = \(.result.secretAccessKey)\naws_session_token = \(.result.sessionToken)\n"' <<<"$creds"
    done >"$AWS_DIR/credentials"
  )
  profiles() { # the files, and no credentials in the environment
    no_env_creds
    export AWS_CONFIG_FILE="$AWS_DIR/config" AWS_SHARED_CONFIG_FILE="$AWS_DIR/config" AWS_SHARED_CREDENTIALS_FILE="$AWS_DIR/credentials"
  }

  profiles
  expect allowed "--profile $BUCKET: put in $BUCKET" put-object --profile "$BUCKET" --bucket "$BUCKET" --key "${PREFIX}profile.txt" --body "$WORK/probe.txt"
  expect allowed "--profile $BUCKET2: put in $BUCKET2" put-object --profile "$BUCKET2" --bucket "$BUCKET2" --key "${PREFIX}profile.txt" --body "$WORK/probe.txt"
  expect denied "--profile $BUCKET: put in $BUCKET2" put-object --profile "$BUCKET" --bucket "$BUCKET2" --key "${PREFIX}cross.txt" --body "$WORK/probe.txt"
  expect denied "--profile $BUCKET2: put in $BUCKET" put-object --profile "$BUCKET2" --bucket "$BUCKET" --key "${PREFIX}cross.txt" --body "$WORK/probe.txt"
  export AWS_PROFILE=$BUCKET2
  expect allowed "AWS_PROFILE=$BUCKET2: list $BUCKET2" list-objects-v2 --bucket "$BUCKET2" --prefix "$PREFIX"
  unset AWS_PROFILE
  expect refused "no profile and no credentials in the environment" list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX"

  # Is the config file needed at all? Region and endpoint come from the environment.
  profiles
  export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CONFIG_FILE=/dev/null
  if aws s3api list-objects-v2 --profile "$BUCKET" --bucket "$BUCKET" --prefix "$PREFIX" >/dev/null 2>&1; then
    record INFO "aws CLI: the credentials file alone is enough"
  else
    record INFO "aws CLI: needs the config file next to the credentials file"
  fi

  # Do stale credentials in the environment beat an explicit profile?
  profiles
  use_creds "$rw"
  if aws s3api put-object --profile "$BUCKET2" --bucket "$BUCKET2" --key "${PREFIX}stale.txt" --body "$WORK/probe.txt" >/dev/null 2>&1; then
    record INFO "aws CLI: --profile wins over credentials in the environment"
  else
    record INFO "aws CLI: credentials in the environment win over --profile, so the action must clear them"
  fi

  # OpenTofu with the backend's profile argument.
  profiles
  tofu_root "$WORK/profile"
  tofu_step "$WORK/profile" FAIL "profile=$BUCKET2: init" init -input=false \
    -backend-config="profile=$BUCKET2" \
    -backend-config="bucket=$BUCKET2" \
    -backend-config="key=${PREFIX}terraform.tfstate" \
    -backend-config="workspace_key_prefix=${PREFIX}env:" &&
    tofu_step "$WORK/profile" FAIL "profile=$BUCKET2: apply" apply -input=false -auto-approve &&
    tofu_step "$WORK/profile" FAIL "profile=$BUCKET2: workspace new staging" workspace new staging &&
    tofu_step "$WORK/profile" FAIL "profile=$BUCKET2: workspace list" workspace list ||
    true

  profiles
  tofu_root "$WORK/cross"
  if tofu -chdir="$WORK/cross" init -input=false \
    -backend-config="profile=$BUCKET" \
    -backend-config="bucket=$BUCKET2" \
    -backend-config="key=${PREFIX}cross.tfstate" >/dev/null 2>&1 &&
    tofu -chdir="$WORK/cross" apply -input=false -auto-approve >/dev/null 2>&1; then
    record FAIL "tofu profile=$BUCKET wrote state to $BUCKET2"
  else
    record PASS "tofu profile=$BUCKET can't use $BUCKET2"
  fi

  # The s3 backend documents AWS_SHARED_CONFIG_FILE; is the credentials file alone enough?
  profiles
  export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CONFIG_FILE=/dev/null
  tofu_root "$WORK/credentials-only"
  if tofu_step "$WORK/credentials-only" INFO "profile=$BUCKET, credentials file only: init" init -input=false \
    -backend-config="profile=$BUCKET" \
    -backend-config="bucket=$BUCKET" \
    -backend-config="key=${PREFIX}credentials-only.tfstate" &&
    tofu_step "$WORK/credentials-only" INFO "profile=$BUCKET, credentials file only: apply" apply -input=false -auto-approve; then
    record INFO "tofu: the credentials file alone is enough"
  fi

  # Stale credentials in the environment against the backend's profile.
  profiles
  use_creds "$rw"
  tofu_root "$WORK/stale"
  if tofu -chdir="$WORK/stale" init -input=false \
    -backend-config="profile=$BUCKET2" \
    -backend-config="bucket=$BUCKET2" \
    -backend-config="key=${PREFIX}stale.tfstate" >/dev/null 2>&1 &&
    tofu -chdir="$WORK/stale" apply -input=false -auto-approve >/dev/null 2>&1; then
    record INFO "tofu: the backend's profile wins over credentials in the environment"
  else
    record INFO "tofu: credentials in the environment win over the backend's profile, so the action must clear them"
  fi
fi

purge

say "9. Deleting the parent token"
if $REVOKE; then
  no_files
  use_creds "$rw"
  expect allowed "list before deleting the parent" list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX"
  deleted=$(cf DELETE "/tokens/$TOKEN_ID")
  if ok "$deleted"; then
    start=$SECONDS
    cut=false
    while ((SECONDS - start < 120)); do
      if ! aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX" >/dev/null 2>&1; then
        cut=true
        break
      fi
      sleep 5
    done
    if $cut; then
      record PASS "the credentials stopped working within $((SECONDS - start))s of deleting the parent"
    else
      record FAIL "the credentials still work 120s after deleting the parent"
    fi
  else
    record FAIL "couldn't delete the test token: $(errors "$deleted")"
  fi
else
  record INFO "skipped; pass --revoke to test it. Delete the test token yourself now"
fi

summary
((FAILED == 0))
