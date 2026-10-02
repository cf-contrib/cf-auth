#!/usr/bin/env bash
# Runs the integration tests: creates the test secrets in a local Secrets Store,
# starts the stand-ins build under `wrangler dev`, runs the tests against it, and
# stops it. All keys and tokens are made up and thrown away afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."

STORE=00000000000000000000000000000000
PERSIST=.wrangler/integration
LOG=${CF_OIDC_EXCHANGE_API_LOG:-$PWD/.wrangler/integration.log}
KEYS=$(mktemp -d)
trap 'rm -rf "$KEYS"; [ -n "${DEV:-}" ] && kill "$DEV" 2>/dev/null; wait 2>/dev/null || true' EXIT

rm -rf "$PERSIST" && mkdir -p "$PERSIST"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEYS/signing.pem" 2>/dev/null
secret() {
  # --value= keeps a PEM's leading dashes from being read as a flag.
  wrangler secrets-store secret create "$STORE" --name "$1" --scopes workers --value="$2" --persist-to "$PERSIST" >/dev/null
}
secret cloudflare-token test-cloudflare-token
secret signing-key "$(cat "$KEYS/signing.pem")"

wrangler dev -c wrangler.test.toml --port 8790 --persist-to "$PERSIST" --test-scheduled >"$LOG" 2>&1 &
DEV=$!
for _ in $(seq 120); do
  curl -s -o /dev/null http://127.0.0.1:8790/ && break
  kill -0 "$DEV" 2>/dev/null || { cat "$LOG"; exit 1; }
  sleep 1
done

CF_OIDC_EXCHANGE_API_LOG="$LOG" cargo test --features integration --test integration -- --test-threads=1 "$@"
