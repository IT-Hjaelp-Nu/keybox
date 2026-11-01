#!/usr/bin/env bash
# Runs the approval page in headless Chromium against a local Key-Box, with
# Chromium's virtual authenticators as passkeys.
#
#   cargo build --release -p keyboxd && tests/browser/run.sh
#
# Needs chromium, node (22 or newer), openssl and curl. Not part of `cargo test`.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
K="$REPO/target/release/keyboxd"
D="$(mktemp -d)"; mkdir -p "$D/shots" "$D/chrome"
"$K" init-pki --dir "$D/state" --name localhost || exit 1
"$K" issue-agent --dir "$D/state" --out "$D/keys" hermes || exit 1
"$K" serve --dir "$D/state" --policy-dir "$HERE/policy.d" --listen 127.0.0.1:18473 \
  --web-listen 127.0.0.1:18474 --origin https://localhost:18474 \
  --web-cert "$D/state/server.pem" --web-key "$D/state/server.key" > "$D/serve.out" 2>&1 &
KPID=$!
# Trust exactly this server's key, the way a real certificate would be trusted.
SPKI=$(openssl x509 -in "$D/state/server.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
chromium --headless=new --remote-debugging-port=9333 --user-data-dir="$D/chrome" \
  --ignore-certificate-errors-spki-list="$SPKI" --no-first-run --disable-gpu about:blank > "$D/chrome.out" 2>&1 &
CPID=$!
for _ in $(seq 1 50); do curl -s http://127.0.0.1:9333/json/version > /dev/null 2>&1 && break; sleep 0.2; done
KEYBOXD="$K" DIR="$D/state" KEYS="$D/keys" CDP=9333 URL_=https://localhost:18474/ AGENT_ADDR=127.0.0.1:18473 SHOTS="$D/shots" \
  node "$HERE/test.mjs"; RC=$?
kill $CPID $KPID 2>/dev/null; wait $CPID $KPID 2>/dev/null
"$K" verify-log "$D/state/audit.log" || RC=1
echo "screenshots and state: $D"
exit $RC
