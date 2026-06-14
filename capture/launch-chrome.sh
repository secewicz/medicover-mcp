#!/usr/bin/env bash
# Launch an isolated Chrome (Chrome for Testing) routed through mitmproxy.
#
# Trust model: instead of installing mitmproxy's CA system-wide, we tell Chrome to
# ignore cert errors ONLY for mitmproxy's specific public key (via its SPKI hash).
# Every other certificate is still validated normally. Nothing global is changed.
#
# A dedicated, disposable profile (capture/chrome-profile) keeps this separate from
# your real Chrome and any real Medicover session.
set -euo pipefail

CHROME="$HOME/.local/chrome-for-testing/chrome-linux64/chrome"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${PROFILE:-$HERE/chrome-profile}"
PROXY="${PROXY:-127.0.0.1:8080}"
CA="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"

# Compute mitmproxy CA SPKI hash at runtime (robust if the CA is ever regenerated).
SPKI="$(openssl x509 -in "$CA" -pubkey -noout \
        | openssl pkey -pubin -outform der \
        | openssl dgst -sha256 -binary \
        | openssl base64)"

mkdir -p "$PROFILE"
echo "Chrome -> proxy http://$PROXY  (profile: $PROFILE)"
exec "$CHROME" \
  --user-data-dir="$PROFILE" \
  --proxy-server="http://$PROXY" \
  --ignore-certificate-errors-spki-list="$SPKI" \
  --no-first-run --no-default-browser-check \
  "$@"
