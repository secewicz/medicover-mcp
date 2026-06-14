#!/usr/bin/env bash
# Start mitmproxy (web UI) to capture Medicover portal traffic.
#   - proxy listens on 127.0.0.1:8080  (point Chrome here)
#   - inspector web UI on http://127.0.0.1:8081
#   - all flows are appended to capture/flows.mitm for later replay/inspection
set -euo pipefail

PROXY_PORT="${PROXY_PORT:-8080}"
WEB_PORT="${WEB_PORT:-8081}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLOWS="${FLOWS:-$HERE/flows.mitm}"

echo "mitmproxy: proxy on :$PROXY_PORT  |  web UI on http://127.0.0.1:$WEB_PORT  |  saving -> $FLOWS"
exec mitmweb \
  --listen-host 127.0.0.1 --listen-port "$PROXY_PORT" \
  --web-host 127.0.0.1 --web-port "$WEB_PORT" \
  --save-stream-file "+$FLOWS"
