# Traffic capture setup (mitmproxy + Chrome)

Local, no-sudo setup for reverse-engineering the Medicover portal's private API by
watching the real browser traffic. Nothing is installed system-wide.

## What's installed
- **mitmproxy** — installed via `uv tool install mitmproxy` (in `~/.local`). Binaries:
  `mitmweb`, `mitmdump`, `mitmproxy`.
- **Chrome for Testing 149** — standalone build unzipped to
  `~/.local/chrome-for-testing/chrome-linux64/chrome` (no apt, no sudo).
- **mitmproxy CA** — auto-generated at `~/.mitmproxy/` on first run.

## Usage
1. **Start the proxy** (leave it running in its own terminal):
   ```
   ./start-proxy.sh
   ```
   - proxy: `127.0.0.1:8080`  ·  inspector UI: <http://127.0.0.1:8081>
   - all flows are appended to `flows.mitm` for later replay/inspection.

2. **Launch Chrome routed through it** (separate terminal):
   ```
   ./launch-chrome.sh                       # opens the portal-ready browser
   ./launch-chrome.sh https://online24.medicover.pl/
   ```
   Then log in normally (incl. the SMS 2FA). Watch requests appear in the web UI at
   :8081, or open `flows.mitm` later.

## How TLS interception works without a system cert
`launch-chrome.sh` passes Chrome `--ignore-certificate-errors-spki-list=<hash>` where the
hash is mitmproxy's CA public-key SPKI (computed at runtime from
`~/.mitmproxy/mitmproxy-ca-cert.pem`). Chrome therefore trusts **only** mitmproxy's key and
still validates every other certificate normally. The browser also uses a dedicated,
disposable profile (`chrome-profile/`) so it never mixes with your real Chrome.

## Tips for the reverse-engineering phases (see ../prompt.md)
- In the :8081 UI, filter to the API host and to XHR/fetch; right-click a flow →
  "Export" to get a curl command you can convert to Python `httpx`.
- Decode the bearer JWT (jwt.io / locally) to read scopes, `exp`, and patient/subaccount
  context.
- To replay captured flows headless later: `mitmdump -nr flows.mitm` (read) or use the UI.

## Reset
- Stop the proxy: Ctrl-C in its terminal.
- Wipe the disposable browser state: `rm -rf chrome-profile/`.
- Clear captures: `rm -f flows.mitm`.

> `chrome-profile/` and `flows.mitm` can contain live session tokens and personal/medical
> data — keep them local, don't commit them. Add both to `.gitignore`.
