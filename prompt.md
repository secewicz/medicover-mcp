# Build an MCP server for the Medicover patient portal

## Goal
Create a **Model Context Protocol (MCP) server** that lets an AI agent manage medical
appointments on Medicover's Polish patient portal (`https://online24.medicover.pl/`).

The portal is a single-page app with **no public or documented API**. The server must
talk to the **same private JSON/HTTP endpoints the SPA itself calls** (a
reverse-engineered internal API), authenticated as the user. The running server must **not**
drive a browser — it makes direct HTTP calls. (A browser is used only during development, to
discover those endpoints; see Reverse-engineering methodology.)

## Primary use case
Some appointment types have very low availability and are hard to book. The server must
let an agent run an **unattended daily routine** that:
1. Searches for available slots for a given specialty/clinic/doctor.
2. Optionally rebooks an existing appointment to an **earlier** available slot.
This drives the design: normal operation must require **no human interaction** (see Auth).

## Scope — exactly these tools, nothing more
Expose only:
- `list_patients` — the logged-in user plus any linked subaccounts/dependents the account
  can access (see Subaccounts below).
- `list_appointments` — a patient's existing/upcoming appointments.
- `search_slots` — available slots filtered by specialty, clinic/region, doctor, and date range.
- `book_appointment` — book an available slot for a patient.
- `reschedule_appointment` — move an existing appointment to a different available slot.

Plus read-only **reference/lookup** tools needed to build valid searches (e.g. list
specialties, clinics, regions, doctors) if the API requires opaque IDs rather than names.

The only other permitted tools are the **conditional** `request_sms_code` / `submit_sms_code`
2FA-fallback pair described under Authentication — and only if the measured token lifetime
makes them necessary.

### Subaccounts / dependents (required feature)
A Medicover login often has access to **multiple patients** — the account holder plus
linked dependents (e.g. children, family members) configured beforehand. The server must
support operating on **any patient the logged-in account can access**:
- `list_patients` returns each accessible patient with a stable identifier and display name,
  and indicates which one is the account holder.
- Patient-scoped tools take an explicit **patient identifier**. For **write tools**
  (`book_appointment`, `reschedule_appointment`) the patient ID is **required** — never
  defaulted or guessed — so an agent cannot book on the wrong person's record. For read
  tools (`list_appointments`, `search_slots`) the ID may default to the account holder when
  omitted.
- Discover how the API represents this (commonly an "on behalf of" patient/member ID or a
  context-switch call) during the discovery step, and document it.
- The daily-check use case must work per-patient, so an agent can, e.g., hunt for an earlier
  pediatric slot for a child while leaving the parent's appointments untouched.

Do **not** expose anything else (messaging, prescriptions, medical records, payments,
profile changes, cancellation-without-rebook unless explicitly required). This is medical
data — keep the surface minimal and conservative.

## Stack
- **Python**, using the official Python MCP SDK (`FastMCP`).
- HTTP client with proper session/cookie and token handling (e.g. `httpx`).
- Typed tool inputs/outputs (Pydantic models); clear schemas and docstrings so an agent
  can call tools correctly.
- Packaged to run as a standard MCP server (stdio transport) launchable from an MCP client config.

## Authentication (the key constraint: login uses SMS-based 2FA)
Because the daily routine must run unattended, the SMS 2FA cannot be in the hot path.
Use this **two-phase** design:

1. **One-time interactive bootstrap** — a separate CLI command (e.g. `medicover-auth login`),
   **not** an MCP tool. It performs username + password login, prompts the operator for the
   **SMS one-time code**, completes the OAuth/OIDC + 2FA flow, and **persists the resulting
   long-lived credential** (refresh token and/or trusted-device cookies) to a secure local
   store (restrictive file permissions; path configurable; never world-readable).

2. **Unattended runtime** — the MCP server loads the cached credential and silently
   refreshes the short-lived access token on each run. No password or SMS code is ever
   required, handled, or logged during normal tool calls.

3. **Re-auth on expiry** — when the cached credential expires or is revoked, tools must
   fail with a **clear, actionable error** ("session expired — run `medicover-auth login`"),
   never attempt to prompt for SMS through a tool call.

Credentials: read username/password from environment variables (or prompt at bootstrap);
never expose, return, or log credentials or tokens via any tool.

### Prior art (reference, likely outdated)
The open-source **`medihunter`** project (Python) already reverse-engineers much of
Medicover's login flow and slot search, so it's a useful starting reference for endpoints
and the OAuth/IdentityServer auth flow. **Caveat:** its last commit is ~2 years old, so
endpoints, the auth flow, and especially the 2FA behaviour may have changed — treat it as a
lead to verify against live traffic, not as ground truth.

### Required discovery step (do this first, document findings)
Before writing the server, inspect the portal's traffic to map the real endpoints and the
auth flow, cross-checking against `medihunter` where helpful — see **Reverse-engineering
methodology** for how. A key output is **how long the refresh token / trusted-device session
lasts** (measured in Phase 4), which decides the fallback:
- If it lasts weeks/months, the bootstrap-once model above is sufficient.
- If it expires within days, additionally provide an **in-MCP 2FA fallback**: a
  `request_sms_code` tool and a `submit_sms_code` tool so re-auth can happen without
  shell access. Decide based on the measured lifetime and note the decision.

Write a short `NOTES.md` documenting the discovered endpoints, auth flow, token lifetimes,
and any IDs/enums needed for searches.

## Reverse-engineering methodology
Work in phases, and **do not write server code until you have replayed every call by hand**.
Build the (easy) business endpoints first and the (hard) auth flow last, so you are never
debugging both at once.

**Phase 0 — capture setup.** A ready-to-use local capture rig lives in `capture/` (see
`capture/README.md`): mitmproxy + a standalone Chrome routed through it, no system installs.
Run `capture/start-proxy.sh` (proxy on `127.0.0.1:8080`, inspector UI on `127.0.0.1:8081`,
flows saved to `capture/flows.mitm`) and `capture/launch-chrome.sh https://online24.medicover.pl/`
to drive the portal through the proxy. Alternatively, browser DevTools → Network with
**Preserve log** and **Disable cache** on, filtered to Fetch/XHR; "Copy as cURL" + a
curl→Python converter to replay individual calls, or export HAR for a whole session.

**Phase 1 — auth flow (the hard part; OAuth2/OIDC, likely IdentityServer + PKCE).** Two
shortcuts first: (a) fetch `GET https://<auth-host>/.well-known/openid-configuration` to get
`authorization_endpoint`, `token_endpoint`, and supported scopes directly; (b) decode the
bearer **JWT** (jwt.io or locally) to read scopes, `exp`, and how the patient/subaccount
context is encoded. Then log in manually with capture running and map the full chain:
`/authorize` (note the PKCE `code_challenge`) → username/password POST → **SMS-code POST** →
`code` → **token exchange at `/token`** returning access + **refresh** tokens. Record every
`Set-Cookie`, especially the **trusted-device cookie** that may let later logins skip 2FA.
Trust your own capture over `medihunter` here.

**Phase 2 — business endpoints (easy).** With a valid token, do each action once in the UI
and record method + URL + query params + body + response shape for: list/switch patient,
list appointments, search slots, book, reschedule. Note how the **patient/subaccount** is
passed (e.g. an "on behalf of" member ID) and how slots are identified — these feed the tool
schemas directly.

**Phase 3 — replay before automating.** Replay each business call from Python (`httpx`)
using a **manually-obtained** token until they all work; only then automate the Phase 1 auth
flow to produce tokens programmatically (SMS handled interactively in the bootstrap CLI),
persist the refresh token, and wire calls into MCP tools.

**Phase 4 — measure token lifetime.** Save the refresh token and re-run a refresh after
~1 hour / ~1 day / several days to find when it dies (the JWT `exp` only covers the
short-lived access token — measure the refresh/trusted-device lifetime empirically). This
answer decides whether the in-MCP SMS-fallback tools are needed.

## Safety & conduct (medical data — be conservative)
- **Read-before-write**: booking/rescheduling tools should confirm the target slot is still
  valid immediately before acting, and return the concrete result (what was booked/moved).
- **No destructive defaults**: `reschedule_appointment` must only move to a slot the caller
  explicitly selected (or, for the "earlier slot" use case, only when the new slot is
  strictly earlier than the current one); never silently cancel without rebooking.
- **Be a polite client**: reasonable request rate/backoff, sane timeouts, a stable
  User-Agent; do not hammer the portal. The daily-check cadence should be respectful.
- **Privacy**: do not log request/response bodies containing personal or medical data;
  redact tokens; keep the credential store local and permission-restricted.
- **Idempotency/clarity**: tools return structured results an agent can reason about
  (e.g. slot IDs, datetimes, clinic/doctor names), and surface errors explicitly rather
  than failing silently.

## Deliverables
- The MCP server (`list_patients` + the four appointment tools + needed lookups) with the
  two-phase auth.
- The `medicover-auth` bootstrap CLI.
- `README.md`: setup, env vars, bootstrap login steps, and MCP client config snippet.
- `NOTES.md`: discovered API/auth details and the token-lifetime decision.
- Basic tests for request building, token refresh, and tool input validation
  (mock the HTTP layer — do not hit the live portal in tests).
