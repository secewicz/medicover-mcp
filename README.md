# medicover-mcp

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent manage appointments on
Medicover's Polish patient portal (`https://online24.medicover.pl/`). It talks directly to the
portal's private JSON API (reverse-engineered from real traffic — see
[`NOTES.md`](./NOTES.md)); it does **not** drive a browser at runtime.

It is built for an **unattended daily routine**: hunt for scarce slots and optionally rebook
an existing appointment to an earlier one — including for linked dependents (e.g. children).

## Tools

| Tool | Purpose |
|------|---------|
| `list_patients` | The account holder + linked dependents, each with a stable `patient_id` (MRN). |
| `list_appointments` | A patient's planned/past appointments (read-only). |
| `search_slots` | Available slots by region + specialty (optionally doctor/clinic/language, date range, and slot-search type e.g. `DiagnosticProcedure`). Each slot reports its `visit_type` (Center/Phone/PhoneAdvice). |
| `book_appointment` | Book a slot for a patient — `patient_id` **required**. |
| `reschedule_appointment` | Move an appointment to another slot; "earlier-only" by default. |
| `list_appointment_filters` | Resolve specialty/doctor/clinic/region **names → IDs** from history. |
| `list_search_filters` | Clinics/doctors/languages bookable for a region + specialty. |

Patient-scoped read tools default to the account holder; the **write** tools require an
explicit `patient_id` so a booking can never land on the wrong person. Nothing else (messaging,
records, prescriptions, payments, cancel-without-rebook) is exposed.

## Authentication (two-phase)

Login uses SMS 2FA, which can't be in an unattended hot path, so:

1. **One-time bootstrap (interactive CLI, not a tool):**
   ```bash
   export MEDICOVER_USERNAME=<your-MRN-or-login>
   export MEDICOVER_PASSWORD=<your-password>   # or omit to be prompted
   uv run medicover-auth login                 # prompts for the SMS code
   ```
   This completes OAuth + 2FA and saves the **refresh token** to a `0600` file (default
   `~/.config/medicover-mcp/credentials.json`; override with `MEDICOVER_STORE_PATH`).
   Username/password are never stored.

2. **Unattended runtime:** the MCP server loads the refresh token and silently refreshes the
   short-lived (~3 min) access token on every run. No password or SMS is ever needed during
   tool calls.

3. **On expiry/revocation:** tools fail with `session expired — run medicover-auth login`;
   they never prompt for an SMS through a tool call.

> **Token-lifetime decision:** the in-MCP `request_sms_code`/`submit_sms_code` fallback is
> **not** shipped — see the reasoning in [`NOTES.md`](./NOTES.md#token-lifetime--the-sms-fallback-decision).

Helpers: `uv run medicover-auth status` (shows whether creds exist, no secrets) and
`uv run medicover-auth logout` (deletes them).

## Setup

```bash
uv sync                 # create the venv and install
uv run medicover-auth login
uv run pytest           # run the tests (no network — HTTP is mocked)
```

## MCP client config

Add to your MCP client (e.g. Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "medicover": {
      "command": "uv",
      "args": ["--directory", "/abs/path/to/medicover", "run", "medicover-mcp"],
      "env": {
        "MEDICOVER_STORE_PATH": "/home/you/.config/medicover-mcp/credentials.json"
      }
    }
  }
}
```

(Run `medicover-auth login` once on the same machine first so the credential store exists.)

## Environment variables

| Var | Used by | Meaning |
|-----|---------|---------|
| `MEDICOVER_USERNAME` / `MEDICOVER_PASSWORD` | bootstrap only | Login credentials (else prompted). |
| `MEDICOVER_STORE_PATH` | bootstrap + server | Credential file path (default `~/.config/medicover-mcp/credentials.json`). |
| `MEDICOVER_TIMEOUT` | server | HTTP timeout seconds (default 30). |

## Example agent flow (earlier-slot hunt for a child)

1. `list_patients` → find the child's `patient_id`.
2. `list_appointments(patient_id=child, state="Planned")` → note the appointment to improve and its `appointment_id`/date.
3. `list_appointment_filters(patient_id=child)` → get the region id and specialty id.
4. `search_slots(patient_id=child, region_ids=[...], specialty_ids=[...], start_date="today")`.
5. If an earlier slot exists: `reschedule_appointment(patient_id=child, appointment_id=..., booking_string=<slot>, new_slot_date=<slot date>)` (refuses unless strictly earlier).

## Safety

Read-before-write on booking/reschedule (the portal validates the slot at action time);
reschedule never cancels without rebooking and defaults to earlier-only; polite request pacing
with backoff; tokens/credentials are never logged or returned; request/response bodies (which
carry medical data) are not logged.

## Fork changes (secewicz/medicover-mcp)

Forked from mattijskersten/medimcp at 09c9415 for the Home Lab's mcp-hub. Two behavioural changes, nothing else:

- `book_appointment` and `reschedule_appointment` take `confirm: bool = False` and refuse (reply starts
  `CONFIRMATION REQUIRED`) unless it is `true`, so a human approves each write.
- `reschedule_appointment` lost its `require_earlier` parameter: it can only move to a strictly earlier slot.

## Disclaimer

Unofficial, built against an undocumented private API that may change without notice. Use with
your own account and within Medicover's terms. Not affiliated with Medicover.
