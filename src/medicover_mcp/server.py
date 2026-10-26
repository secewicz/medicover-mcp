"""FastMCP server exposing the Medicover appointment tools.

Surface (deliberately minimal — this is medical data):
  list_patients, list_appointments, search_slots, book_appointment,
  reschedule_appointment, plus two read-only lookup tools to resolve opaque IDs.

The SMS-2FA `request_sms_code`/`submit_sms_code` pair is intentionally NOT exposed; see the
token-lifetime decision in NOTES.md. Expiry surfaces as a clear "run `medicover-auth login`".
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from . import config, models
from .auth import AuthError
from .client import MedicoverClient, MedicoverError
from .store import CredentialError, CredentialStore

log = logging.getLogger("medicover_mcp")

mcp = FastMCP("medicover")

# Fork change: the lab's mcp-hub guard lists a read tool only if the server says readOnlyHint=true.
_READ_ONLY = ToolAnnotations(readOnlyHint=True)

_settings = config.Settings.from_env()
_store = CredentialStore(_settings.store_path)
_client: MedicoverClient | None = None


def _get_client() -> MedicoverClient:
    global _client
    if _client is None:
        _client = MedicoverClient(_store, _settings)
    return _client


def _require_confirmation(tool: str, confirm: bool, what: str = "changes a real medical appointment") -> None:
    """Write gate (fork change). The text starts with CONFIRMATION REQUIRED because the lab's
    mcp-hub guard recognises that phrase and refunds the write-budget slot for such a reply."""
    if confirm is not True:
        raise RuntimeError(
            f"CONFIRMATION REQUIRED: {tool} {what}. Show the human what is about to happen "
            "and call again with confirm=true only after they approve it."
        )


def _friendly(exc: Exception) -> str:
    if isinstance(exc, (AuthError, CredentialError)):
        return f"Authentication problem: {exc}"
    if isinstance(exc, MedicoverError):
        return f"Medicover API error: {exc}"
    return f"Unexpected error: {exc}"


# --- patients ---------------------------------------------------------------------------


@mcp.tool(annotations=_READ_ONLY)
async def list_patients() -> list[models.Patient]:
    """List every patient the logged-in account can act on.

    Returns the account holder plus any linked dependents (e.g. children). Each entry has a
    stable `patient_id` (MRN) used by all other tools, and `is_account_holder` marks the
    logged-in user. Use these IDs — never names — for the patient-scoped tools.
    """
    try:
        profiles = await _get_client().list_profiles()
        return [models.Patient.from_profile(p) for p in profiles]
    except Exception as exc:  # noqa: BLE001 - surface a clean message to the agent
        raise RuntimeError(_friendly(exc)) from exc


# --- appointments -----------------------------------------------------------------------


@mcp.tool(annotations=_READ_ONLY)
async def list_appointments(
    patient_id: Annotated[
        int | None,
        Field(description="MRN of the patient. Defaults to the account holder when omitted."),
    ] = None,
    state: Annotated[
        str, Field(description="Which appointments: 'Planned', 'Past', or 'All'.")
    ] = "Planned",
) -> list[models.Appointment]:
    """List a patient's appointments (upcoming by default).

    Each appointment includes an opaque `appointment_id` (pass it to reschedule_appointment)
    and a `can_reschedule` flag. Read-only.
    """
    if state not in ("Planned", "Past", "All"):
        raise RuntimeError("state must be one of: Planned, Past, All")
    try:
        items = await _get_client().list_appointments(patient_id, state)
        return [models.Appointment.from_item(it) for it in items]
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(_friendly(exc)) from exc


# --- reference / lookup -----------------------------------------------------------------


@mcp.tool(annotations=_READ_ONLY)
async def list_appointment_filters(
    patient_id: Annotated[
        int | None, Field(description="MRN; defaults to the account holder.")
    ] = None,
) -> models.FilterOptions:
    """Resolve names → IDs from a patient's own visit history.

    Returns the specialties, doctors, clinics and regions seen in this patient's appointments,
    each as {id, name}. Use this to discover the opaque IDs that search_slots needs (e.g. the
    region id and a specialty id), then narrow further with list_search_filters. Read-only.
    """
    try:
        data = await _get_client().list_appointments_filters(patient_id)
        return models.FilterOptions(
            specialties=models.to_named_refs(data.get("specialties", [])),
            doctors=models.to_named_refs(data.get("doctors", [])),
            clinics=models.to_named_refs(data.get("clinics", [])),
            regions=models.to_named_refs(data.get("regions", [])),
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(_friendly(exc)) from exc


@mcp.tool(annotations=_READ_ONLY)
async def list_search_filters(
    region_ids: Annotated[list[str], Field(description="Region IDs (e.g. ['204'] = Warszawa).")],
    specialty_ids: Annotated[list[str], Field(description="Specialty IDs to search within.")],
    patient_id: Annotated[
        int | None, Field(description="MRN; defaults to the account holder.")
    ] = None,
    doctor_ids: Annotated[
        list[str] | None, Field(description="Optional doctor IDs to narrow the result.")
    ] = None,
    slot_search_type: Annotated[
        str,
        Field(description="Match the search_slots value: 'Standard' (default) or "
                          "'DiagnosticProcedure'."),
    ] = "Standard",
) -> models.FilterOptions:
    """List the clinics, doctors and languages bookable for a region + specialty selection.

    Use this after picking a region and specialty to enumerate valid clinic and doctor IDs
    before calling search_slots. Read-only.
    """
    try:
        data = await _get_client().search_filters(
            patient_id,
            region_ids=region_ids,
            specialty_ids=specialty_ids,
            doctor_ids=doctor_ids,
            slot_search_type=slot_search_type,
        )
        return models.FilterOptions(
            specialties=models.to_named_refs(data.get("specialties", []), name_key="value"),
            clinics=models.to_named_refs(data.get("clinics", []), name_key="value"),
            doctors=models.to_named_refs(data.get("doctors", []), name_key="value"),
            languages=models.to_named_refs(data.get("doctorLanguages", []), name_key="name"),
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(_friendly(exc)) from exc


# --- slot search ------------------------------------------------------------------------


@mcp.tool(annotations=_READ_ONLY)
async def search_slots(
    region_ids: Annotated[list[str], Field(description="Region IDs (e.g. ['204']). Required.")],
    specialty_ids: Annotated[list[str], Field(description="Specialty IDs. Required.")],
    start_date: Annotated[
        str, Field(description="Earliest date to search from, YYYY-MM-DD.")
    ],
    end_date: Annotated[
        str | None,
        Field(description="Optional latest date (YYYY-MM-DD). Slots after this date are "
                          "dropped client-side (the portal only honours a start date)."),
    ] = None,
    patient_id: Annotated[
        int | None, Field(description="MRN; defaults to the account holder.")
    ] = None,
    doctor_ids: Annotated[list[str] | None, Field(description="Optional doctor IDs.")] = None,
    clinic_ids: Annotated[list[str] | None, Field(description="Optional clinic IDs.")] = None,
    language_ids: Annotated[
        list[str] | None,
        Field(description="Optional doctor-language IDs (e.g. 4=Polski, 6=Angielski, "
                          "60=Ukraiński; resolve others via list_search_filters)."),
    ] = None,
    slot_search_type: Annotated[
        str,
        Field(description="Slot category. 'Standard' (default) for normal consultations; "
                          "'DiagnosticProcedure' for diagnostic procedures."),
    ] = "Standard",
) -> models.SlotSearchResult:
    """Find available appointment slots for a specialty/region (optionally doctor/clinic).

    Each returned slot carries a `booking_string` — the single-use handle you pass to
    book_appointment or reschedule_appointment, and a `visit_type` (Center | Phone |
    PhoneAdvice). The portal has no visit-type search filter, so to get in-person ("Center")
    visits, choose an in-person specialty and/or filter the returned slots by `visit_type`.
    `next_search_date` hints the StartTime to use to page further into the future. Re-run this
    immediately before booking, because a booking_string can expire. Read-only.
    """
    try:
        sd = models.normalize_date(start_date)
        ed = models.normalize_date(end_date) if end_date else None
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    try:
        data = await _get_client().search_slots(
            patient_id,
            region_ids=region_ids,
            specialty_ids=specialty_ids,
            start_date=sd,
            doctor_ids=doctor_ids,
            clinic_ids=clinic_ids,
            language_ids=language_ids,
            slot_search_type=slot_search_type,
        )
        slots = [models.Slot.from_item(it) for it in data.get("items", [])]
        if ed is not None:
            slots = [s for s in slots if s.date[:10] <= ed]
        return models.SlotSearchResult(
            count=len(slots) if ed is not None else data.get("count", len(slots)),
            next_search_date=data.get("nextSearchDate"),
            slots=slots,
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(_friendly(exc)) from exc


# --- write tools ------------------------------------------------------------------------


@mcp.tool()
async def book_appointment(
    patient_id: Annotated[
        int,
        Field(description="MRN of the patient to book for. REQUIRED — never guessed."),
    ],
    booking_string: Annotated[
        str, Field(description="The `booking_string` of the slot to book (from search_slots).")
    ],
    reporting_id: Annotated[
        str,
        Field(description="Reporting/correlation token. Whether the portal requires it is "
                          "unverified (see NOTES.md); the in-scope search flow has no source "
                          "for one, so leave empty unless you captured a value."),
    ] = "",
    confirm: Annotated[
        bool,
        Field(description="Must be true to actually book. Leave false until the human has "
                          "approved this exact slot for this exact patient."),
    ] = False,
) -> models.BookingResult:
    """Book an available slot for a specific patient.

    `patient_id` is mandatory so a booking can never land on the wrong person's record. The
    portal validates the slot at booking time (read-before-write); if the slot is gone you get
    a clear error and nothing is booked. Returns the new appointment id on success.

    Note: `reporting_id` defaults to empty. It's unverified whether the API requires it (the
    captured bookings carried one from the out-of-scope triage flow); if booking fails citing
    it, that's the likely cause.
    """
    _require_confirmation("book_appointment", confirm)
    try:
        result = await _get_client().book_appointment(
            patient_id, booking_string=booking_string, reporting_id=reporting_id
        )
        appt_id = result.get("appointmentId")
        return models.BookingResult(
            booked=appt_id is not None,
            appointment_id=appt_id,
            message=None if appt_id is not None else "No appointment id returned.",
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(_friendly(exc)) from exc


@mcp.tool()
async def reschedule_appointment(
    patient_id: Annotated[
        int, Field(description="MRN of the patient. REQUIRED — never guessed.")
    ],
    appointment_id: Annotated[
        str, Field(description="The `appointment_id` of the existing appointment to move.")
    ],
    booking_string: Annotated[
        str, Field(description="`booking_string` of the new slot (from search_slots).")
    ],
    new_slot_date: Annotated[
        str,
        Field(description="The new slot's datetime (ISO, as shown by search_slots). Used for "
                          "the earlier-only safety check and to report the move."),
    ],
    confirm: Annotated[
        bool,
        Field(description="Must be true to actually move the appointment. Leave false until "
                          "the human has approved this exact move."),
    ] = False,
) -> models.RescheduleResult:
    """Move an existing appointment to a strictly EARLIER slot (atomic; never cancels).

    Only moves to the slot you explicitly pass, and only if it is strictly earlier than the
    current appointment (fork change: the upstream `require_earlier=false` override is gone, so
    an agent cannot move an appointment later). The portal re-validates the slot at
    reschedule time.
    """
    _require_confirmation("reschedule_appointment", confirm)
    client = _get_client()
    try:
        # Read-before-write: locate the current appointment to learn its date.
        planned = await client.list_appointments(patient_id, "Planned")
        current = next((a for a in planned if a.get("id") == appointment_id), None)
        old_date = current.get("date") if current else None
        if current is None:
            raise RuntimeError(
                "appointment_id not found among this patient's planned appointments; "
                "refusing to reschedule an unknown appointment"
            )
        # ISO 8601 datetimes compare correctly as strings (same offset assumed).
        if old_date is None or new_slot_date[:19] >= old_date[:19]:
            raise RuntimeError(
                f"new slot {new_slot_date} is not strictly earlier than the current "
                f"appointment {old_date}; refusing"
            )
        result = await client.reschedule_appointment(
            patient_id,
            old_appointment_string=appointment_id,
            booking_string=booking_string,
        )
        status = result.get("status", "Unknown")
        return models.RescheduleResult(
            rescheduled=status.lower() == "success",
            status=status,
            old_date=old_date,
            new_date=new_slot_date,
            message=result.get("message"),
        )
    except RuntimeError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(_friendly(exc)) from exc


# --- login hand-off (fork change): the hub's renewer may stop at the portal's emailed-code page -----------------------------

_LOGIN_MESSAGES = {
    "ok": "The login works.",
    "renewing": "The hub is logging in again right now; check again in a minute.",
    "awaiting_code": "The portal sent an emailed code. Ask the person for the digits and call submit_login_code before the deadline.",
    "blocked_password": "The portal rejected the stored password. Nothing will retry until the password in SOPS is changed.",
    "blocked_code": "The portal asked for an emailed code and none arrived in time. The renewer tries again within an hour.",
    "blocked_repeated": "The renewer failed several times in a row and is paused for a few hours.",
    "waiting": "The login is down; the renewer is waiting out its attempt limit.",
    "unreachable": "This instance could not be reached by the renewer.",
}


def _login_state() -> dict:
    path = os.environ.get("MEDICOVER_STATUS_FILE")
    try:
        data = json.loads(Path(path).read_text()) if path else {}
    except (OSError, ValueError):
        data = {}
    return data if isinstance(data, dict) else {}


@mcp.tool(annotations=_READ_ONLY)
async def login_status() -> dict:
    """What the hub's login renewer is doing for THIS account: ok, renewing, awaiting_code, blocked_*, waiting.

    Cheap: it reads a status file and does not call the portal. When it says `awaiting_code`, the portal has e-mailed a code to the
    person and the hub's browser is waiting for it until `deadline` (unix seconds): get the digits from the person and call
    submit_login_code. Read-only.
    """
    st = _login_state()
    state = st.get("state") or "unknown"
    deadline = st.get("deadline")
    live = state == "awaiting_code" and isinstance(deadline, (int, float)) and deadline > time.time()
    return {
        "state": state if (state != "awaiting_code" or live) else "blocked_code",
        "message": _LOGIN_MESSAGES.get(state, "No status yet: the renewer has not run for this account."),
        "can_submit_code": bool(live),
        "seconds_left": int(deadline - time.time()) if live else 0,
        "updated": st.get("updated"),
    }


@mcp.tool()
async def submit_login_code(
    code: Annotated[str, Field(description="The 4 to 8 digit code the portal e-mailed to the person. Digits only.")],
    confirm: Annotated[
        bool,
        Field(description="Must be true. Leave false until the person has given you the code in this conversation."),
    ] = False,
) -> dict:
    """Hand the e-mailed login code to the hub's waiting browser (only when login_status says awaiting_code).

    The browser types it, ticks 'trust this device' so later logins need only the password, and stores the new session. The code is
    useless without the password that only the hub holds. Check login_status again after a few seconds.
    """
    _require_confirmation("submit_login_code", confirm, "hands a login code to the hub's browser")
    digits = code.strip()
    if not (digits.isdigit() and 4 <= len(digits) <= 8):
        raise RuntimeError("the code must be 4 to 8 digits and nothing else")
    st = _login_state()
    deadline = st.get("deadline")
    if st.get("state") != "awaiting_code" or not isinstance(deadline, (int, float)) or deadline <= time.time():
        raise RuntimeError("no code is being waited for right now (login_status says " + str(st.get("state") or "unknown") + ")")
    target = _settings.store_path.parent / "pending-code.txt"
    tmp = target.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(digits)
    os.replace(tmp, target)
    return {"submitted": True, "message": "The code was handed to the browser. Check login_status in a few seconds."}


def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    mcp.run()


if __name__ == "__main__":
    main()
