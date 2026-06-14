"""Pydantic models for MCP tool inputs and outputs.

Kept deliberately close to the portal's JSON so an agent sees stable IDs, ISO datetimes and
human-readable clinic/doctor/specialty names it can reason about.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from pydantic import BaseModel, Field


# --- Outputs ----------------------------------------------------------------------------


class Patient(BaseModel):
    patient_id: int = Field(description="MRN — the stable patient identifier used by all tools.")
    name: str
    surname: str
    is_account_holder: bool = Field(description="True for the logged-in account holder.")
    is_child: bool
    access_level: str = Field(description='e.g. "Owner" or "Linked".')

    @classmethod
    def from_profile(cls, p: dict) -> "Patient":
        return cls(
            patient_id=p["mrn"],
            name=p.get("name", ""),
            surname=p.get("surname", ""),
            is_account_holder=bool(p.get("isMain")),
            is_child=bool(p.get("isChild")),
            access_level=p.get("accessLevel", ""),
        )


class NamedRef(BaseModel):
    id: str
    name: str


class Appointment(BaseModel):
    appointment_id: str = Field(
        description="Opaque appointment handle; pass as `appointment_id` to reschedule_appointment."
    )
    date: str = Field(description="Local appointment datetime, ISO 8601.")
    date_offset: str | None = Field(default=None, description="Same instant with UTC offset.")
    state: str = Field(description="Planned | Past | …")
    specialty: NamedRef | None = None
    doctor: NamedRef | None = None
    clinic: NamedRef | None = None
    region: NamedRef | None = None
    visit_type: str | None = None
    can_reschedule: bool = False
    can_cancel: bool = False

    @classmethod
    def from_item(cls, it: dict) -> "Appointment":
        attrs = it.get("attributes") or {}
        return cls(
            appointment_id=it["id"],
            date=it.get("date", ""),
            date_offset=it.get("dateOffset"),
            state=it.get("state", ""),
            specialty=_ref(it.get("specialty")),
            doctor=_ref(it.get("doctor")),
            clinic=_ref(it.get("clinic")),
            region=_ref(it.get("region")),
            visit_type=it.get("visitType"),
            can_reschedule=bool(attrs.get("canReschedule")),
            can_cancel=bool(attrs.get("canCancel")),
        )


class Slot(BaseModel):
    booking_string: str = Field(
        description="Opaque, single-use slot handle. Pass to book_appointment / "
        "reschedule_appointment. Re-search right before booking — it can expire."
    )
    date: str = Field(description="Local slot datetime, ISO 8601.")
    date_offset: str | None = None
    specialty: NamedRef | None = None
    doctor: NamedRef | None = None
    clinic: NamedRef | None = None
    visit_type: str | None = None
    is_overbooking: bool = False

    @classmethod
    def from_item(cls, it: dict) -> "Slot":
        return cls(
            booking_string=it["bookingString"],
            date=it.get("appointmentDate", ""),
            date_offset=it.get("appointmentDateOffset"),
            specialty=_ref(it.get("specialty")),
            doctor=_ref(it.get("doctor")),
            clinic=_ref(it.get("clinic")),
            visit_type=it.get("visitType"),
            is_overbooking=bool(it.get("isOverbooking")),
        )


class SlotSearchResult(BaseModel):
    count: int
    next_search_date: str | None = Field(
        default=None, description="Hint for the next StartTime when paging forward in time."
    )
    slots: list[Slot]


class BookingResult(BaseModel):
    booked: bool
    appointment_id: int | None = None
    slot_date: str | None = None
    doctor: str | None = None
    clinic: str | None = None
    message: str | None = None


class RescheduleResult(BaseModel):
    rescheduled: bool
    status: str
    old_date: str | None = None
    new_date: str | None = None
    message: str | None = None


class FilterOptions(BaseModel):
    """Reference data for building a slot search (resolve names → opaque IDs)."""

    specialties: list[NamedRef] = []
    clinics: list[NamedRef] = []
    doctors: list[NamedRef] = []
    regions: list[NamedRef] = []
    languages: list[NamedRef] = []


# --- helpers ----------------------------------------------------------------------------


def _ref(obj: dict[str, Any] | None) -> NamedRef | None:
    if not obj:
        return None
    rid = obj.get("id")
    if rid is None:
        return None
    # Some endpoints use {"id","name"}, others {"id","value"}.
    return NamedRef(id=str(rid), name=str(obj.get("name", obj.get("value", ""))))


def to_named_refs(items: list[dict], name_key: str = "name") -> list[NamedRef]:
    out = []
    for it in items or []:
        rid = it.get("id")
        if rid is None:
            continue
        out.append(NamedRef(id=str(rid), name=str(it.get(name_key, it.get("value", "")))))
    return out


def normalize_date(value: str | date) -> str:
    """Accept a date or ISO string and return YYYY-MM-DD for the StartTime query param."""
    if isinstance(value, date):
        return value.isoformat()
    # Validate it parses; keep only the date portion.
    try:
        return date.fromisoformat(str(value)[:10]).isoformat()
    except ValueError as exc:
        raise ValueError(f"invalid date {value!r}; expected YYYY-MM-DD") from exc
