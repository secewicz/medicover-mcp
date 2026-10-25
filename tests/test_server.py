"""Tool-level behaviour: input validation and the reschedule safety guards.

The client is replaced with a fake so no network or token logic is exercised here.
"""

from __future__ import annotations

import pytest

from medicover_mcp import server


class FakeClient:
    def __init__(self):
        self.reschedule_called = False
        self.planned = [{"id": "APPT-1", "date": "2026-06-20T10:00:00", "state": "Planned"}]

    async def list_appointments(self, patient_id, state, specialty_id=None):
        return self.planned

    async def reschedule_appointment(self, patient_id, *, old_appointment_string, booking_string):
        self.reschedule_called = True
        return {"status": "Success", "message": None}

    async def book_appointment(self, patient_id, *, booking_string, reporting_id=""):
        return {"appointmentId": 999}

    async def search_slots(self, patient_id, **kwargs):
        self.search_kwargs = kwargs
        return {
            "count": 3,
            "nextSearchDate": None,
            "items": [
                {"bookingString": "B1", "appointmentDate": "2026-06-16T07:00:00"},
                {"bookingString": "B2", "appointmentDate": "2026-06-18T09:00:00"},
                {"bookingString": "B3", "appointmentDate": "2026-06-25T11:00:00"},
            ],
        }


@pytest.fixture
def fake_client(monkeypatch):
    fc = FakeClient()
    monkeypatch.setattr(server, "_get_client", lambda: fc)
    return fc


async def test_list_appointments_rejects_bad_state(fake_client):
    with pytest.raises(RuntimeError, match="Planned, Past, All"):
        await server.list_appointments(patient_id=1, state="Soon")


async def test_book_returns_appointment_id(fake_client):
    result = await server.book_appointment(patient_id=2220055, booking_string="BSTR", confirm=True)
    assert result.booked is True
    assert result.appointment_id == 999


async def test_reschedule_refuses_later_slot_when_earlier_required(fake_client):
    # New slot (2026-06-21) is LATER than the current appointment (2026-06-20).
    with pytest.raises(RuntimeError, match="not strictly earlier"):
        await server.reschedule_appointment(
            patient_id=2220055, appointment_id="APPT-1", booking_string="BSTR",
            new_slot_date="2026-06-21T09:00:00",
            confirm=True,
        )
    assert fake_client.reschedule_called is False


async def test_reschedule_allows_earlier_slot(fake_client):
    result = await server.reschedule_appointment(
        patient_id=2220055, appointment_id="APPT-1", booking_string="BSTR",
        new_slot_date="2026-06-18T09:00:00",
            confirm=True,
    )
    assert result.rescheduled is True
    assert fake_client.reschedule_called is True
    assert result.old_date == "2026-06-20T10:00:00"
    assert result.new_date == "2026-06-18T09:00:00"


async def test_reschedule_rejects_unknown_appointment(fake_client):
    with pytest.raises(RuntimeError, match="not found"):
        await server.reschedule_appointment(
            patient_id=2220055, appointment_id="DOES-NOT-EXIST", booking_string="BSTR",
            new_slot_date="2026-06-18T09:00:00", confirm=True,
        )
    assert fake_client.reschedule_called is False


async def test_reschedule_has_no_later_override(fake_client):
    # The fork removed require_earlier: a later slot is always refused.
    with pytest.raises(RuntimeError, match="not strictly earlier"):
        await server.reschedule_appointment(
            patient_id=2220055, appointment_id="APPT-1", booking_string="BSTR",
            new_slot_date="2026-06-25T09:00:00", confirm=True,
        )
    assert fake_client.reschedule_called is False


async def test_book_without_confirm_is_refused_and_does_not_call(fake_client, monkeypatch):
    called = []
    async def boom(*a, **k):
        called.append(1)
    monkeypatch.setattr(fake_client, "book_appointment", boom)
    for kwargs in ({}, {"confirm": False}):
        with pytest.raises(RuntimeError, match="CONFIRMATION REQUIRED"):
            await server.book_appointment(patient_id=2220055, booking_string="BSTR", **kwargs)
    assert called == []


async def test_reschedule_without_confirm_is_refused_and_does_not_call(fake_client):
    with pytest.raises(RuntimeError, match="CONFIRMATION REQUIRED"):
        await server.reschedule_appointment(
            patient_id=2220055, appointment_id="APPT-1", booking_string="BSTR",
            new_slot_date="2026-06-18T09:00:00",
        )
    assert fake_client.reschedule_called is False


async def test_search_slots_end_date_filters_client_side(fake_client):
    result = await server.search_slots(
        region_ids=["204"], specialty_ids=["9"],
        start_date="2026-06-16", end_date="2026-06-20",
    )
    # Only the two slots on/before 2026-06-20 survive; the 06-25 one is dropped.
    assert result.count == 2
    assert [s.booking_string for s in result.slots] == ["B1", "B2"]


async def test_search_slots_forwards_search_type(fake_client):
    await server.search_slots(
        region_ids=["204"], specialty_ids=["9"], start_date="2026-06-16",
        slot_search_type="DiagnosticProcedure",
    )
    assert fake_client.search_kwargs["slot_search_type"] == "DiagnosticProcedure"
