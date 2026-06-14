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


@pytest.fixture
def fake_client(monkeypatch):
    fc = FakeClient()
    monkeypatch.setattr(server, "_get_client", lambda: fc)
    return fc


async def test_list_appointments_rejects_bad_state(fake_client):
    with pytest.raises(RuntimeError, match="Planned, Past, All"):
        await server.list_appointments(patient_id=1, state="Soon")


async def test_book_returns_appointment_id(fake_client):
    result = await server.book_appointment(patient_id=2220055, booking_string="BSTR")
    assert result.booked is True
    assert result.appointment_id == 999


async def test_reschedule_refuses_later_slot_when_earlier_required(fake_client):
    # New slot (2026-06-21) is LATER than the current appointment (2026-06-20).
    with pytest.raises(RuntimeError, match="not strictly earlier"):
        await server.reschedule_appointment(
            patient_id=2220055, appointment_id="APPT-1", booking_string="BSTR",
            new_slot_date="2026-06-21T09:00:00", require_earlier=True,
        )
    assert fake_client.reschedule_called is False


async def test_reschedule_allows_earlier_slot(fake_client):
    result = await server.reschedule_appointment(
        patient_id=2220055, appointment_id="APPT-1", booking_string="BSTR",
        new_slot_date="2026-06-18T09:00:00", require_earlier=True,
    )
    assert result.rescheduled is True
    assert fake_client.reschedule_called is True
    assert result.old_date == "2026-06-20T10:00:00"
    assert result.new_date == "2026-06-18T09:00:00"


async def test_reschedule_rejects_unknown_appointment(fake_client):
    with pytest.raises(RuntimeError, match="not found"):
        await server.reschedule_appointment(
            patient_id=2220055, appointment_id="DOES-NOT-EXIST", booking_string="BSTR",
            new_slot_date="2026-06-18T09:00:00",
        )
    assert fake_client.reschedule_called is False


async def test_reschedule_later_allowed_when_override(fake_client):
    result = await server.reschedule_appointment(
        patient_id=2220055, appointment_id="APPT-1", booking_string="BSTR",
        new_slot_date="2026-06-25T09:00:00", require_earlier=False,
    )
    assert result.rescheduled is True
