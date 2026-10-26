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


async def test_read_tools_are_hinted_read_only_and_writes_are_not():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    reads = {"list_patients", "list_appointments", "list_appointment_filters",
             "list_search_filters", "search_slots", "login_status"}
    writes = {"book_appointment", "reschedule_appointment", "submit_login_code"}
    assert set(tools) == reads | writes
    for name in reads:
        assert tools[name].annotations is not None and tools[name].annotations.readOnlyHint is True
    for name in writes:
        assert not (tools[name].annotations and tools[name].annotations.readOnlyHint)
        assert "confirm" in tools[name].inputSchema["properties"]


# --- login hand-off ------------------------------------------------------------------------------


def _status(tmp_path, monkeypatch, **fields):
    import json
    from medicover_mcp import config
    path = tmp_path / "status.json"
    path.write_text(json.dumps(fields))
    monkeypatch.setenv("MEDICOVER_STATUS_FILE", str(path))
    monkeypatch.setattr(server, "_settings", config.Settings(store_path=tmp_path / "creds.json", request_timeout=5, username=None, password=None))


async def test_login_status_reports_the_waiting_code_and_how_long_is_left(tmp_path, monkeypatch):
    import time
    _status(tmp_path, monkeypatch, state="awaiting_code", deadline=int(time.time()) + 300, updated=1)
    out = await server.login_status()
    assert out["state"] == "awaiting_code" and out["can_submit_code"] is True and 250 < out["seconds_left"] <= 300


async def test_an_expired_wait_is_reported_as_no_longer_possible(tmp_path, monkeypatch):
    import time
    _status(tmp_path, monkeypatch, state="awaiting_code", deadline=int(time.time()) - 5)
    out = await server.login_status()
    assert out["can_submit_code"] is False and out["state"] == "blocked_code"


async def test_login_status_without_a_file_says_so(monkeypatch):
    monkeypatch.delenv("MEDICOVER_STATUS_FILE", raising=False)
    out = await server.login_status()
    assert out["state"] == "unknown" and out["can_submit_code"] is False


async def test_submit_login_code_needs_confirm_and_digits_and_a_waiting_browser(tmp_path, monkeypatch):
    import time
    _status(tmp_path, monkeypatch, state="awaiting_code", deadline=int(time.time()) + 300)
    with pytest.raises(RuntimeError, match="CONFIRMATION REQUIRED"):
        await server.submit_login_code("123456")
    assert not (tmp_path / "pending-code.txt").exists()
    for bad in ("12", "abcdef", "12 34 56", "123456789", ""):
        with pytest.raises(RuntimeError, match="4 to 8 digits"):
            await server.submit_login_code(bad, confirm=True)
    out = await server.submit_login_code(" 123456 ", confirm=True)
    f = tmp_path / "pending-code.txt"
    assert out["submitted"] is True and f.read_text() == "123456"
    import stat
    assert stat.S_IMODE(f.stat().st_mode) == 0o600


async def test_submit_login_code_refuses_when_nothing_waits(tmp_path, monkeypatch):
    _status(tmp_path, monkeypatch, state="ok")
    with pytest.raises(RuntimeError, match="no code is being waited for"):
        await server.submit_login_code("123456", confirm=True)
    assert not (tmp_path / "pending-code.txt").exists()
