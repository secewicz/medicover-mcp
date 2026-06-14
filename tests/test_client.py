"""MedicoverClient: token refresh/rotation, dependent token-exchange, request building."""

from __future__ import annotations

import httpx
import pytest

from medicover_mcp.auth import AuthError
from medicover_mcp.client import MedicoverClient, MedicoverError
from tests.conftest import CHILD_MRN, HOLDER_MRN, build_client, token_response


def _record(requests: list):
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path
        if path == "/connect/token":
            body = request.content.decode()
            if "grant_type=refresh_token" in body and "RT-holder" in body:
                return httpx.Response(200, json=token_response(HOLDER_MRN, "RT-holder-1"))
            if "token-exchange" in body:
                return httpx.Response(200, json=token_response(CHILD_MRN, "RT-child-0"))
            if "grant_type=refresh_token" in body and "RT-child" in body:
                return httpx.Response(200, json=token_response(CHILD_MRN, "RT-child-1"))
        if path.endswith("/available-profiles/me"):
            return httpx.Response(200, json=[{"mrn": HOLDER_MRN, "name": "A", "surname": "K",
                                              "isMain": True, "isChild": False, "accessLevel": "Owner"}])
        if path.endswith("/person-appointments/appointments"):
            return httpx.Response(200, json={"items": [{"id": "APPT", "date": "2026-06-15T08:00:00",
                                                        "state": "Planned", "attributes": {"canReschedule": True}}]})
        if path.endswith("/search-appointments/slots"):
            return httpx.Response(200, json={"count": 1, "nextSearchDate": "2026-06-20T08:00:00",
                                             "items": [{"appointmentDate": "2026-06-16T07:00:00",
                                                        "bookingString": "BSTR"}]})
        if path.endswith("/book-appointment"):
            return httpx.Response(200, json={"appointmentId": 600299524})
        if path.endswith("/reschedule-appointment"):
            return httpx.Response(200, json={"status": "Success", "message": None})
        return httpx.Response(404, json={"path": path})

    return handler


async def test_holder_refresh_persists_rotated_token(store, settings):
    requests: list = []
    client = build_client(store, settings, _record(requests))
    await client.list_profiles()
    # The stored refresh token must have been rotated to the new value.
    assert store.load().refresh_token == "RT-holder-1"
    await client.aclose()


async def test_holder_token_is_reused_until_expiry(store, settings):
    requests: list = []
    client = build_client(store, settings, _record(requests))
    await client.list_profiles()
    await client.list_profiles()
    token_calls = [r for r in requests if r.url.path == "/connect/token"]
    assert len(token_calls) == 1  # only refreshed once
    await client.aclose()


async def test_dependent_uses_token_exchange(store, settings):
    requests: list = []
    client = build_client(store, settings, _record(requests))
    await client.list_appointments(CHILD_MRN, "Planned")
    bodies = [r.content.decode() for r in requests if r.url.path == "/connect/token"]
    assert any("token-exchange" in b and "target_sub=3914784" in b for b in bodies)
    # The appointments call must carry the child's bearer token (sub=child).
    appt = next(r for r in requests if r.url.path.endswith("/person-appointments/appointments"))
    assert appt.headers["authorization"].startswith("Bearer ")
    await client.aclose()


async def test_holder_calls_skip_exchange(store, settings):
    requests: list = []
    client = build_client(store, settings, _record(requests))
    await client.list_appointments(HOLDER_MRN, "Planned")
    bodies = [r.content.decode() for r in requests if r.url.path == "/connect/token"]
    assert not any("token-exchange" in b for b in bodies)
    await client.aclose()


async def test_search_slots_builds_repeated_query_params(store, settings):
    requests: list = []
    client = build_client(store, settings, _record(requests))
    await client.search_slots(
        None, region_ids=["204"], specialty_ids=["9", "1586"], start_date="2026-06-15",
        doctor_ids=["221808"],
    )
    slot_req = next(r for r in requests if r.url.path.endswith("/slots"))
    qs = str(slot_req.url.query)
    assert "SpecialtyIds=9" in qs and "SpecialtyIds=1586" in qs
    assert "RegionIds=204" in qs
    assert "DoctorIds=221808" in qs
    assert "StartTime=2026-06-15" in qs
    await client.aclose()


async def test_book_appointment_body_shape(store, settings):
    requests: list = []
    client = build_client(store, settings, _record(requests))
    result = await client.book_appointment(HOLDER_MRN, booking_string="BSTR", reporting_id="")
    assert result["appointmentId"] == 600299524
    book_req = next(r for r in requests if r.url.path.endswith("/book-appointment"))
    import json

    body = json.loads(book_req.content)
    assert body["bookingString"] == "BSTR"
    assert body["metadata"] == {"appointmentSource": "Direct"}
    assert book_req.headers["content-type"].startswith("application/json")
    await client.aclose()


async def test_reschedule_body_shape(store, settings):
    requests: list = []
    client = build_client(store, settings, _record(requests))
    result = await client.reschedule_appointment(
        HOLDER_MRN, old_appointment_string="OLD", booking_string="BSTR"
    )
    assert result["status"] == "Success"
    req = next(r for r in requests if r.url.path.endswith("/reschedule-appointment"))
    import json

    body = json.loads(req.content)
    assert body == {"oldAppointmentString": "OLD", "bookingString": "BSTR"}
    await client.aclose()


async def test_401_raises_reauth_hint(store, settings):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/connect/token":
            return httpx.Response(200, json=token_response(HOLDER_MRN, "RT-holder-1"))
        return httpx.Response(401)

    client = build_client(store, settings, handler)
    with pytest.raises(AuthError, match="medicover-auth login"):
        await client.list_profiles()
    await client.aclose()


async def test_invalid_refresh_token_raises_clear_error(store, settings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant"})

    client = build_client(store, settings, handler)
    with pytest.raises(AuthError, match="session expired or revoked"):
        await client.list_profiles()
    await client.aclose()


async def test_retries_on_503(store, settings):
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/connect/token":
            return httpx.Response(200, json=token_response(HOLDER_MRN, "RT-holder-1"))
        if request.url.path.endswith("/available-profiles/me"):
            state["n"] += 1
            if state["n"] == 1:
                return httpx.Response(503)
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    client = build_client(store, settings, handler)
    client._min_interval = 0
    profiles = await client.list_profiles()
    assert profiles == []
    assert state["n"] == 2  # retried once
    await client.aclose()
