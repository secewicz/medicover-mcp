"""Async Medicover API client: token lifecycle + business endpoints.

Token strategy (see NOTES.md):
- The **account holder** access token is obtained by refreshing the stored refresh token
  (`grant_type=refresh_token`); the rotated refresh token is persisted on every refresh.
- A **dependent** access token is minted once via OAuth token-exchange (`target_sub=<mrn>`)
  using a fresh holder access token, then kept alive on its **own** rotating refresh token —
  so we touch the holder's refresh token as little as possible.

All patient context rides in the bearer token; no endpoint takes an "on behalf of" param.
Request/response bodies (which carry personal/medical data) are never logged.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from . import auth, config
from .auth import AuthError, TokenSet
from .store import CredentialStore, StoredCredentials

log = logging.getLogger("medicover_mcp")


class MedicoverError(RuntimeError):
    """A business API call failed."""


class MedicoverClient:
    def __init__(self, store: CredentialStore, settings: config.Settings):
        self._store = store
        self._settings = settings
        self._http = httpx.AsyncClient(
            timeout=settings.request_timeout,
            headers={"User-Agent": config.USER_AGENT},
        )
        self._creds: StoredCredentials | None = None
        self._holder_token: TokenSet | None = None
        self._holder_mrn: int | None = None
        # mrn -> dependent TokenSet (each with its own rotating refresh token)
        self._patient_tokens: dict[int, TokenSet] = {}
        self._lock = asyncio.Lock()
        self._last_request_ts = 0.0
        self._min_interval = 0.25  # be a polite client

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- token management ----------------------------------------------------------------

    def _load_creds(self) -> StoredCredentials:
        if self._creds is None:
            self._creds = self._store.load()
        return self._creds

    async def _holder_access_token(self) -> str:
        """Return a valid holder access token, refreshing (and persisting rotation) as needed."""
        if self._holder_token is not None and not self._holder_token.is_expired():
            return self._holder_token.access_token
        creds = self._load_creds()
        resp = await self._http.post(
            config.TOKEN_ENDPOINT,
            data=auth.build_refresh_request(creds.refresh_token),
            headers={"Accept": "application/json"},
        )
        tokens = auth.parse_token_response(resp)
        self._holder_token = tokens
        self._holder_mrn = _sub_of(tokens.access_token)
        if tokens.refresh_token and tokens.refresh_token != creds.refresh_token:
            creds.refresh_token = tokens.refresh_token
            self._store.save(creds)  # persist the rotated token immediately
        return tokens.access_token

    async def _holder_mrn_value(self) -> int | None:
        if self._holder_mrn is None:
            await self._holder_access_token()
        return self._holder_mrn

    async def _access_token_for(self, patient_id: int | None) -> str:
        """Bearer token for the given patient (holder when None or when it *is* the holder)."""
        holder = await self._holder_access_token()
        if patient_id is None or patient_id == self._holder_mrn:
            return holder

        cached = self._patient_tokens.get(patient_id)
        if cached is not None and not cached.is_expired():
            return cached.access_token
        if cached is not None and cached.refresh_token:
            # Keep the dependent alive on its own refresh chain (avoids re-exchanging).
            resp = await self._http.post(
                config.TOKEN_ENDPOINT,
                data=auth.build_refresh_request(cached.refresh_token, scope="offline_access"),
                headers={"Accept": "application/json"},
            )
            try:
                tokens = auth.parse_token_response(resp)
                self._patient_tokens[patient_id] = tokens
                return tokens.access_token
            except AuthError:
                pass  # fall through to a fresh exchange

        creds = self._load_creds()
        resp = await self._http.post(
            config.TOKEN_ENDPOINT,
            data=auth.build_token_exchange_request(
                refresh_token=creds.refresh_token,
                subject_token=holder,
                target_sub=patient_id,
            ),
            headers={"Accept": "application/json"},
        )
        tokens = auth.parse_token_response(resp)
        if _sub_of(tokens.access_token) != patient_id:
            raise MedicoverError(
                f"token-exchange did not switch to patient {patient_id}; "
                "the account may not have access to this patient"
            )
        self._patient_tokens[patient_id] = tokens
        return tokens.access_token

    # -- HTTP plumbing -------------------------------------------------------------------

    async def _request(
        self, method: str, url: str, *, patient_id: int | None, **kwargs
    ) -> httpx.Response:
        async with self._lock:  # serialize token refresh + pace requests
            await self._pace()
            token = await self._access_token_for(patient_id)
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Accept-Language": "en",
                "Origin": config.SPA_ORIGIN,
                # Client hints — the gateway is behind the same Imperva WAF as login.
                "sec-ch-ua": config.SEC_CH_UA,
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": config.SEC_CH_UA_PLATFORM,
            }
            resp = await self._send_with_retry(method, url, headers, kwargs)
        log.debug("%s %s -> %s", method, _path(url), resp.status_code)
        if resp.status_code == 401:
            raise AuthError("API returned 401 — " + _reauth_hint())
        if resp.status_code >= 400:
            raise MedicoverError(f"{method} {_path(url)} failed: HTTP {resp.status_code}")
        return resp

    async def _send_with_retry(self, method, url, headers, kwargs) -> httpx.Response:
        backoff = 1.0
        for attempt in range(3):
            resp = await self._http.request(method, url, headers=headers, **kwargs)
            if resp.status_code in (429, 502, 503, 504) and attempt < 2:
                wait = float(resp.headers.get("Retry-After", backoff))
                await asyncio.sleep(min(wait, 10))
                backoff *= 2
                continue
            return resp
        return resp

    async def _pace(self) -> None:
        delta = time.monotonic() - self._last_request_ts
        if delta < self._min_interval:
            await asyncio.sleep(self._min_interval - delta)
        self._last_request_ts = time.monotonic()

    # -- business endpoints --------------------------------------------------------------

    async def list_profiles(self) -> list[dict]:
        """Accessible patients. Always called with the holder token."""
        resp = await self._request("GET", config.PROFILES_ENDPOINT, patient_id=None)
        return resp.json()

    async def list_appointments(
        self, patient_id: int | None, state: str, specialty_id: str | None = None
    ) -> list[dict]:
        params: dict[str, str | int] = {
            "AppointmentState": state,
            "Page": 1,
            "PageSize": 2147483647,
        }
        if specialty_id:
            params["specialtyId"] = specialty_id
        resp = await self._request(
            "GET",
            f"{config.API_HOST}/appointments/api/v2/person-appointments/appointments",
            patient_id=patient_id,
            params=params,
        )
        return resp.json().get("items", [])

    async def list_appointments_filters(self, patient_id: int | None) -> dict:
        """Specialties/doctors/clinics/regions drawn from the patient's own visit history."""
        resp = await self._request(
            "GET",
            f"{config.API_HOST}/appointments/api/v2/person-appointments/appointments/filters",
            patient_id=patient_id,
            params={"AppointmentState": "All"},
        )
        return resp.json()

    async def search_filters(
        self,
        patient_id: int | None,
        *,
        region_ids: list[str],
        specialty_ids: list[str],
        doctor_ids: list[str] | None = None,
        language_ids: list[str] | None = None,
        slot_search_type: str = "Standard",
    ) -> dict:
        params: list[tuple[str, str]] = [("SlotSearchType", slot_search_type)]
        params += [("RegionIds", r) for r in region_ids]
        params += [("SpecialtyIds", s) for s in specialty_ids]
        params += [("DoctorIds", d) for d in (doctor_ids or [])]
        params += [("DoctorLanguageIds", l) for l in (language_ids or [])]
        resp = await self._request(
            "GET",
            f"{config.API_HOST}/appointments/api/v2/search-appointments/filters",
            patient_id=patient_id,
            params=params,
        )
        return resp.json()

    async def search_slots(
        self,
        patient_id: int | None,
        *,
        region_ids: list[str],
        specialty_ids: list[str],
        start_date: str,
        doctor_ids: list[str] | None = None,
        clinic_ids: list[str] | None = None,
        language_ids: list[str] | None = None,
        slot_search_type: str = "Standard",
        page_size: int = 200,
    ) -> dict:
        params: list[tuple[str, str | int]] = [
            ("SlotSearchType", slot_search_type),
            ("StartTime", start_date),
            ("Page", 1),
            ("PageSize", page_size),
            ("isOverbookingSearchDisabled", "false"),
        ]
        params += [("RegionIds", r) for r in region_ids]
        params += [("SpecialtyIds", s) for s in specialty_ids]
        params += [("DoctorIds", d) for d in (doctor_ids or [])]
        params += [("ClinicIds", c) for c in (clinic_ids or [])]
        params += [("DoctorLanguageIds", l) for l in (language_ids or [])]
        resp = await self._request(
            "GET",
            f"{config.API_HOST}/appointments/api/v2/search-appointments/slots",
            patient_id=patient_id,
            params=params,
        )
        return resp.json()

    async def book_appointment(
        self, patient_id: int, *, booking_string: str, reporting_id: str = ""
    ) -> dict:
        body = {
            "reportingId": reporting_id,
            "bookingString": booking_string,
            "metadata": {"appointmentSource": "Direct"},
        }
        resp = await self._request(
            "POST",
            f"{config.API_HOST}/appointments/api/v2/search-appointments/book-appointment",
            patient_id=patient_id,
            json=body,
        )
        return resp.json()

    async def cancel_appointment(self, patient_id: int, *, encoded_appointment_id: str) -> dict:
        """Cancel an appointment by its encoded `id` (from list_appointments).

        Intentionally NOT exposed as an MCP tool (no cancel-without-rebook in the agent
        surface); it exists so test/probe code can guarantee cleanup after a booking.
        """
        import urllib.parse

        quoted = urllib.parse.quote(encoded_appointment_id, safe="")
        resp = await self._request(
            "DELETE",
            f"{config.API_HOST}/appointments/api/v2/person-appointments/appointments/{quoted}",
            patient_id=patient_id,
        )
        return resp.json()

    async def reschedule_appointment(
        self, patient_id: int, *, old_appointment_string: str, booking_string: str
    ) -> dict:
        body = {
            "oldAppointmentString": old_appointment_string,
            "bookingString": booking_string,
        }
        resp = await self._request(
            "POST",
            f"{config.API_HOST}/appointments/api/v2/person-appointments/reschedule-appointment",
            patient_id=patient_id,
            json=body,
        )
        return resp.json()


def _sub_of(access_token: str) -> int | None:
    import base64
    import json

    try:
        payload = access_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return int(json.loads(base64.urlsafe_b64decode(payload))["sub"])
    except Exception:
        return None


def _path(url: str) -> str:
    return httpx.URL(url).path


def _reauth_hint() -> str:
    return "session expired or revoked; run `medicover-auth login`"
