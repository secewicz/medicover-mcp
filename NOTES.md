# Reverse-engineering notes — Medicover OnLine24 private API

All findings below come from **direct inspection of `capture/flows.mitm`** (one real login +
browsing session, captured via mitmproxy). `medihunter` was used only to confirm the broad
paradigm (IdentityServer OAuth2/OIDC + opaque-ID slot search); every concrete endpoint, the
2FA step, and the subaccount model below were verified against live traffic, because
medihunter has diverged on all of them.

> The capture contains real credentials, tokens and medical data. It is gitignored and was
> **never** copied into source, tests, or these notes. Tokens/IDs shown here are either
> structural (lengths/shapes) or already-expired sample values for documentation only.

## Hosts

| Host | Role |
|------|------|
| `online24.medicover.pl` | SPA (static assets, `signin-oidc` redirect target). Used only as `Origin`. |
| `login-online24.medicover.pl` | IdentityServer (OIDC): authorize, login, MFA, token, profiles, permissions. |
| `api-gateway-online24.medicover.pl` | Business API (appointments, slots, booking, …). |

## OIDC discovery

`GET https://login-online24.medicover.pl/.well-known/openid-configuration`

```
issuer                 https://login-online24.medicover.pl
authorization_endpoint .../connect/authorize
token_endpoint         .../connect/token
revocation_endpoint    .../connect/revocation
scopes_supported       openid, profile, rdol_api, offline_access
code_challenge_methods  plain, S256
grant_types            authorization_code, refresh_token, client_credentials,
                       urn:ietf:params:oauth:grant-type:token-exchange, password-reset, ...
```

Public client, **no client secret**. PKCE is used.

- `client_id = web`
- `redirect_uri = https://online24.medicover.pl/signin-oidc`
- `scope = openid offline_access profile`
- `response_type = code`, `response_mode = query`, `code_challenge_method = S256`

## Auth flow (full chain)

The whole interactive flow runs against `login-online24.medicover.pl` and relies on a cookie
jar (`antiforgery`, `orch_state`, `MfaInfo`, `idsrv`, `cookiesession1`). Steps:

1. **`GET /connect/authorize`** with `client_id=web&redirect_uri=…/signin-oidc&response_type=code&scope=openid offline_access profile&state=<rand>&code_challenge=<S256(verifier)>&code_challenge_method=S256&response_mode=query&ui_locales=en&app_version=…&device_id=<uuid>&device_name=Chrome&ts=<ms>`
   → `302` to `/Account/Login?ReturnUrl=<urlencoded /connect/authorize/callback?…>`.
2. **`GET /Account/Login?ReturnUrl=…`** → HTML. Sets `antiforgery` cookie; page embeds a
   hidden `__RequestVerificationToken`. Must scrape that token out of the HTML.
3. **`POST /Account/Login?ReturnUrl=…`** (form-urlencoded):
   `Input.ReturnUrl, Input.LoginType=FullLogin, Input.Username=<MRN>, Input.Password=<pwd>,
   Input.Button=login, __RequestVerificationToken=<from step 2>,
   Input.IsSimpleAccessRegulationAccepted=false`
   → `302` to `/Account/Mfa?ReturnUrl=…` (sets `orch_state`). *(If the device is already
   trusted, this 302 goes straight to `/connect/authorize/callback` and MFA is skipped — see
   "Trusted device".)*
4. **`GET /Account/Mfa?ReturnUrl=…`** → triggers the SMS send and sets the `MfaInfo` cookie
   `{"MfaCodeId":"<uuid>","AuthenticatorId":…}`. Page again embeds `__RequestVerificationToken`.
5. *(operator reads the SMS code)*
6. **`POST /Account/Mfa?ReturnUrl=…`** (form-urlencoded):
   `Input.MfaCodeId=<from MfaInfo>, Input.ReturnUrl, Input.DeviceName=Chrome,
   Input.MfaCode=<6 digits>, Input.IsTrustedDevice=true, Input.Channel=SMS,
   Input.Operation=SIGN_IN, Input.Button=confirm, __RequestVerificationToken=<from step 4>`
   → `302` to `/connect/authorize/callback?…` (sets `idsrv` session cookie).
7. **`GET /connect/authorize/callback?…`** (follow with the cookie jar) → `302` to
   `https://online24.medicover.pl/signin-oidc?code=<AUTH_CODE>&state=<state>&session_state=…`.
   Stop here and read `code` out of the `Location` (the browser SPA does the token call; we
   do it ourselves).
8. **`POST /connect/token`** (form-urlencoded):
   `grant_type=authorization_code&redirect_uri=…/signin-oidc&code=<AUTH_CODE>&code_verifier=<verifier>&client_id=web`
   → JSON `{ id_token, access_token, refresh_token, expires_in:180, token_type:Bearer, scope }`.

**Persist `refresh_token`** (+ the `device_id` used, for trusted-device reuse). That is the
only long-lived secret the unattended runtime needs.

### Token refresh (unattended runtime)

```
POST /connect/token
grant_type=refresh_token&refresh_token=<rt>&scope=openid offline_access profile&client_id=web
→ { access_token, refresh_token (ROTATED), expires_in:180, ... }
```

The refresh token **rotates on every use** — the new one must be persisted each time or the
chain breaks.

### Subaccounts / dependents — OAuth token-exchange

This is how the portal switches "on behalf of" a dependent. After obtaining the account
holder's access token, exchange it for a patient-scoped token:

```
POST /connect/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&refresh_token=<holder rt>
&scope=offline_access
&target_sub=<patient MRN>
&subject_token=<holder access_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&client_id=web
→ { access_token (sub=<patient MRN>, role=SwitchedToKid, act.sub=<holder>), refresh_token, expires_in:180 }
```

The resulting access token's `sub` **is** the patient. **All business endpoints carry the
patient context purely in the bearer token** — there is no "on behalf of" query parameter or
body field. So: holder calls use the holder token; dependent calls use a token-exchanged
token for that `target_sub`.

### JWT contents

`access_token` (`typ: at+jwt`, RS256) payload, holder:
```
iss login-online24.medicover.pl   sub 2220055 (= MRN)   client_id web
scope [openid, profile, offline_access]   amr [pwd, mfa]   role FullAccess
iat … exp = iat + 180
```
Token-exchanged (dependent): `scope [offline_access]`, `role SwitchedToKid`,
`act.sub <holder MRN>`, `sub <dependent MRN>`.

### Trusted device

The MFA POST sends `Input.IsTrustedDevice=true` with a stable `device_id`. In the same
capture a **second** fresh `/connect/authorize`→`/Account/Login` login then skipped MFA
entirely (login POST 302'd straight to `/connect/authorize/callback`). So the IdP remembers a
trusted device. We do not rely on this for the runtime (the refresh token covers that); it is
only a convenience for re-bootstrap.

## Token lifetime & the SMS-fallback decision

- **Access token: 180 s** (measured: `exp − iat = 180`; `expires_in:180`). Short — must be
  refreshed essentially per run.
- **Refresh token: rotating**, scope `offline_access`. Its absolute/sliding lifetime **cannot
  be measured from a single ~minutes-long capture** (Phase 4 needs re-runs over hours/days,
  which this exercise's one captured session does not contain).

**Decision: ship the bootstrap-once model; do NOT expose in-MCP `request_sms_code` /
`submit_sms_code` tools.** Rationale:
- The scope is explicitly `offline_access` and the token rotates, the standard IdentityServer
  pattern for long-lived unattended refresh; a daily routine refreshing once per day keeps a
  sliding window alive indefinitely.
- The prompt says expose the SMS pair *only if the measured lifetime makes it necessary*.
  Nothing measured makes it necessary, and the surface should stay minimal for medical data.
- If real-world operation shows the refresh token dying within days, the fallback is a small
  addition: the bootstrap login logic in `auth.py` (`begin_login` / `submit_password` /
  `request_mfa` / `submit_mfa`) is already factored so the two tools could wrap it. Until
  then, expiry surfaces as a clear *"session expired — run `medicover-auth login`"* error.

## Business endpoints (`api-gateway-online24.medicover.pl`)

Request headers for every call: `Authorization: Bearer <access_token>`,
`Accept: application/json`, `Origin: https://online24.medicover.pl`, `Accept-Language: en`
(+`Content-Type: application/json` for POST). **No cookies**, no custom headers.

### List patients — `GET login-online24.medicover.pl/api/v4/available-profiles/me`
(Note: on the **login** host, not the gateway.) Holder token returns every accessible
profile; a switched token returns only that profile, so always call it with the holder token.
```json
[{"mrn":2220055,"name":"Anne-Mattijs","surname":"Kersten","isChild":false,"accessLevel":"Owner","sourceSystem":"MCOV","isMain":true},
 {"mrn":2098443,"name":"Lena","surname":"Kersten","isChild":true,"accessLevel":"Linked","sourceSystem":"MCOV","isMain":false},
 {"mrn":3914784,"name":"Livia","surname":"Kersten","isChild":true,"accessLevel":"Linked","sourceSystem":"MCOV","isMain":false}]
```
`mrn` is the patient id **and** the `target_sub` for token-exchange. `isMain/accessLevel=Owner`
marks the account holder.

### List appointments — `GET /appointments/api/v2/person-appointments/appointments`
Query: `AppointmentState = Planned | Past | All`, `Page`, `PageSize` (SPA uses `2147483647`),
optional `specialtyId`. Response: `{page,pageSize,count,items:[…]}`. Item shape:
```json
{"id":"<base64 EncodedAppointmentId blob>",
 "clinic":{"id":"174","name":"Centrum Medicover Atrium"},
 "doctor":{"id":"221808","name":"Opatczyk Paweł"},
 "region":{"id":"204","name":"Warszawa"},
 "specialty":{"id":"9","name":"Internal Medicine Doctor"},
 "visitType":"Center","date":"2026-06-15T08:00:00","dateOffset":"2026-06-15T08:00:00+02:00",
 "state":"Planned",
 "attributes":{"canReschedule":true,"canCancel":true,"isCheckInAllowed":true,…}}
```
The opaque `id` is the `oldAppointmentString` for reschedule. `attributes.canReschedule`
gates rescheduling.

### Reference / lookup — `GET /appointments/api/v2/search-appointments/filters`
Query: `RegionIds` (repeatable), `SlotSearchType=Standard`, `SpecialtyIds` (repeatable),
optional `DoctorIds`, `DoctorLanguageIds`. Returns the valid `specialties / clinics / doctors
/ doctorLanguages` (each `{id,value}`) for the current selection — used to resolve names→IDs
and to enumerate clinics/doctors. Region `204 = Warszawa`.

There is also `GET /appointments/api/v2/person-appointments/appointments/filters?AppointmentState=All`
returning `{specialties,doctors,clinics,regions}` ( `{id,name}` ) scoped to the patient's own
visits — handy for `list_appointments` filtering.

### Search slots — `GET /appointments/api/v2/search-appointments/slots`
Query: `RegionIds` (repeatable, required), `SpecialtyIds` (repeatable, required),
`SlotSearchType=Standard`, `StartTime=YYYY-MM-DD` (search-from date), `Page`, `PageSize`,
optional `DoctorIds`, `ClinicIds`, `DoctorLanguageIds`, `VisitType`,
`isOverbookingSearchDisabled=false`.

**Corroborated against `rafsaf/medichaser`** (independent, current implementation):
- `SlotSearchType` is **not a fixed constant** — medichaser defaults it to integer `0` and
  exposes other categories, notably `DiagnosticProcedure`. Our capture only ever showed
  `"Standard"`; both the string `"Standard"` and `0` appear to denote the default category.
  We surface it as a parameter (`slot_search_type`, default `"Standard"`) so diagnostic
  procedures can be searched.
- `VisitType`: medichaser sends it (pinned to `"Center"`), **but the official SPA does not** —
  the second capture's slot searches (incl. the one that led to a real booking) carry **no
  `VisitType` param at all**, even for an in-person booking. In-person vs. tele is expressed by
  **specialty choice** (e.g. `158`/`7340` are in-center pediatrics; `19048` is tele) and read
  back from each slot's `visitType`. We therefore **do not send `VisitType`** (matching the
  SPA); callers filter returned slots by `visit_type` instead. (Verified: `capture/flows.mitm`
  session 2, 2026-06-17.)
- There is **no end-date query param**; medichaser filters by `appointmentDate` client-side
  after the call. We do the same for the optional `end_date`.
- Note: medichaser hits the **unversioned** path (`/appointments/api/search-appointments/…`,
  no `/v2/`). We use `/v2/` (what the captured SPA used). Both appear to coexist; the
  unversioned path is a known-good fallback if a `/v2/` route ever 404s.

medichaser does **not** book, reschedule, or handle subaccounts/dependents — so it offers no
corroboration for our `book_appointment` / `reschedule_appointment` / token-exchange paths;
those remain validated only against this single capture.
Response:
```json
{"additionalFilters":{"doctors":[…],"clinics":[…]},
 "nextSearchDate":"2026-06-21T08:00:00","page":1,"pageSize":2,"count":4,
 "items":[{"appointmentDate":"2026-06-16T07:00:00","appointmentDateOffset":"…+02:00",
           "clinic":{"id":"19642","name":"e-wizyta","isPozClinic":false},
           "doctor":{"id":"487780","name":"Internista 4 Telecentrum"},
           "specialty":{"id":"19046","name":"…"},"visitType":"PhoneAdvice",
           "bookingString":"<opaque ~330-char token>", "isOverbooking":false, …}]}
```
`bookingString` is the slot handle consumed by booking/reschedule. `nextSearchDate` lets you
page forward in time when `items` is short. There is **no separate slot id** — the
`bookingString` *is* the slot identity, and it is single-use/short-lived (read-before-write:
re-search right before booking).

### Book — `POST /appointments/api/v2/search-appointments/book-appointment`
```json
{"reportingId":"<optional reporting/correlation token>",
 "bookingString":"<from the chosen slot>",
 "metadata":{"appointmentSource":"Direct"}}
→ 200 {"appointmentId": 600299524}
```
`reportingId`: **the SPA always sends a non-empty value, sourced from the triage flow.**
Confirmed in `capture/flows.mitm` session 2 (2026-06-17, a real booking): the 86-char
`reportingId` in the `book-appointment` body is returned verbatim by
`GET /service-selector-configurator-os/api/keywords/{keywordId}/triage/flat` (the
symptom-checker / service-selector), which runs **before** the slot search and is **out of
scope** for this server. No booking with an empty/absent `reportingId` has ever been observed,
so whether `""` is *accepted* remains untested — but it is now certain the official client
never books without one. Booking is keyed by `bookingString`; the in-scope "search → book" path
has no legitimate source for a `reportingId`, so the server **defaults it to an empty string**
and always sends `metadata.appointmentSource:"Direct"`. **Risk (now the single biggest live
unknown):** if the API requires a valid `reportingId`, `book_appointment` fails with a clear API
error. Closing this would mean implementing the triage call to mint a `reportingId` per slot.

### Reschedule — `POST /appointments/api/v2/person-appointments/reschedule-appointment`
```json
{"oldAppointmentString":"<existing appointment .id from list_appointments>",
 "bookingString":"<new slot's bookingString>"}
→ 200 {"status":"Success","message":null,"errorDetails":null}
```
Atomic move (no separate cancel). For the "earlier slot" use case, compare the new slot's
`appointmentDate` against the existing appointment's `date` and only proceed if strictly
earlier.

### Cancel — `DELETE /appointments/api/v2/person-appointments/appointments/<encoded id>`
Exists, but **deliberately not exposed** (no cancel-without-rebook in scope).

## IDs / enums seen (examples, not exhaustive)

- Region: `204 = Warszawa`.
- Specialties: `9 Internal Medicine Doctor`, `1586 Family Doctor - adults`,
  `158 Pediatrician - sick children`, `7340 Pediatrician on duty`, `100 Otolaryngologist
  Paediatrician`, `88 Allergologist Paediatrician`, `19046 Internal medicine – phone advice`.
- `AppointmentState`: `Planned | Past | All`.
- `visitType` / consultation type: `Center | Phone | PhoneAdvice | All`.
- `SlotSearchType`: `Standard` (default; `0` in medichaser), `DiagnosticProcedure`, … —
  configurable, not exhaustive.
- `DoctorLanguageIds` (from medichaser): `4 = Polski`, `6 = Angielski`, `60 = Ukraiński`.
  Not exhaustive — resolve others via the `filters` endpoint.
- Patients (this account): holder `2220055`; dependents `2098443`, `3914784`.

All specialty/clinic/doctor/region IDs are opaque integers — resolve them via the `filters`
endpoints; never hardcode in the server.
</content>
</invoke>
