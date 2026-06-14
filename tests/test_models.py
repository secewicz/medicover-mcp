"""Model parsing from real captured JSON shapes + input normalisation."""

from __future__ import annotations

from datetime import date

import pytest

from medicover_mcp import models


def test_patient_from_profile_marks_holder_and_child():
    holder = models.Patient.from_profile(
        {"mrn": 2220055, "name": "Anne-Mattijs", "surname": "Kersten",
         "isChild": False, "accessLevel": "Owner", "isMain": True}
    )
    assert holder.patient_id == 2220055
    assert holder.is_account_holder is True
    assert holder.is_child is False

    child = models.Patient.from_profile(
        {"mrn": 3914784, "name": "Livia", "surname": "Kersten",
         "isChild": True, "accessLevel": "Linked", "isMain": False}
    )
    assert child.is_account_holder is False
    assert child.is_child is True


def test_appointment_from_item_extracts_handle_and_flags():
    item = {
        "id": "ENCODED-ID", "date": "2026-06-15T08:00:00", "dateOffset": "2026-06-15T08:00:00+02:00",
        "state": "Planned",
        "clinic": {"id": "174", "name": "Centrum Medicover Atrium"},
        "doctor": {"id": "221808", "name": "Opatczyk Paweł"},
        "specialty": {"id": "9", "name": "Internal Medicine Doctor"},
        "region": {"id": "204", "name": "Warszawa"},
        "visitType": "Center",
        "attributes": {"canReschedule": True, "canCancel": True},
    }
    a = models.Appointment.from_item(item)
    assert a.appointment_id == "ENCODED-ID"
    assert a.can_reschedule is True
    assert a.doctor.name == "Opatczyk Paweł"
    assert a.specialty.id == "9"


def test_slot_from_item_uses_booking_string():
    item = {
        "appointmentDate": "2026-06-16T07:00:00", "appointmentDateOffset": "2026-06-16T07:00:00+02:00",
        "clinic": {"id": "19642", "name": "e-wizyta", "isPozClinic": False},
        "doctor": {"id": "487780", "name": "Internista 4 Telecentrum"},
        "specialty": {"id": "19046", "name": "phone advice"},
        "visitType": "PhoneAdvice", "bookingString": "OPAQUE-BSTR", "isOverbooking": False,
    }
    s = models.Slot.from_item(item)
    assert s.booking_string == "OPAQUE-BSTR"
    assert s.date == "2026-06-16T07:00:00"
    assert s.clinic.name == "e-wizyta"


def test_named_refs_handles_value_and_name_keys():
    # filters endpoint uses {"id","value"}; appointment filters use {"id","name"}.
    by_value = models.to_named_refs([{"id": "204", "value": "Warszawa"}], name_key="value")
    assert by_value[0].name == "Warszawa"
    by_name = models.to_named_refs([{"id": "9", "name": "Internal Medicine"}])
    assert by_name[0].name == "Internal Medicine"


def test_normalize_date_accepts_date_and_string():
    assert models.normalize_date(date(2026, 6, 15)) == "2026-06-15"
    assert models.normalize_date("2026-06-15T08:00:00") == "2026-06-15"


def test_normalize_date_rejects_garbage():
    with pytest.raises(ValueError):
        models.normalize_date("not-a-date")
