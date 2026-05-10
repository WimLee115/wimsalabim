"""Privacy primitives: WHOIS redaction + telemetry guard."""

from __future__ import annotations

from wimsalabim.core.privacy import (
    TELEMETRY_BLACKLIST,
    is_telemetry_host,
    redact_whois,
)


def test_whois_redacts_pii_by_default() -> None:
    record = {
        "registrant_name": "Jan Janssen",
        "registrant_email": "jan@example.com",
        "registrar": "TransIP",
        "creation_date": "2020-01-01",
    }
    cleaned = redact_whois(record)
    assert cleaned["registrant_name"] == "[REDACTED:AVG-art-5]"
    assert cleaned["registrant_email"] == "[REDACTED:AVG-art-5]"
    assert cleaned["registrar"] == "TransIP"


def test_whois_show_pii_returns_original() -> None:
    record = {"registrant_name": "Jan Janssen"}
    assert redact_whois(record, show_pii=True) == record


def test_whois_email_in_freeform_field_redacted() -> None:
    record = {"comment": "contact me at jan@example.com please"}
    cleaned = redact_whois(record)
    assert "jan@example.com" not in str(cleaned["comment"])
    assert "[REDACTED:email]" in str(cleaned["comment"])


def test_telemetry_host_match_subdomain() -> None:
    assert is_telemetry_host("eu.mixpanel.com")
    assert is_telemetry_host("mixpanel.com")
    assert not is_telemetry_host("notpanel.com")


def test_blacklist_lowercase_only() -> None:
    for host in TELEMETRY_BLACKLIST:
        assert host == host.lower()
