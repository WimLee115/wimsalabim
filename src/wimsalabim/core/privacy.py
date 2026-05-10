"""Privacy-by-design primitives.

Three guarantees:
    1. **No telemetry.** A test asserts no module references a telemetry domain.
    2. **WHOIS PII redacted by default.** Personal names in WHOIS payloads
       are masked unless ``--whois-show-pii`` is explicitly supplied.
    3. **Optional Tor transport.** ``--via-tor`` routes httpx and DNS via
       a local SOCKS5 proxy + Tor's DNS resolver.
"""

from __future__ import annotations

import re
from typing import Final

# Domains we will never speak to under any flag — guarded by tests.
TELEMETRY_BLACKLIST: Final[frozenset[str]] = frozenset(
    {
        "google-analytics.com",
        "googletagmanager.com",
        "doubleclick.net",
        "facebook.com/tr",
        "connect.facebook.net",
        "hotjar.com",
        "segment.io",
        "segment.com",
        "mixpanel.com",
        "amplitude.com",
        "fullstory.com",
        "sentry.io",
        "bugsnag.com",
        "rollbar.com",
        "newrelic.com",
        "datadoghq.com",
    }
)

# Field names in WHOIS that typically contain PII. Redacted by default.
_WHOIS_PII_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "registrant_name",
        "registrant",
        "name",
        "admin_name",
        "tech_name",
        "billing_name",
        "registrant_email",
        "admin_email",
        "tech_email",
        "billing_email",
        "registrant_phone",
        "admin_phone",
        "tech_phone",
        "registrant_street",
        "registrant_address",
        "address",
        "registrant_postal_code",
        "registrant_postalcode",
    }
)

_EMAIL_RE: Final = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+", re.UNICODE)


def redact_whois(record: dict[str, object], *, show_pii: bool = False) -> dict[str, object]:
    """Return a shallow copy with PII fields masked unless ``show_pii``."""
    if show_pii:
        return dict(record)

    cleaned: dict[str, object] = {}
    for key, value in record.items():
        if key.lower() in _WHOIS_PII_FIELDS:
            cleaned[key] = "[REDACTED:AVG-art-5]"
        elif isinstance(value, str):
            cleaned[key] = _EMAIL_RE.sub("[REDACTED:email]", value)
        else:
            cleaned[key] = value
    return cleaned


def is_telemetry_host(host: str) -> bool:
    """True if ``host`` matches our telemetry blacklist."""
    h = host.lower().rstrip(".")
    return any(h == bad or h.endswith("." + bad) for bad in TELEMETRY_BLACKLIST)


__all__ = [
    "TELEMETRY_BLACKLIST",
    "is_telemetry_host",
    "redact_whois",
]
