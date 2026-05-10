"""No-telemetry guarantee — proves the codebase contains no calls
to telemetry domains, and the HTTP client's pre-flight hook refuses
them at runtime.
"""

from __future__ import annotations

import pathlib
import re

import httpx
import pytest

from wimsalabim.core.exceptions import NetworkError
from wimsalabim.core.http_client import _block_telemetry, make_client
from wimsalabim.core.privacy import TELEMETRY_BLACKLIST, is_telemetry_host

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src" / "wimsalabim"


def test_blacklist_not_empty() -> None:
    assert len(TELEMETRY_BLACKLIST) >= 10


@pytest.mark.parametrize("host", sorted(TELEMETRY_BLACKLIST))
def test_blacklist_match(host: str) -> None:
    assert is_telemetry_host(host)
    assert is_telemetry_host(f"sub.{host}")


def test_neutral_host_is_not_telemetry() -> None:
    assert not is_telemetry_host("example.com")


@pytest.mark.asyncio
async def test_block_telemetry_hook_refuses_blacklisted_host() -> None:
    req = httpx.Request("GET", "https://google-analytics.com/track")
    with pytest.raises(NetworkError):
        await _block_telemetry(req)


def test_no_telemetry_imports_in_source() -> None:
    """If we ever ``import google.analytics``, this test should fail."""
    forbidden = re.compile(
        r"\b(google[_.]analytics|sentry_sdk|segment|mixpanel|amplitude|"
        r"datadog|new[_.]?relic|hotjar|fullstory|bugsnag|rollbar)\b",
        re.IGNORECASE,
    )
    offenders: list[str] = []
    for py in _SRC.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        if (
            forbidden.search(text)
            and "TELEMETRY_BLACKLIST" not in text
            and "is_telemetry_host" not in text
            and "telemetry" not in py.name
        ):
            offenders.append(str(py))
    assert not offenders, f"telemetry references found: {offenders}"


def test_make_client_has_telemetry_hook() -> None:
    client = make_client()
    hooks = client.event_hooks.get("request", [])
    assert any(h is _block_telemetry for h in hooks)
