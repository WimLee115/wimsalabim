"""HTTP client factory — privacy hooks active by default."""

from __future__ import annotations

import httpx
import pytest

from wimsalabim.core.exceptions import NetworkError
from wimsalabim.core.http_client import (
    DEFAULT_TIMEOUT,
    USER_AGENT,
    _block_telemetry,
    make_client,
)


def test_make_client_returns_async_client() -> None:
    client = make_client()
    assert isinstance(client, httpx.AsyncClient)


def test_user_agent_pvnl_branded() -> None:
    assert "wimsalabim" in USER_AGENT
    assert "PVNL" in USER_AGENT


def test_default_timeout_present() -> None:
    assert DEFAULT_TIMEOUT.connect is not None
    assert DEFAULT_TIMEOUT.read is not None


def test_make_client_no_redirect_by_default() -> None:
    client = make_client()
    assert client.follow_redirects is False


@pytest.mark.asyncio
async def test_block_telemetry_passes_clean_request() -> None:
    req = httpx.Request("GET", "https://example.com/")
    # Should NOT raise.
    await _block_telemetry(req)


@pytest.mark.asyncio
async def test_block_telemetry_raises_on_blacklist() -> None:
    req = httpx.Request("GET", "https://eu.mixpanel.com/track")
    with pytest.raises(NetworkError, match="telemetry"):
        await _block_telemetry(req)
