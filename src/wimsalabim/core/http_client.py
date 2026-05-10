"""HTTP client factory with privacy & legal guards baked in.

Every analyzer that talks HTTP/HTTPS receives an ``httpx.AsyncClient``
constructed here. The factory enforces:

* Conservative ``User-Agent`` (no fingerprintable extras).
* Telemetry-blacklist event-hook (block before the socket opens).
* Optional Tor SOCKS5 transport.
* Strict timeouts.
* No automatic redirects across hosts (caller decides).
"""

from __future__ import annotations

from typing import Final

import httpx

from wimsalabim.core.exceptions import NetworkError
from wimsalabim.core.privacy import is_telemetry_host

USER_AGENT: Final = "wimsalabim/0.2 (+https://github.com/WimLee115/wimsalabim) PVNL"
DEFAULT_TIMEOUT: Final = httpx.Timeout(10.0, connect=5.0, read=10.0)


async def _block_telemetry(request: httpx.Request) -> None:
    if request.url.host and is_telemetry_host(request.url.host):
        raise NetworkError(
            kind="policy",
            target=request.url.host,
            message="blocked: target is on the telemetry blacklist",
        )


def make_client(
    *,
    timeout: httpx.Timeout | float | None = None,
    via_tor: bool = False,
    follow_redirects: bool = False,
    http2: bool = True,
) -> httpx.AsyncClient:
    """Create an ``httpx.AsyncClient`` with our privacy/legal guards."""
    transport: httpx.AsyncBaseTransport | None = None
    if via_tor:
        # Tor's default SOCKS5 listener is 127.0.0.1:9050.
        transport = httpx.AsyncHTTPTransport(
            proxy=httpx.Proxy("socks5://127.0.0.1:9050"),
            retries=0,
        )

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": "en;q=0.5",
        "Connection": "close",
    }

    return httpx.AsyncClient(
        timeout=timeout if timeout is not None else DEFAULT_TIMEOUT,
        follow_redirects=follow_redirects,
        http2=http2,
        headers=headers,
        transport=transport,
        event_hooks={"request": [_block_telemetry]},
    )


__all__ = ["DEFAULT_TIMEOUT", "USER_AGENT", "make_client"]
