"""Shared TLS test infrastructure.

We use ``trustme`` to mint a fresh CA + leaf-certificate per test run. The
asyncio server we start does the bare minimum: complete the handshake,
then close. That's enough for ``TLSAnalyzer.analyze`` because it only
inspects what the server presents during the handshake (peer cert,
protocol, cipher) — no application data is exchanged.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import trustme


def make_cert(
    *,
    common_name: str = "127.0.0.1",
    valid_for_days: int = 90,
) -> trustme.LeafCert:
    """Mint a CA + leaf valid for ``valid_for_days``.

    For *expiring soon* / *expired* scenarios we mint a leaf with a short
    or negative validity window. Returns the leaf together with its CA so
    the test can configure both server and client trust.
    """
    ca = make_cert._ca  # reuse one CA per test run for speed
    not_before = datetime.now(tz=timezone.utc) - timedelta(days=1)
    not_after = datetime.now(tz=timezone.utc) + timedelta(days=valid_for_days)
    return ca.issue_cert(
        common_name,
        not_before=not_before,
        not_after=not_after,
    )


# Lazy module-level CA — one per test session keeps the TLS-handshake fast.
make_cert._ca = trustme.CA()  # type: ignore[attr-defined]


def session_ca() -> trustme.CA:
    """Expose the single test CA so client trust can be configured."""
    return make_cert._ca  # type: ignore[attr-defined]


@asynccontextmanager
async def tls_server(
    leaf: trustme.LeafCert,
    *,
    host: str = "127.0.0.1",
    minimum_version: ssl.TLSVersion | None = None,
    maximum_version: ssl.TLSVersion | None = None,
) -> AsyncIterator[tuple[str, int]]:
    """Yield (host, port) of a running TLS echo-close server."""
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    leaf.configure_cert(server_ctx)
    if minimum_version is not None:
        server_ctx.minimum_version = minimum_version
    if maximum_version is not None:
        server_ctx.maximum_version = maximum_version

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Handshake complete by the time we get here. Close cleanly.
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()

    server = await asyncio.start_server(handler, host, 0, ssl=server_ctx)
    assigned_port = server.sockets[0].getsockname()[1]
    try:
        yield host, assigned_port
    finally:
        server.close()
        await server.wait_closed()


def install_client_trust(
    monkeypatch: object,  # pytest.MonkeyPatch — typed as object to avoid heavy import
    *,
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
) -> None:
    """Make ``ssl.create_default_context`` trust the test CA.

    The TLS analyzer constructs its own ``ssl.create_default_context()``;
    by patching the factory we don't need to thread a context through the
    analyzer API.
    """
    real_factory = ssl.create_default_context
    ca = session_ca()

    def patched(*args: object, **kwargs: object) -> ssl.SSLContext:
        ctx = real_factory(*args, **kwargs)  # type: ignore[arg-type]
        ca.configure_trust(ctx)
        ctx.minimum_version = minimum_version
        return ctx

    monkeypatch.setattr("ssl.create_default_context", patched)  # type: ignore[attr-defined]


__all__ = [
    "install_client_trust",
    "make_cert",
    "session_ca",
    "tls_server",
]
