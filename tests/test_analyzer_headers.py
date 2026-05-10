"""Headers analyzer — fully mocked via respx, no real network."""

from __future__ import annotations

import httpx
import pytest
import respx

from wimsalabim.analyzers.base import AnalysisContext
from wimsalabim.analyzers.headers import HeadersAnalyzer
from wimsalabim.core.http_client import make_client


@pytest.fixture
async def http_ctx() -> AnalysisContext:  # type: ignore[misc]
    async with make_client() as http:
        yield AnalysisContext(target="example.com", http=http)


@pytest.mark.asyncio
@respx.mock
async def test_clean_response_grades_a() -> None:
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=63072000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            },
            content=b"<html></html>",
        )
    )
    async with make_client() as http:
        ctx = AnalysisContext(target="example.com", http=http)
        analyzer = HeadersAnalyzer()
        report = await analyzer.analyze(ctx)
    assert report.grade == "A"
    assert len(report.findings) == 0
    assert "Strict-Transport-Security" in report.metadata["present"]


@pytest.mark.asyncio
@respx.mock
async def test_missing_hsts_and_csp_grades_d() -> None:
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(200, headers={"X-Frame-Options": "DENY"}, content=b"")
    )
    async with make_client() as http:
        ctx = AnalysisContext(target="example.com", http=http)
        analyzer = HeadersAnalyzer()
        report = await analyzer.analyze(ctx)
    assert report.grade == "D"
    ids = {f.id for f in report.findings}
    assert "headers.missing.strict-transport-security" in ids
    assert "headers.missing.content-security-policy" in ids


@pytest.mark.asyncio
@respx.mock
async def test_info_leak_header_emits_finding() -> None:
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=63072000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
                "Server": "nginx/1.20.1",
            },
            content=b"",
        )
    )
    async with make_client() as http:
        ctx = AnalysisContext(target="example.com", http=http)
        analyzer = HeadersAnalyzer()
        report = await analyzer.analyze(ctx)
    leak_ids = [f.id for f in report.findings if f.id.startswith("headers.leak")]
    assert "headers.leak.server" in leak_ids
    assert "nginx" in report.metadata["info_leaks"]


@pytest.mark.asyncio
@respx.mock
async def test_network_failure_raises_network_error() -> None:
    from wimsalabim.core.exceptions import NetworkError

    respx.get("https://example.com/").mock(side_effect=httpx.ConnectError("boom"))
    async with make_client() as http:
        ctx = AnalysisContext(target="example.com", http=http)
        analyzer = HeadersAnalyzer()
        with pytest.raises(NetworkError):
            await analyzer.analyze(ctx)
