"""TLS analyzer — end-to-end via an in-process TLS server.

Each test mints a fresh leaf certificate via the shared ``trustme`` CA,
spins up an asyncio TLS server, monkeypatches the analyzer's HTTPS port
and the client SSL trust, then invokes ``TLSAnalyzer.analyze``.

No real network. No flakiness from the public internet.
"""

from __future__ import annotations

import ssl

import pytest

from tests._tls_helpers import install_client_trust, make_cert, tls_server
from wimsalabim.analyzers.base import AnalysisContext
from wimsalabim.analyzers.tls import TLSAnalyzer
from wimsalabim.core.exceptions import AnalyzerError, NetworkError


def _ctx(target: str = "127.0.0.1") -> AnalysisContext:
    # http is not used by TLSAnalyzer; pass None.
    return AnalysisContext(target=target, http=None)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_happy_path_returns_grade_a(monkeypatch: pytest.MonkeyPatch) -> None:
    install_client_trust(monkeypatch)
    leaf = make_cert(common_name="127.0.0.1", valid_for_days=90)

    async with tls_server(leaf) as (host, port):
        monkeypatch.setattr("wimsalabim.analyzers.tls._HTTPS_PORT", port)
        report = await TLSAnalyzer().analyze(_ctx(host))

    assert report.grade == "A"
    assert report.findings == []
    assert report.metadata["protocol"].startswith("TLSv1.")
    assert report.metadata["days_until_expiry"] >= 80
    # trustme stores the hostname in SAN; subject CN is generic. Verify
    # the analyzer captured *some* subject metadata.
    assert isinstance(report.metadata["subject"], str)
    assert report.metadata["subject"]


@pytest.mark.asyncio
async def test_certificate_expiring_within_seven_days_is_critical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_client_trust(monkeypatch)
    leaf = make_cert(common_name="127.0.0.1", valid_for_days=3)

    async with tls_server(leaf) as (host, port):
        monkeypatch.setattr("wimsalabim.analyzers.tls._HTTPS_PORT", port)
        report = await TLSAnalyzer().analyze(_ctx(host))

    assert report.grade == "F"
    finding_ids = {f.id for f in report.findings}
    assert "tls.cert.expiring_soon" in finding_ids
    crit = next(f for f in report.findings if f.id == "tls.cert.expiring_soon")
    assert crit.severity == "critical"
    assert crit.cwe == "CWE-298"


@pytest.mark.asyncio
async def test_certificate_expiring_within_thirty_days_is_medium(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_client_trust(monkeypatch)
    leaf = make_cert(common_name="127.0.0.1", valid_for_days=20)

    async with tls_server(leaf) as (host, port):
        monkeypatch.setattr("wimsalabim.analyzers.tls._HTTPS_PORT", port)
        report = await TLSAnalyzer().analyze(_ctx(host))

    assert report.grade == "B"
    finding_ids = {f.id for f in report.findings}
    assert "tls.cert.expiring_warning" in finding_ids
    warn = next(f for f in report.findings if f.id == "tls.cert.expiring_warning")
    assert warn.severity == "medium"


@pytest.mark.asyncio
async def test_metadata_includes_subject_issuer_and_dates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_client_trust(monkeypatch)
    leaf = make_cert(common_name="127.0.0.1", valid_for_days=60)

    async with tls_server(leaf) as (host, port):
        monkeypatch.setattr("wimsalabim.analyzers.tls._HTTPS_PORT", port)
        report = await TLSAnalyzer().analyze(_ctx(host))

    md = report.metadata
    for key in (
        "protocol",
        "cipher",
        "days_until_expiry",
        "subject",
        "issuer",
        "not_before",
        "not_after",
    ):
        assert key in md, f"missing metadata key {key!r}"


@pytest.mark.asyncio
async def test_connection_refused_raises_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Port 1 is reserved for tcpmux and almost universally closed.
    monkeypatch.setattr("wimsalabim.analyzers.tls._HTTPS_PORT", 1)
    monkeypatch.setattr("wimsalabim.analyzers.tls._HANDSHAKE_TIMEOUT_S", 2.0)

    with pytest.raises(NetworkError) as excinfo:
        await TLSAnalyzer().analyze(_ctx("127.0.0.1"))
    assert excinfo.value.kind == "tls"


@pytest.mark.asyncio
async def test_handshake_timeout_raises_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — guaranteed unroutable.
    monkeypatch.setattr("wimsalabim.analyzers.tls._HTTPS_PORT", 443)
    monkeypatch.setattr("wimsalabim.analyzers.tls._HANDSHAKE_TIMEOUT_S", 0.5)

    with pytest.raises(NetworkError):
        await TLSAnalyzer().analyze(_ctx("192.0.2.1"))


@pytest.mark.asyncio
async def test_no_peer_cert_raises_analyzer_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Force the analyzer's ``getpeercert`` path to return None.

    This simulates a TLS implementation that completes the handshake
    without exposing the peer certificate (very rare, but the analyzer
    explicitly handles it).
    """
    install_client_trust(monkeypatch)
    leaf = make_cert(common_name="127.0.0.1", valid_for_days=90)

    async with tls_server(leaf) as (host, port):
        monkeypatch.setattr("wimsalabim.analyzers.tls._HTTPS_PORT", port)

        # Patch SSLObject.getpeercert to return None for one call.
        original = ssl.SSLObject.getpeercert

        def fake_getpeercert(self: ssl.SSLObject, binary_form: bool = False) -> object:
            return None

        monkeypatch.setattr(ssl.SSLObject, "getpeercert", fake_getpeercert)

        with pytest.raises(AnalyzerError) as excinfo:
            await TLSAnalyzer().analyze(_ctx(host))
        assert "no peer certificate" in str(excinfo.value).lower()

        monkeypatch.setattr(ssl.SSLObject, "getpeercert", original)


@pytest.mark.asyncio
async def test_grading_with_only_high_severity_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the grade-from-findings rule for the 'high' band.

    The code path for 'high' severity is tricky to reach via certificate
    state alone (TLS-protocol weakness requires negotiating <TLS1.2,
    which the client refuses). We hit the static method directly.
    """
    from datetime import datetime, timezone

    from wimsalabim.core.schema import Finding, Source

    src = Source(kind="tls", target="x", timestamp=datetime.now(tz=timezone.utc))
    high_finding = Finding(
        id="tls.protocol.weak",
        title="x",
        description="x",
        severity="high",
        source=src,
        cwe="CWE-326",
    )
    medium_finding = Finding(
        id="tls.cert.expiring_warning",
        title="x",
        description="x",
        severity="medium",
        source=src,
    )

    assert TLSAnalyzer._grade([high_finding]) == "C"
    assert TLSAnalyzer._grade([medium_finding]) == "B"
    assert TLSAnalyzer._grade([]) == "A"


@pytest.mark.asyncio
async def test_dns_resolution_failure_raises_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Targeting a hostname that can never resolve must raise NetworkError."""
    monkeypatch.setattr("wimsalabim.analyzers.tls._HTTPS_PORT", 443)
    monkeypatch.setattr("wimsalabim.analyzers.tls._HANDSHAKE_TIMEOUT_S", 2.0)

    # .invalid is reserved by RFC 6761 — guaranteed not to resolve.
    with pytest.raises(NetworkError):
        await TLSAnalyzer().analyze(_ctx("definitely-not-a-real-host-just-for-testing.invalid"))
