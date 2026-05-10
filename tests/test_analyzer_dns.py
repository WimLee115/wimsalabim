"""DNS analyzer — mocked resolver, no real network."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import dns.exception
import pytest

from wimsalabim.analyzers.base import AnalysisContext
from wimsalabim.analyzers.dns_recon import DNSAnalyzer


class _FakeAnswer:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


def _answers(*texts: str) -> list[_FakeAnswer]:
    return [_FakeAnswer(t) for t in texts]


@pytest.mark.asyncio
async def test_dns_full_record_set_clean_grade_a() -> None:
    async def fake_resolve(name: str, rtype: str):  # type: ignore[no-untyped-def]
        table: dict[str, list[_FakeAnswer]] = {
            "A": _answers("93.184.216.34"),
            "AAAA": _answers("2606:2800:220:1::"),
            "MX": _answers("10 mail.example.com."),
            "NS": _answers("a.iana-servers.net."),
            "TXT": _answers('"v=spf1 -all"'),
            "SOA": _answers("ns.icann.org. noc.dns.icann.org. 1 7200 3600 1209600 3600"),
            "CNAME": _answers(),
            "CAA": _answers('0 issue "letsencrypt.org"'),
            "DNSKEY": _answers("256 3 13 abc"),
        }
        if rtype not in table or not table[rtype]:
            raise dns.exception.DNSException
        return table[rtype]

    with patch(
        "wimsalabim.analyzers.dns_recon.dns.asyncresolver.Resolver.resolve",
        new=AsyncMock(side_effect=fake_resolve),
    ):
        ctx = AnalysisContext(target="example.com", http=None)  # type: ignore[arg-type]
        analyzer = DNSAnalyzer()
        report = await analyzer.analyze(ctx)
    assert report.grade == "A"
    assert report.metadata["dnssec"] is True
    assert "93.184.216.34" in report.metadata["records_a"]


@pytest.mark.asyncio
async def test_dns_no_caa_no_dnssec_grades_b() -> None:
    async def fake_resolve(name: str, rtype: str):  # type: ignore[no-untyped-def]
        if rtype in ("A", "MX"):
            return _answers("1.2.3.4")
        raise dns.exception.DNSException

    with patch(
        "wimsalabim.analyzers.dns_recon.dns.asyncresolver.Resolver.resolve",
        new=AsyncMock(side_effect=fake_resolve),
    ):
        ctx = AnalysisContext(target="example.com", http=None)  # type: ignore[arg-type]
        analyzer = DNSAnalyzer()
        report = await analyzer.analyze(ctx)
    finding_ids = {f.id for f in report.findings}
    assert "dns.caa.absent" in finding_ids
    assert "dns.dnssec.absent" in finding_ids
    # B because medium-severity DNSSEC finding bumps the grade.
    assert report.grade == "B"


@pytest.mark.asyncio
async def test_dns_no_records_at_all_grades_f() -> None:
    async def fake_resolve(name: str, rtype: str):  # type: ignore[no-untyped-def]
        raise dns.exception.DNSException

    with patch(
        "wimsalabim.analyzers.dns_recon.dns.asyncresolver.Resolver.resolve",
        new=AsyncMock(side_effect=fake_resolve),
    ):
        ctx = AnalysisContext(target="example.com", http=None)  # type: ignore[arg-type]
        analyzer = DNSAnalyzer()
        report = await analyzer.analyze(ctx)
    assert report.grade == "F"
    assert report.metadata["total_records"] == 0
