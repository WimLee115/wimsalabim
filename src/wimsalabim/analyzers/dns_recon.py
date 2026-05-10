"""DNS reconnaissance — passive, public-data only.

Resolves A / AAAA / MX / NS / TXT / SOA / CNAME / CAA. Probes for
DNSSEC by attempting a DNSKEY lookup. Never attempts a zone transfer
(would be ``intrusive`` and we keep this strictly passive).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import dns.asyncresolver
import dns.exception

from wimsalabim.analyzers.base import AnalysisContext, BaseAnalyzer
from wimsalabim.core.registry import Capabilities, analyzer
from wimsalabim.core.schema import BaseReport, Finding, Grade, Source

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA")


@analyzer(
    "dns_recon",
    legal_class="passive",
    capabilities=Capabilities(network=("dns",), rate_limit_per_second=20, timeout_seconds=12.0),
    description="A/AAAA/MX/NS/TXT/SOA/CNAME/CAA + DNSSEC presence (passive).",
)
class DNSAnalyzer(BaseAnalyzer):
    async def analyze(self, context: AnalysisContext) -> BaseReport:
        started = datetime.now(tz=timezone.utc)
        target = context.target
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0

        records: dict[str, list[str]] = {}
        for rtype in _RECORD_TYPES:
            records[rtype] = await self._lookup(resolver, target, rtype)

        dnssec_present = await self._probe_dnssec(resolver, target)
        findings: list[Finding] = []
        now = datetime.now(tz=timezone.utc)

        if not records["CAA"]:
            findings.append(
                Finding(
                    id="dns.caa.absent",
                    title="No CAA record",
                    description=(
                        "A CAA record restricts which Certificate Authorities may issue "
                        "certs for this domain. None was found."
                    ),
                    severity="low",
                    source=Source(kind="dns", target=target, timestamp=now),
                    cwe="CWE-295",
                    remediation='Add e.g.  example.com. CAA 0 issue "letsencrypt.org"',
                    references=["https://datatracker.ietf.org/doc/html/rfc8659"],
                )
            )

        if not dnssec_present:
            findings.append(
                Finding(
                    id="dns.dnssec.absent",
                    title="DNSSEC not deployed",
                    description="No DNSKEY records found at the apex.",
                    severity="medium",
                    source=Source(kind="dns", target=target, timestamp=now),
                    cwe="CWE-345",
                    remediation="Deploy DNSSEC on the authoritative zone.",
                    references=["https://www.sidn.nl/en/dnssec"],
                )
            )

        if not records["MX"]:
            findings.append(
                Finding(
                    id="dns.mx.absent",
                    title="No MX records",
                    description=(
                        "Domain advertises no MX. Mail to this domain will be silently dropped."
                    ),
                    severity="info",
                    source=Source(kind="dns", target=target, timestamp=now),
                )
            )

        total = sum(len(v) for v in records.values())
        grade = self._grade(findings, total)

        meta: dict[str, str | int | float | bool] = {
            "total_records": total,
            "dnssec": dnssec_present,
        }
        for rtype, values in records.items():
            meta[f"records_{rtype.lower()}"] = ",".join(values[:5])

        return BaseReport(
            analyzer="dns_recon",
            target=target,
            started_at=started,
            duration_ms=(datetime.now(tz=timezone.utc) - started).total_seconds() * 1000.0,
            grade=grade,
            findings=findings,
            metadata=meta,
        )

    @staticmethod
    async def _lookup(resolver: dns.asyncresolver.Resolver, name: str, rtype: str) -> list[str]:
        try:
            answers = await resolver.resolve(name, rtype)
        except (dns.exception.DNSException, asyncio.TimeoutError):
            return []
        return [a.to_text() for a in answers]

    @staticmethod
    async def _probe_dnssec(resolver: dns.asyncresolver.Resolver, name: str) -> bool:
        try:
            answers = await resolver.resolve(name, "DNSKEY")
        except (dns.exception.DNSException, asyncio.TimeoutError):
            return False
        return len(answers) > 0

    @staticmethod
    def _grade(findings: list[Finding], total_records: int) -> Grade:
        if total_records == 0:
            return "F"
        if any(f.severity in ("critical", "high") for f in findings):
            return "C"
        if any(f.severity == "medium" for f in findings):
            return "B"
        return "A"
