"""TLS/SSL inspection — handshake to the target, parse the leaf certificate.

This is **passive** in the legal sense: we open a single connection on
:443 the way any browser would, observe what the server presents, and
disconnect. No probing, no fuzzing, no downgrade attempts.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from wimsalabim.analyzers.base import AnalysisContext, BaseAnalyzer
from wimsalabim.core.exceptions import AnalyzerError, NetworkError
from wimsalabim.core.registry import Capabilities, analyzer
from wimsalabim.core.schema import BaseReport, Finding, Grade, Source

_WEAK_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})
_HANDSHAKE_TIMEOUT_S = 8.0
_EXPIRY_CRITICAL_DAYS = 7
_EXPIRY_WARNING_DAYS = 30
_HTTPS_PORT = 443


@analyzer(
    "tls",
    legal_class="passive",
    capabilities=Capabilities(network=("tls",), rate_limit_per_second=4, timeout_seconds=12.0),
    description="TLS handshake + leaf certificate inspection (single connection).",
)
class TLSAnalyzer(BaseAnalyzer):
    async def analyze(self, context: AnalysisContext) -> BaseReport:
        started = datetime.now(tz=timezone.utc)
        host = context.target

        ctx = ssl.create_default_context()
        ctx.minimum_version = (
            ssl.TLSVersion.TLSv1_2
        )  # we still want to KNOW about old; the metadata captures it
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=_HTTPS_PORT, ssl=ctx, server_hostname=host),
                timeout=_HANDSHAKE_TIMEOUT_S,
            )
        except (asyncio.TimeoutError, OSError, ssl.SSLError) as exc:
            raise NetworkError(kind="tls", target=host, message=str(exc)) from exc

        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            peer_cert_der: bytes | None = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            protocol: str | None = ssl_obj.version() if ssl_obj else None
            cipher_tuple = ssl_obj.cipher() if ssl_obj else None
        finally:
            writer.close()
            with contextlib.suppress(OSError, ssl.SSLError):
                await writer.wait_closed()

        if peer_cert_der is None:
            raise AnalyzerError(analyzer="tls", message="no peer certificate received")

        cert = x509.load_der_x509_certificate(peer_cert_der, default_backend())
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
        now = datetime.now(tz=timezone.utc)
        days_left = (not_after - now).days

        cipher_name = cipher_tuple[0] if cipher_tuple else "unknown"

        findings: list[Finding] = []

        if days_left < 0:
            findings.append(
                Finding(
                    id="tls.cert.expired",
                    title="Certificate is expired",
                    description=f"Leaf certificate expired on {not_after.isoformat()}.",
                    severity="critical",
                    source=Source(kind="tls", target=host, timestamp=now),
                    cwe="CWE-298",
                    remediation="Renew the certificate immediately.",
                )
            )
        elif days_left < _EXPIRY_CRITICAL_DAYS:
            findings.append(
                Finding(
                    id="tls.cert.expiring_soon",
                    title=f"Certificate expires within {_EXPIRY_CRITICAL_DAYS} days",
                    description=f"Leaf certificate expires on {not_after.isoformat()}.",
                    severity="critical",
                    source=Source(kind="tls", target=host, timestamp=now),
                    cwe="CWE-298",
                    remediation="Renew now; outage risk imminent.",
                )
            )
        elif days_left < _EXPIRY_WARNING_DAYS:
            findings.append(
                Finding(
                    id="tls.cert.expiring_warning",
                    title=f"Certificate expires within {_EXPIRY_WARNING_DAYS} days",
                    description=f"Leaf certificate expires on {not_after.isoformat()}.",
                    severity="medium",
                    source=Source(kind="tls", target=host, timestamp=now),
                    remediation="Schedule renewal.",
                )
            )

        if protocol in _WEAK_PROTOCOLS:
            findings.append(
                Finding(
                    id="tls.protocol.weak",
                    title=f"Weak protocol negotiated: {protocol}",
                    description=f"The handshake settled on {protocol}, which is deprecated.",
                    severity="high",
                    source=Source(kind="tls", target=host, timestamp=now),
                    cwe="CWE-326",
                    remediation="Disable TLS < 1.2 on the server.",
                )
            )

        grade = self._grade(findings)

        return BaseReport(
            analyzer="tls",
            target=host,
            started_at=started,
            duration_ms=(datetime.now(tz=timezone.utc) - started).total_seconds() * 1000.0,
            grade=grade,
            findings=findings,
            metadata={
                "protocol": protocol or "unknown",
                "cipher": cipher_name,
                "days_until_expiry": days_left,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
            },
        )

    @staticmethod
    def _grade(findings: list[Finding]) -> Grade:
        if any(f.severity == "critical" for f in findings):
            return "F"
        if any(f.severity == "high" for f in findings):
            return "C"
        if any(f.severity == "medium" for f in findings):
            return "B"
        return "A"
