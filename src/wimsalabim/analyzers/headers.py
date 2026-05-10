"""HTTP security headers — passive single GET.

We send exactly one request to ``https://<target>/`` and inspect the
response headers. Information-leaking headers (``Server``,
``X-Powered-By``) are reported as findings; missing security headers
generate one finding each.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256

import httpx

from wimsalabim.analyzers.base import AnalysisContext, BaseAnalyzer
from wimsalabim.core.exceptions import NetworkError
from wimsalabim.core.registry import Capabilities, analyzer
from wimsalabim.core.schema import BaseReport, Finding, Grade, Severity, Source

_BODY_SHA_PREFIX_BYTES = 65536
_GRADE_D_MISSING_THRESHOLD = 2
_HEAVY_HITTERS: frozenset[str] = frozenset({"Strict-Transport-Security", "Content-Security-Policy"})

_SECURITY_HEADERS: tuple[tuple[str, Severity, str], ...] = (
    ("Strict-Transport-Security", "high", "CWE-319"),
    ("Content-Security-Policy", "medium", "CWE-693"),
    ("X-Frame-Options", "medium", "CWE-1021"),
    ("X-Content-Type-Options", "low", "CWE-693"),
    ("Referrer-Policy", "low", "CWE-200"),
    ("Permissions-Policy", "low", "CWE-693"),
)
_LEAKY_HEADERS: tuple[str, ...] = (
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator",
)

_REMEDIATIONS: dict[str, str] = {
    "Strict-Transport-Security": (
        "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'."
    ),
    "Content-Security-Policy": (
        "Define a baseline CSP, e.g. \"default-src 'self'; object-src 'none'\"."
    ),
    "X-Frame-Options": "Set 'X-Frame-Options: DENY' (or use frame-ancestors in CSP).",
    "X-Content-Type-Options": "Set 'X-Content-Type-Options: nosniff'.",
    "Referrer-Policy": "Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
    "Permissions-Policy": (
        "Restrict APIs you do not use, e.g. 'Permissions-Policy: geolocation=()'."
    ),
}


@analyzer(
    "headers",
    legal_class="passive",
    capabilities=Capabilities(network=("https",), rate_limit_per_second=2, timeout_seconds=10.0),
    description="Security & info-leak headers via single GET (passive).",
)
class HeadersAnalyzer(BaseAnalyzer):
    async def analyze(self, context: AnalysisContext) -> BaseReport:
        started = datetime.now(tz=timezone.utc)
        url = f"https://{context.target}/"

        try:
            response = await context.http.get(url, follow_redirects=True)
        except httpx.HTTPError as exc:
            raise NetworkError(kind="http", target=context.target, message=str(exc)) from exc

        now = datetime.now(tz=timezone.utc)
        body_sha = ""
        if response.content:
            body_sha = sha256(response.content[:_BODY_SHA_PREFIX_BYTES]).hexdigest()

        findings: list[Finding] = []
        present: list[str] = []
        missing: list[str] = []

        for name, severity, cwe in _SECURITY_HEADERS:
            if name in response.headers:
                present.append(name)
            else:
                missing.append(name)
                findings.append(
                    Finding(
                        id=f"headers.missing.{name.lower()}",
                        title=f"Security header missing: {name}",
                        description=f"Server response did not include {name}.",
                        severity=severity,
                        source=Source(
                            kind="http",
                            target=context.target,
                            timestamp=now,
                            body_sha256=body_sha or None,
                            metadata={
                                "url": str(response.url),
                                "status": str(response.status_code),
                            },
                        ),
                        cwe=cwe,
                        remediation=_remediation_for(name),
                    )
                )

        info_leaks: list[str] = []
        for name in _LEAKY_HEADERS:
            if name in response.headers:
                value = response.headers[name]
                info_leaks.append(f"{name}: {value}")
                findings.append(
                    Finding(
                        id=f"headers.leak.{name.lower()}",
                        title=f"Information-disclosing header: {name}",
                        description=(
                            f"{name} is set to '{value}', revealing software/version detail."
                        ),
                        severity="low",
                        source=Source(
                            kind="http",
                            target=context.target,
                            timestamp=now,
                            metadata={"url": str(response.url)},
                        ),
                        cwe="CWE-200",
                        remediation=f"Remove the {name} header from server config.",
                    )
                )

        grade = _grade(missing, info_leaks)

        return BaseReport(
            analyzer="headers",
            target=context.target,
            started_at=started,
            duration_ms=(datetime.now(tz=timezone.utc) - started).total_seconds() * 1000.0,
            grade=grade,
            findings=findings,
            metadata={
                "url": str(response.url),
                "status": response.status_code,
                "present": ",".join(present),
                "missing": ",".join(missing),
                "info_leaks": ",".join(info_leaks),
                "protocol": response.http_version,
            },
        )


def _remediation_for(header: str) -> str:
    return _REMEDIATIONS.get(header, f"Add {header} header.")


def _grade(missing: list[str], info_leaks: list[str]) -> Grade:
    severity_count = sum(1 for h in missing if h in _HEAVY_HITTERS)
    if severity_count >= _GRADE_D_MISSING_THRESHOLD:
        return "D"
    if severity_count == 1 and info_leaks:
        return "C"
    if missing or info_leaks:
        return "B"
    return "A"
