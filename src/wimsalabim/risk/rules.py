"""Risk rules — every score increment is traceable to one of these.

Rules are pure functions over the ``analyzers`` dict of a ``ScanReport``.
A rule returns ``RuleHit`` if it fires, ``None`` otherwise.

Adding a rule = adding a row in ``RULE_REGISTRY`` + a small predicate.
That is the entire extension surface.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from wimsalabim.core.schema import (
    AnalyzerResult,
    BaseReport,
    Severity,
)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    severity: Severity
    points: float
    cwe: str | None
    predicate: Callable[[dict[str, AnalyzerResult]], bool]
    rationale_fn: Callable[[dict[str, AnalyzerResult]], str]


def _report(results: dict[str, AnalyzerResult], analyzer: str) -> BaseReport | None:
    res = results.get(analyzer)
    if res is None or res.status != "ok" or res.report is None:
        return None
    return res.report


# ─── Predicates ──────────────────────────────────────────────────────────
def _tls_grade_below(results: dict[str, AnalyzerResult], threshold: str) -> bool:
    rep = _report(results, "tls")
    if rep is None:
        return False
    order = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1, "N/A": 0}
    return order[rep.grade] < order[threshold] and rep.grade != "N/A"


def _missing_security_header(results: dict[str, AnalyzerResult], header: str) -> bool:
    rep = _report(results, "headers")
    if rep is None:
        return False
    missing = rep.metadata.get("missing", "")
    if not isinstance(missing, str):
        return False
    return header.lower() in missing.lower()


def _has_finding(results: dict[str, AnalyzerResult], analyzer: str, finding_id: str) -> bool:
    rep = _report(results, analyzer)
    if rep is None:
        return False
    return any(f.id == finding_id for f in rep.findings)


# ─── Registry ────────────────────────────────────────────────────────────
def _tls_grade_rationale(results: dict[str, AnalyzerResult]) -> str:
    rep = _report(results, "tls")
    grade = rep.grade if rep else "N/A"
    return f"TLS analyzer graded the endpoint '{grade}'."


RULE_REGISTRY: list[Rule] = [
    Rule(
        rule_id="WSL-TLS-001",
        name="TLS grade below B",
        severity="high",
        points=20.0,
        cwe="CWE-326",
        predicate=lambda r: _tls_grade_below(r, "B"),
        rationale_fn=_tls_grade_rationale,
    ),
    Rule(
        rule_id="WSL-TLS-002",
        name="TLS certificate expiring within 7 days",
        severity="critical",
        points=25.0,
        cwe="CWE-298",
        predicate=lambda r: _has_finding(r, "tls", "tls.cert.expiring_soon"),
        rationale_fn=lambda _: "Leaf certificate expires within 7 days — outage risk imminent.",
    ),
    Rule(
        rule_id="WSL-HEADERS-001",
        name="Strict-Transport-Security header missing",
        severity="high",
        points=12.0,
        cwe="CWE-319",
        predicate=lambda r: _missing_security_header(r, "Strict-Transport-Security"),
        rationale_fn=lambda _: "HSTS absent — downgrade attacks possible on first connect.",
    ),
    Rule(
        rule_id="WSL-HEADERS-002",
        name="Content-Security-Policy header missing",
        severity="medium",
        points=8.0,
        cwe="CWE-693",
        predicate=lambda r: _missing_security_header(r, "Content-Security-Policy"),
        rationale_fn=lambda _: "CSP absent — XSS mitigation surface dramatically smaller.",
    ),
    Rule(
        rule_id="WSL-HEADERS-003",
        name="X-Frame-Options / frame-ancestors missing",
        severity="medium",
        points=5.0,
        cwe="CWE-1021",
        predicate=lambda r: _missing_security_header(r, "X-Frame-Options"),
        rationale_fn=lambda _: "Frame-Options absent — clickjacking surface present.",
    ),
    Rule(
        rule_id="WSL-DNS-001",
        name="DNSSEC not deployed",
        severity="medium",
        points=6.0,
        cwe="CWE-345",
        predicate=lambda r: _has_finding(r, "dns_recon", "dns.dnssec.absent"),
        rationale_fn=lambda _: (
            "DNSSEC chain absent — record-spoofing remains feasible at the resolver layer."
        ),
    ),
    Rule(
        rule_id="WSL-DNS-002",
        name="CAA record absent",
        severity="low",
        points=3.0,
        cwe="CWE-295",
        predicate=lambda r: _has_finding(r, "dns_recon", "dns.caa.absent"),
        rationale_fn=lambda _: "No CAA record limits which CAs may issue certs for this domain.",
    ),
]


__all__ = ["RULE_REGISTRY", "Rule"]
