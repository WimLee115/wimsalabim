"""Risk engine — every score is traceable to a rule."""

from __future__ import annotations

from datetime import datetime, timezone

from wimsalabim.core.schema import (
    AnalyzerResult,
    BaseReport,
    Finding,
    Source,
)
from wimsalabim.risk.heuristic import HeuristicRiskEngine


def _now() -> datetime:
    return datetime(2026, 5, 10, 12, 0, 0, tzinfo=timezone.utc)


def _result(
    name: str,
    *,
    grade: str = "A",
    findings: list[Finding] | None = None,
    metadata: dict[str, str | int | float | bool] | None = None,
) -> AnalyzerResult:
    return AnalyzerResult(
        name=name,
        legal_class="passive",
        status="ok",
        report=BaseReport(
            analyzer=name,
            target="example.com",
            started_at=_now(),
            duration_ms=10.0,
            grade=grade,  # type: ignore[arg-type]
            findings=findings or [],
            metadata=metadata or {},
        ),
    )


def test_clean_state_grades_a() -> None:
    out = HeuristicRiskEngine().assess(
        {
            "tls": _result("tls", grade="A", metadata={}),
            "headers": _result("headers", grade="A", metadata={"missing": ""}),
            "dns_recon": _result("dns_recon", grade="A"),
        }
    )
    assert out.grade == "A"
    assert out.overall_score == 0.0
    assert out.rules_fired == []


def test_tls_grade_below_b_fires_rule() -> None:
    out = HeuristicRiskEngine().assess(
        {
            "tls": _result("tls", grade="C"),
            "headers": _result("headers", metadata={"missing": ""}),
        }
    )
    assert any(h.rule_id == "WSL-TLS-001" for h in out.rules_fired)
    assert out.overall_score >= 20.0


def test_tls_expiring_soon_fires_critical() -> None:
    src = Source(kind="tls", target="x", timestamp=_now())
    finding = Finding(
        id="tls.cert.expiring_soon",
        title="x",
        description="x",
        severity="critical",
        source=src,
    )
    out = HeuristicRiskEngine().assess(
        {
            "tls": _result("tls", grade="F", findings=[finding]),
            "headers": _result("headers", metadata={"missing": ""}),
        }
    )
    assert any(h.rule_id == "WSL-TLS-002" and h.severity == "critical" for h in out.rules_fired)
    assert out.grade in ("D", "F")


def test_missing_hsts_fires() -> None:
    out = HeuristicRiskEngine().assess(
        {
            "tls": _result("tls"),
            "headers": _result("headers", metadata={"missing": "Strict-Transport-Security"}),
        }
    )
    assert any(h.rule_id == "WSL-HEADERS-001" for h in out.rules_fired)


def test_score_capped_at_100() -> None:
    src = Source(kind="tls", target="x", timestamp=_now())
    crit = Finding(
        id="tls.cert.expiring_soon", title="x", description="x", severity="critical", source=src
    )
    out = HeuristicRiskEngine().assess(
        {
            "tls": _result("tls", grade="F", findings=[crit]),
            "headers": _result(
                "headers",
                metadata={
                    "missing": "Strict-Transport-Security,Content-Security-Policy,X-Frame-Options"
                },
            ),
            "dns_recon": _result(
                "dns_recon",
                findings=[
                    Finding(
                        id="dns.dnssec.absent",
                        title="x",
                        description="x",
                        severity="medium",
                        source=src,
                    ),
                    Finding(
                        id="dns.caa.absent", title="x", description="x", severity="low", source=src
                    ),
                ],
            ),
        }
    )
    assert out.overall_score <= 100.0


def test_every_hit_has_rationale() -> None:
    out = HeuristicRiskEngine().assess(
        {
            "tls": _result("tls", grade="C"),
            "headers": _result("headers", metadata={"missing": "Content-Security-Policy"}),
        }
    )
    for hit in out.rules_fired:
        assert hit.rationale, f"rule {hit.rule_id} fired without rationale"
