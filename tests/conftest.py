"""Pytest fixtures."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from wimsalabim.core.schema import (
    AnalyzerResult,
    BaseReport,
    Finding,
    ScanReport,
    Source,
)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 5, 10, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def example_finding(now: datetime) -> Finding:
    return Finding(
        id="tls.cert.expiring_soon",
        title="Certificate expires within 7 days",
        description="Leaf cert expires soon.",
        severity="critical",
        source=Source(kind="tls", target="example.com", timestamp=now),
        cwe="CWE-298",
        remediation="Renew now.",
    )


@pytest.fixture
def example_report(now: datetime, example_finding: Finding) -> BaseReport:
    return BaseReport(
        analyzer="tls",
        target="example.com",
        started_at=now,
        duration_ms=42.0,
        grade="F",
        findings=[example_finding],
        metadata={"protocol": "TLSv1.3", "days_until_expiry": 3},
    )


@pytest.fixture
def example_scan(now: datetime, example_report: BaseReport) -> ScanReport:
    return ScanReport(
        tool_version="0.2.0",
        target="example.com",
        started_at=now,
        duration_ms=100.0,
        config_hash="0" * 64,
        analyzers={
            "tls": AnalyzerResult(
                name="tls",
                legal_class="passive",
                status="ok",
                report=example_report,
            ),
        },
    )
