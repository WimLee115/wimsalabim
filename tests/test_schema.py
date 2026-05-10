"""Schema invariants — what we promise about reports."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from wimsalabim.core.schema import (
    BaseReport,
    Finding,
    RiskAssessment,
    Source,
)


def test_source_requires_utc_timestamp() -> None:
    naive = datetime(2026, 5, 10, 12, 0, 0)
    s = Source(kind="dns", target="x", timestamp=naive)
    assert s.timestamp.tzinfo is timezone.utc


def test_source_normalizes_to_utc() -> None:
    from datetime import timedelta

    cet = timezone(timedelta(hours=1))
    aware = datetime(2026, 5, 10, 13, 0, 0, tzinfo=cet)
    s = Source(kind="dns", target="x", timestamp=aware)
    assert s.timestamp == datetime(2026, 5, 10, 12, 0, 0, tzinfo=timezone.utc)


def test_source_body_sha_must_be_hex64() -> None:
    with pytest.raises(ValidationError):
        Source(
            kind="http",
            target="x",
            timestamp=datetime.now(tz=timezone.utc),
            body_sha256="not-a-hash",
        )


def test_finding_cwe_format() -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="x",
            title="t",
            description="d",
            severity="low",
            source=Source(kind="x", target="y", timestamp=datetime.now(tz=timezone.utc)),
            cwe="not-a-cwe",
        )


def test_finding_cvss_range() -> None:
    src = Source(kind="x", target="y", timestamp=datetime.now(tz=timezone.utc))
    with pytest.raises(ValidationError):
        Finding(
            id="x",
            title="t",
            description="d",
            severity="low",
            source=src,
            cvss_score=11.0,
        )


def test_basereport_immutable(example_report: BaseReport) -> None:
    with pytest.raises(ValidationError):
        example_report.grade = "A"  # type: ignore[misc]


def test_basereport_extra_field_rejected() -> None:
    with pytest.raises(ValidationError):
        BaseReport.model_validate(
            {
                "analyzer": "x",
                "target": "y",
                "started_at": datetime.now(tz=timezone.utc),
                "duration_ms": 0,
                "extra_unwanted": "nope",
            }
        )


def test_riskassessment_summary_present() -> None:
    ra = RiskAssessment(
        overall_score=42.0,
        grade="C",
        rules_fired=[],
        summary="…",
    )
    assert ra.engine == "rules"
    assert ra.overall_score == 42.0
