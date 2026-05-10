"""Baseline storage round-trip + diff detection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from wimsalabim.core.schema import (
    AnalyzerResult,
    BaseReport,
    Finding,
    ScanReport,
    Source,
)
from wimsalabim.watch.baseline import BaselineStore


def _now(offset_seconds: int = 0) -> datetime:
    return datetime(2026, 5, 10, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)


def _scan(*, grade: str, finding_id: str | None, ts_offset: int = 0) -> ScanReport:
    src = Source(kind="tls", target="example.com", timestamp=_now(ts_offset))
    findings = []
    if finding_id:
        findings.append(
            Finding(
                id=finding_id,
                title="x",
                description="x",
                severity="high",
                source=src,
            )
        )
    rep = BaseReport(
        analyzer="tls",
        target="example.com",
        started_at=_now(ts_offset),
        duration_ms=10.0,
        grade=grade,  # type: ignore[arg-type]
        findings=findings,
    )
    return ScanReport(
        tool_version="0.2.0",
        target="example.com",
        started_at=_now(ts_offset),
        duration_ms=10.0,
        config_hash="0" * 64,
        analyzers={
            "tls": AnalyzerResult(name="tls", legal_class="passive", status="ok", report=rep),
        },
    )


def test_record_returns_digest(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")
    digest = store.record(_scan(grade="A", finding_id=None))
    assert len(digest) == 64


def test_previous_returns_none_on_first(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")
    store.record(_scan(grade="A", finding_id=None))
    assert store.previous("example.com") is None


def test_previous_returns_first_after_second(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")
    store.record(_scan(grade="A", finding_id=None, ts_offset=0))
    store.record(_scan(grade="B", finding_id="x", ts_offset=10))
    prev = store.previous("example.com")
    assert prev is not None
    assert prev.analyzers["tls"].report is not None
    assert prev.analyzers["tls"].report.grade == "A"


def test_diff_against_previous_detects_added_finding(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")
    store.record(_scan(grade="A", finding_id=None, ts_offset=0))
    current = _scan(grade="C", finding_id="tls.cert.expiring_soon", ts_offset=10)
    store.record(current)
    diff = store.diff_against_previous(current)
    assert diff is not None
    assert any("tls.cert.expiring_soon" in a for a in diff.added)
    assert any("grade A→C" in c for c in diff.changed)
    assert diff.is_meaningful


def test_diff_returns_none_without_history(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")
    current = _scan(grade="A", finding_id=None)
    store.record(current)
    assert store.diff_against_previous(current) is None
