"""Watch-loop tests — hermetisch, zonder netwerk of echte tijd."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from wimsalabim.core.schema import (
    AnalyzerResult,
    BaseReport,
    Finding,
    ScanReport,
    Source,
)
from wimsalabim.watch import BaselineStore, Diff, watch_loop, watch_once


def _now(offset_seconds: int = 0) -> datetime:
    return datetime(2026, 5, 10, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)


def _scan(
    *, target: str = "example.com", grade: str, finding_id: str | None, ts_offset: int = 0
) -> ScanReport:
    src = Source(kind="tls", target=target, timestamp=_now(ts_offset))
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
        target=target,
        started_at=_now(ts_offset),
        duration_ms=10.0,
        grade=grade,
        findings=findings,
    )
    return ScanReport(
        tool_version="0.2.0",
        target=target,
        started_at=_now(ts_offset),
        duration_ms=10.0,
        config_hash="0" * 64,
        analyzers={
            "tls": AnalyzerResult(name="tls", legal_class="passive", status="ok", report=rep),
        },
    )


# ─── watch_once ──────────────────────────────────────────────────────────


async def test_watch_once_records_and_returns_no_diff_first(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")

    async def scan(target: str) -> ScanReport:
        return _scan(target=target, grade="A", finding_id=None)

    report, diff = await watch_once(target="example.com", scan=scan, store=store)
    assert report.target == "example.com"
    assert diff is None  # first snapshot, nothing to diff against


async def test_watch_once_detects_diff_on_second_round(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")
    reports = iter(
        [
            _scan(grade="A", finding_id=None, ts_offset=0),
            _scan(grade="C", finding_id="tls.cert.expiring_soon", ts_offset=10),
        ]
    )

    async def scan(_target: str) -> ScanReport:
        return next(reports)

    await watch_once(target="example.com", scan=scan, store=store)
    _, diff = await watch_once(target="example.com", scan=scan, store=store)

    assert diff is not None
    assert diff.is_meaningful
    assert any("tls.cert.expiring_soon" in entry for entry in diff.added)


# ─── watch_loop ──────────────────────────────────────────────────────────


async def test_watch_loop_runs_max_iterations_and_invokes_callback(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")
    seen: list[tuple[str, Diff | None]] = []

    async def scan(target: str) -> ScanReport:
        return _scan(target=target, grade="A", finding_id=None)

    def on_iter(target: str, _report: ScanReport, diff: Diff | None) -> None:
        seen.append((target, diff))

    outcome = await watch_loop(
        targets=["a.example", "b.example"],
        interval_s=0.01,
        scan=scan,
        store=store,
        on_iteration=on_iter,
        max_iterations=2,
    )

    assert outcome.iterations == 2
    assert outcome.rounds_with_diff == 0
    assert [t for t, _ in seen] == ["a.example", "b.example", "a.example", "b.example"]


async def test_watch_loop_counts_meaningful_diffs(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")
    reports = iter(
        [
            _scan(grade="A", finding_id=None, ts_offset=0),
            _scan(grade="C", finding_id="tls.cert.expiring_soon", ts_offset=10),
            _scan(grade="C", finding_id="tls.cert.expiring_soon", ts_offset=20),
        ]
    )

    async def scan(_target: str) -> ScanReport:
        return next(reports)

    diffs: list[Diff | None] = []

    def on_iter(_t: str, _r: ScanReport, d: Diff | None) -> None:
        diffs.append(d)

    outcome = await watch_loop(
        targets=["example.com"],
        interval_s=0.01,
        scan=scan,
        store=store,
        on_iteration=on_iter,
        max_iterations=3,
    )

    assert outcome.iterations == 3
    # Round 1: no baseline. Round 2: meaningful. Round 3: identical → no change.
    assert outcome.rounds_with_diff == 1
    assert diffs[0] is None
    assert diffs[1] is not None and diffs[1].is_meaningful
    assert diffs[2] is not None and not diffs[2].is_meaningful


async def test_watch_loop_stops_when_event_set(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")
    stop = asyncio.Event()
    rounds = 0

    async def scan(target: str) -> ScanReport:
        nonlocal rounds
        rounds += 1
        if rounds >= 2:
            stop.set()
        return _scan(target=target, grade="A", finding_id=None)

    def on_iter(_t: str, _r: ScanReport, _d: Diff | None) -> None:
        pass

    outcome = await watch_loop(
        targets=["example.com"],
        interval_s=0.01,
        scan=scan,
        store=store,
        on_iteration=on_iter,
        stop_event=stop,
    )
    assert outcome.iterations >= 1
    assert rounds == 2  # stopped right after the second scan


async def test_watch_loop_continues_after_scan_error(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")
    calls = 0

    async def scan(target: str) -> ScanReport:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("boom")
        return _scan(target=target, grade="A", finding_id=None)

    seen: list[str] = []

    def on_iter(target: str, _r: ScanReport, _d: Diff | None) -> None:
        seen.append(target)

    outcome = await watch_loop(
        targets=["example.com"],
        interval_s=0.01,
        scan=scan,
        store=store,
        on_iteration=on_iter,
        max_iterations=2,
    )
    assert outcome.iterations == 2
    assert seen == ["example.com"]  # only the second round produced a callback


async def test_watch_loop_rejects_empty_targets(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")

    async def scan(_t: str) -> ScanReport:  # pragma: no cover — never called
        raise AssertionError

    with pytest.raises(ValueError, match="at least one target"):
        await watch_loop(
            targets=[],
            interval_s=1.0,
            scan=scan,
            store=store,
            on_iteration=lambda *_: None,
        )


async def test_watch_loop_rejects_nonpositive_interval(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "base.sqlite")

    async def scan(_t: str) -> ScanReport:  # pragma: no cover
        raise AssertionError

    with pytest.raises(ValueError, match="interval_s must be"):
        await watch_loop(
            targets=["example.com"],
            interval_s=0.0,
            scan=scan,
            store=store,
            on_iteration=lambda *_: None,
        )
