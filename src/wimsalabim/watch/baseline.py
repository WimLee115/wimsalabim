"""Baseline storage for ``wimsalabim watch``.

Stores canonical-JSON snapshots of scan reports keyed by ``target`` and
``config_hash``. Backed by SQLite (stdlib) — DuckDB is optional and
adds nothing at this scale.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from wimsalabim.core.canonical import canonicalize, sha256_hex
from wimsalabim.core.schema import ScanReport


@dataclass(frozen=True)
class Diff:
    target: str
    previous_at: datetime
    current_at: datetime
    added: list[str]
    removed: list[str]
    changed: list[str]

    @property
    def is_meaningful(self) -> bool:
        return bool(self.added or self.removed or self.changed)


class BaselineStore:
    """Tiny key-value-ish store backed by SQLite."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS snapshots (
        target       TEXT NOT NULL,
        config_hash  TEXT NOT NULL,
        recorded_at  TEXT NOT NULL,
        digest       TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        PRIMARY KEY (target, recorded_at)
    );
    CREATE INDEX IF NOT EXISTS idx_target_time
        ON snapshots(target, recorded_at DESC);
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        with self._conn() as con:
            con.executescript(self.SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self._path)
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def record(self, report: ScanReport) -> str:
        """Persist ``report``. Returns the canonical-JSON SHA-256 digest."""
        payload = canonicalize(report.model_dump(mode="json"))
        digest = sha256_hex(payload)
        with self._conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO snapshots VALUES (?,?,?,?,?)",
                (
                    report.target,
                    report.config_hash,
                    datetime.now(tz=timezone.utc).isoformat(),
                    digest,
                    payload.decode("utf-8"),
                ),
            )
        return digest

    def previous(self, target: str) -> ScanReport | None:
        with self._conn() as con:
            cur = con.execute(
                "SELECT payload_json FROM snapshots WHERE target = ? "
                "ORDER BY recorded_at DESC LIMIT 1 OFFSET 1",
                (target,),
            )
            row = cur.fetchone()
        if not row:
            return None
        data = json.loads(row[0])
        return ScanReport.model_validate(data)

    def diff_against_previous(self, current: ScanReport) -> Diff | None:
        prev = self.previous(current.target)
        if prev is None:
            return None
        added: list[str] = []
        removed: list[str] = []
        changed: list[str] = []

        prev_findings = {
            (a, f.id) for a, r in prev.analyzers.items() if r.report for f in r.report.findings
        }
        cur_findings = {
            (a, f.id) for a, r in current.analyzers.items() if r.report for f in r.report.findings
        }
        for entry in cur_findings - prev_findings:
            added.append(f"{entry[0]}::{entry[1]}")
        for entry in prev_findings - cur_findings:
            removed.append(f"{entry[0]}::{entry[1]}")

        for name, cur_res in current.analyzers.items():
            prev_res = prev.analyzers.get(name)
            if (
                prev_res
                and cur_res.report
                and prev_res.report
                and cur_res.report.grade != prev_res.report.grade
            ):
                changed.append(f"{name}: grade {prev_res.report.grade}→{cur_res.report.grade}")

        return Diff(
            target=current.target,
            previous_at=prev.started_at,
            current_at=current.started_at,
            added=sorted(added),
            removed=sorted(removed),
            changed=sorted(changed),
        )


__all__ = ["BaselineStore", "Diff"]
