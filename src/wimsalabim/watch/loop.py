"""Daemonized scan-loop voor ``wimsalabim watch``.

De loop is bewust ontkoppeld van CLI én Orchestrator: hij krijgt een
``scan``-callable en een ``BaselineStore`` mee. Dat houdt de tests
hermetisch — geen netwerk, geen klokken nodig — en laat de CLI dunne
opslag/orchestratie-keuzes maken.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass

from wimsalabim.core.logging import get_logger
from wimsalabim.core.schema import ScanReport
from wimsalabim.watch.baseline import BaselineStore, Diff

logger = get_logger(__name__)

ScanFn = Callable[[str], Awaitable[ScanReport]]
OnIteration = Callable[[str, ScanReport, "Diff | None"], None]


@dataclass(frozen=True)
class WatchOutcome:
    iterations: int
    rounds_with_diff: int


async def watch_once(
    *,
    target: str,
    scan: ScanFn,
    store: BaselineStore,
) -> tuple[ScanReport, Diff | None]:
    """Eén scan-cyclus: scan → record → diff t.o.v. vorige snapshot."""
    report = await scan(target)
    store.record(report)
    diff = store.diff_against_previous(report)
    return report, diff


async def watch_loop(
    *,
    targets: Iterable[str],
    interval_s: float,
    scan: ScanFn,
    store: BaselineStore,
    on_iteration: OnIteration,
    stop_event: asyncio.Event | None = None,
    max_iterations: int | None = None,
) -> WatchOutcome:
    """Loop tot ``stop_event`` set is of ``max_iterations`` is bereikt.

    - Eén iteratie = één scan per target uit ``targets``.
    - Tussen iteraties wordt geslapen tot ``interval_s`` seconden of tot
      ``stop_event`` set wordt — wat eerder is. Zo is shutdown direct.
    - ``max_iterations=None`` betekent oneindig (default voor de daemon).
    - ``WatchOutcome`` rapporteert hoeveel rondes effectief liepen en
      hoeveel daarvan een betekenisvolle diff opleverden.
    """
    targets = list(targets)
    if not targets:
        raise ValueError("watch_loop needs at least one target")
    if interval_s <= 0:
        raise ValueError("interval_s must be > 0")

    stop = stop_event if stop_event is not None else asyncio.Event()
    iterations = 0
    rounds_with_diff = 0

    while not stop.is_set():
        for target in targets:
            if stop.is_set():
                return WatchOutcome(iterations, rounds_with_diff)
            log = logger.bind(target=target, iteration=iterations + 1)
            try:
                report, diff = await watch_once(target=target, scan=scan, store=store)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Daemon mag niet sterven aan één scan-mislukking; log + door.
                log.warning("scan_failed", error=str(exc), error_type=type(exc).__name__)
                continue
            if diff is not None and diff.is_meaningful:
                rounds_with_diff += 1
            on_iteration(target, report, diff)

        iterations += 1
        if max_iterations is not None and iterations >= max_iterations:
            return WatchOutcome(iterations, rounds_with_diff)

        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval_s)

    return WatchOutcome(iterations, rounds_with_diff)


__all__ = ["OnIteration", "ScanFn", "WatchOutcome", "watch_loop", "watch_once"]
