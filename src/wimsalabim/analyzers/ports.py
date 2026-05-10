"""TCP-connect port scan — **active**, behind the Authorization Gate.

We perform connection-level probes, no SYN-spraying or banner-grabbing
that goes beyond what a regular client would observe. Default port list
is small and conservative; the operator can override.

NL/EU note: this analyzer's ``legal_class`` is ``active``, which means
the orchestrator will *refuse* to run it unless ``Authorization`` was
verified for the target (see ``core.authorization``). That is the
technical implementation of NL Sr 138ab compliance.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timezone

from wimsalabim.analyzers.base import AnalysisContext, BaseAnalyzer
from wimsalabim.core.registry import Capabilities, analyzer
from wimsalabim.core.schema import BaseReport, Finding, Grade, Source

_DEFAULT_PORTS = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    465,
    587,
    993,
    995,
    1433,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    9200,
    27017,
)
_RISKY_PORTS = frozenset({21, 23, 3389, 5900, 6379, 9200, 27017, 1433, 3306, 5432})


@analyzer(
    "ports",
    legal_class="active",
    capabilities=Capabilities(
        network=("tcp",),
        rate_limit_per_second=15,
        timeout_seconds=30.0,
    ),
    description="Async TCP-connect port scan (active — requires authorization).",
)
class PortsAnalyzer(BaseAnalyzer):
    async def analyze(self, context: AnalysisContext) -> BaseReport:
        started = datetime.now(tz=timezone.utc)
        target = context.target
        ports: tuple[int, ...] = _DEFAULT_PORTS

        sem = asyncio.Semaphore(20)
        results: list[tuple[int, bool]] = []

        async def probe(port: int) -> None:
            async with sem:
                results.append((port, await _is_open(target, port, timeout=1.5)))

        await asyncio.gather(*(probe(p) for p in ports))

        open_ports = sorted(p for p, ok in results if ok)
        risky_open = sorted(p for p in open_ports if p in _RISKY_PORTS)

        now = datetime.now(tz=timezone.utc)
        findings: list[Finding] = []
        for p in risky_open:
            findings.append(
                Finding(
                    id=f"ports.risky.{p}",
                    title=f"Risky service port open: {p}",
                    description=f"TCP/{p} is reachable. Common high-risk service.",
                    severity=_severity_for_port(p),
                    source=Source(
                        kind="tcp",
                        target=f"{target}:{p}",
                        timestamp=now,
                    ),
                    cwe="CWE-200",
                    remediation=(
                        f"Confirm TCP/{p} should be reachable; if not, restrict "
                        f"to a private network or behind VPN."
                    ),
                )
            )

        grade: Grade = "A"
        if any(f.severity == "critical" for f in findings):
            grade = "F"
        elif risky_open:
            grade = "C"
        elif open_ports:
            grade = "B"

        return BaseReport(
            analyzer="ports",
            target=target,
            started_at=started,
            duration_ms=(datetime.now(tz=timezone.utc) - started).total_seconds() * 1000.0,
            grade=grade,
            findings=findings,
            metadata={
                "open_ports": ",".join(str(p) for p in open_ports),
                "risky_open": ",".join(str(p) for p in risky_open),
                "ports_scanned": len(ports),
                "open_count": len(open_ports),
            },
        )


async def _is_open(host: str, port: int, *, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    with contextlib.suppress(OSError, asyncio.TimeoutError):
        await writer.wait_closed()
    return reader is not None


def _severity_for_port(port: int) -> str:
    if port in (3389, 5900, 6379, 9200, 27017):
        return "high"
    if port in (21, 23, 3306, 5432, 1433):
        return "medium"
    return "low"
