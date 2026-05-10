"""Async orchestrator — runs registered analyzers concurrently.

Responsibilities:
    1. Consult the AuthorizationGate before launching each analyzer.
    2. Construct the shared HTTP client and one ``AnalysisContext`` each.
    3. Apply per-analyzer timeouts and bubble errors as ``AnalyzerResult``.
    4. Compose the final ``ScanReport`` with a deterministic ``config_hash``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from wimsalabim import __version__
from wimsalabim.analyzers.base import AnalysisContext, BaseAnalyzer
from wimsalabim.core.authorization import AuthorizationDenied, AuthorizationGate
from wimsalabim.core.canonical import hash_obj
from wimsalabim.core.exceptions import AnalyzerError, NetworkError
from wimsalabim.core.http_client import make_client
from wimsalabim.core.logging import get_logger
from wimsalabim.core.registry import AnalyzerRegistration
from wimsalabim.core.schema import (
    AnalyzerResult,
    Authorization,
    ScanReport,
)

logger = get_logger(__name__)


@dataclass(frozen=True)
class OrchestratorConfig:
    target: str
    enabled: tuple[str, ...]
    via_tor: bool = False
    offline: bool = False
    show_pii: bool = False
    allow_intrusive: bool = False
    per_analyzer_timeout_s: float = 30.0


@dataclass
class _RunRecord:
    name: str
    legal_class: str
    result: AnalyzerResult


class Orchestrator:
    def __init__(
        self,
        *,
        config: OrchestratorConfig,
        registrations: Iterable[AnalyzerRegistration],
        gate: AuthorizationGate,
        authorization: Authorization | None = None,
    ) -> None:
        self._config = config
        self._registrations = list(registrations)
        self._gate = gate
        self._authorization = authorization

    async def run(self) -> ScanReport:
        started_at = datetime.now(tz=timezone.utc)
        async with make_client(via_tor=self._config.via_tor) as http:
            ctx = AnalysisContext(
                target=self._config.target,
                http=http,
                via_tor=self._config.via_tor,
                offline=self._config.offline,
                show_pii=self._config.show_pii,
            )

            tasks = [
                asyncio.create_task(self._run_one(reg, ctx), name=f"analyzer:{reg.name}")
                for reg in self._registrations
                if reg.name in self._config.enabled
            ]
            records: list[_RunRecord] = await asyncio.gather(*tasks)

        duration_ms = (datetime.now(tz=timezone.utc) - started_at).total_seconds() * 1000.0

        analyzers = {r.name: r.result for r in records}

        config_hash = hash_obj(
            {
                "target": self._config.target,
                "enabled": sorted(self._config.enabled),
                "via_tor": self._config.via_tor,
                "offline": self._config.offline,
                "allow_intrusive": self._config.allow_intrusive,
            }
        )

        return ScanReport(
            tool_version=__version__,
            target=self._config.target,
            started_at=started_at,
            duration_ms=duration_ms,
            config_hash=config_hash,
            authorization=self._authorization,
            analyzers=analyzers,
        )

    async def _run_one(
        self,
        reg: AnalyzerRegistration,
        ctx: AnalysisContext,
    ) -> _RunRecord:
        log = logger.bind(analyzer=reg.name, target=ctx.target)

        # --- Authorization gate ----------------------------------------
        try:
            self._gate.check(target=ctx.target, legal_class=reg.legal_class)
        except AuthorizationDenied as denied:
            log.info("denied", reason=str(denied))
            return _RunRecord(
                name=reg.name,
                legal_class=reg.legal_class,
                result=AnalyzerResult(
                    name=reg.name,
                    legal_class=reg.legal_class,
                    status="denied",
                    skip_reason=str(denied),
                ),
            )

        # --- Run with timeout ------------------------------------------
        instance: BaseAnalyzer = reg.cls()
        try:
            report = await asyncio.wait_for(
                instance.analyze(ctx),
                timeout=self._config.per_analyzer_timeout_s,
            )
        except asyncio.TimeoutError:
            log.warning("timeout")
            return _RunRecord(
                name=reg.name,
                legal_class=reg.legal_class,
                result=AnalyzerResult(
                    name=reg.name,
                    legal_class=reg.legal_class,
                    status="error",
                    error_kind="timeout",
                    error_message=f"exceeded {self._config.per_analyzer_timeout_s}s",
                ),
            )
        except NetworkError as exc:
            log.warning("network_error", error=str(exc))
            return _RunRecord(
                name=reg.name,
                legal_class=reg.legal_class,
                result=AnalyzerResult(
                    name=reg.name,
                    legal_class=reg.legal_class,
                    status="error",
                    error_kind="network",
                    error_message=str(exc),
                ),
            )
        except AnalyzerError as exc:
            log.warning("analyzer_error", error=str(exc))
            return _RunRecord(
                name=reg.name,
                legal_class=reg.legal_class,
                result=AnalyzerResult(
                    name=reg.name,
                    legal_class=reg.legal_class,
                    status="error",
                    error_kind="analyzer",
                    error_message=str(exc),
                ),
            )

        log.info("ok", findings=len(report.findings), grade=report.grade)
        return _RunRecord(
            name=reg.name,
            legal_class=reg.legal_class,
            result=AnalyzerResult(
                name=reg.name,
                legal_class=reg.legal_class,
                status="ok",
                report=report,
            ),
        )


__all__ = ["Orchestrator", "OrchestratorConfig"]
