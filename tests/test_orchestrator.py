"""Orchestrator end-to-end with fake analyzers (no network)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone

import pytest

from wimsalabim.analyzers.base import AnalysisContext, BaseAnalyzer
from wimsalabim.core import registry as registry_mod
from wimsalabim.core.authorization import AuthorizationGate
from wimsalabim.core.exceptions import AnalyzerError, NetworkError
from wimsalabim.core.orchestrator import Orchestrator, OrchestratorConfig
from wimsalabim.core.registry import (
    Capabilities,
    all_analyzers,
    analyzer,
    reset_registry_for_tests,
)
from wimsalabim.core.schema import Authorization, BaseReport


@pytest.fixture
def fresh_registry() -> Iterator[None]:
    snapshot = dict(registry_mod._REGISTRY)
    reset_registry_for_tests()
    try:
        yield
    finally:
        registry_mod._REGISTRY.clear()
        registry_mod._REGISTRY.update(snapshot)


def _now() -> datetime:
    return datetime(2026, 5, 10, 12, 0, 0, tzinfo=timezone.utc)


def _stub_report(name: str, target: str) -> BaseReport:
    return BaseReport(
        analyzer=name,
        target=target,
        started_at=_now(),
        duration_ms=1.0,
        grade="A",
        findings=[],
        metadata={"stub": True},
    )


@pytest.mark.asyncio
async def test_orchestrator_runs_passive_without_authz(fresh_registry: None) -> None:
    @analyzer("stub_passive", legal_class="passive", capabilities=Capabilities())
    class _StubPassive(BaseAnalyzer):
        async def analyze(self, context: AnalysisContext) -> BaseReport:
            return _stub_report("stub_passive", context.target)

    cfg = OrchestratorConfig(target="example.com", enabled=("stub_passive",))
    orch = Orchestrator(
        config=cfg,
        registrations=list(all_analyzers().values()),
        gate=AuthorizationGate(),
    )
    report = await orch.run()
    assert report.target == "example.com"
    assert report.analyzers["stub_passive"].status == "ok"
    assert report.analyzers["stub_passive"].report is not None
    assert report.analyzers["stub_passive"].report.grade == "A"


@pytest.mark.asyncio
async def test_active_denied_without_authz(fresh_registry: None) -> None:
    @analyzer("stub_active", legal_class="active", capabilities=Capabilities())
    class _StubActive(BaseAnalyzer):
        async def analyze(self, context: AnalysisContext) -> BaseReport:  # pragma: no cover
            return _stub_report("stub_active", context.target)

    cfg = OrchestratorConfig(target="example.com", enabled=("stub_active",))
    orch = Orchestrator(
        config=cfg,
        registrations=list(all_analyzers().values()),
        gate=AuthorizationGate(),
    )
    report = await orch.run()
    assert report.analyzers["stub_active"].status == "denied"
    assert "authorization" in (report.analyzers["stub_active"].skip_reason or "").lower()


@pytest.mark.asyncio
async def test_active_runs_with_matching_authz(fresh_registry: None) -> None:
    @analyzer("stub_active2", legal_class="active", capabilities=Capabilities())
    class _StubActive(BaseAnalyzer):
        async def analyze(self, context: AnalysisContext) -> BaseReport:
            return _stub_report("stub_active2", context.target)

    authz = Authorization(
        target="example.com",
        mode="self_owned",
        evidence="local",
        verified_at=_now(),
    )
    cfg = OrchestratorConfig(target="example.com", enabled=("stub_active2",))
    orch = Orchestrator(
        config=cfg,
        registrations=list(all_analyzers().values()),
        gate=AuthorizationGate(authorization=authz),
        authorization=authz,
    )
    report = await orch.run()
    assert report.analyzers["stub_active2"].status == "ok"
    assert report.authorization is authz


@pytest.mark.asyncio
async def test_analyzer_error_wrapped(fresh_registry: None) -> None:
    @analyzer("stub_err", legal_class="passive", capabilities=Capabilities())
    class _StubErr(BaseAnalyzer):
        async def analyze(self, context: AnalysisContext) -> BaseReport:
            raise AnalyzerError(analyzer="stub_err", message="boom")

    cfg = OrchestratorConfig(target="example.com", enabled=("stub_err",))
    orch = Orchestrator(
        config=cfg,
        registrations=list(all_analyzers().values()),
        gate=AuthorizationGate(),
    )
    report = await orch.run()
    res = report.analyzers["stub_err"]
    assert res.status == "error"
    assert res.error_kind == "analyzer"


@pytest.mark.asyncio
async def test_network_error_wrapped(fresh_registry: None) -> None:
    @analyzer("stub_net", legal_class="passive", capabilities=Capabilities())
    class _StubNet(BaseAnalyzer):
        async def analyze(self, context: AnalysisContext) -> BaseReport:
            raise NetworkError(kind="dns", target=context.target, message="resolver timeout")

    cfg = OrchestratorConfig(target="example.com", enabled=("stub_net",))
    orch = Orchestrator(
        config=cfg,
        registrations=list(all_analyzers().values()),
        gate=AuthorizationGate(),
    )
    report = await orch.run()
    res = report.analyzers["stub_net"]
    assert res.status == "error"
    assert res.error_kind == "network"


@pytest.mark.asyncio
async def test_config_hash_deterministic(fresh_registry: None) -> None:
    @analyzer("stub_h", legal_class="passive", capabilities=Capabilities())
    class _StubH(BaseAnalyzer):
        async def analyze(self, context: AnalysisContext) -> BaseReport:
            return _stub_report("stub_h", context.target)

    cfg = OrchestratorConfig(target="example.com", enabled=("stub_h",))
    orch = Orchestrator(
        config=cfg,
        registrations=list(all_analyzers().values()),
        gate=AuthorizationGate(),
    )
    a = await orch.run()
    b = await orch.run()
    assert a.config_hash == b.config_hash
    assert len(a.config_hash) == 64
