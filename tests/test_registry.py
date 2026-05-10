"""Registry & decorator behaviour."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from wimsalabim.analyzers.base import AnalysisContext, BaseAnalyzer
from wimsalabim.core import registry as registry_mod
from wimsalabim.core.registry import (
    Capabilities,
    all_analyzers,
    analyzer,
    get_analyzer,
)
from wimsalabim.core.schema import BaseReport


@pytest.fixture
def isolated_registry() -> Iterator[None]:
    """Snapshot the global registry, run the test against an empty one,
    restore the snapshot on teardown.
    """
    snapshot = dict(registry_mod._REGISTRY)
    registry_mod._REGISTRY.clear()
    try:
        yield
    finally:
        registry_mod._REGISTRY.clear()
        registry_mod._REGISTRY.update(snapshot)


def test_analyzer_decorator_registers(isolated_registry: None) -> None:
    @analyzer(
        "fake_one",
        legal_class="passive",
        capabilities=Capabilities(network=("dns",)),
        description="for tests",
    )
    class FakeAnalyzer(BaseAnalyzer):
        async def analyze(self, context: AnalysisContext) -> BaseReport:  # pragma: no cover
            raise NotImplementedError

    reg = get_analyzer("fake_one")
    assert reg.cls is FakeAnalyzer
    assert reg.legal_class == "passive"
    assert reg.capabilities.network == ("dns",)
    assert FakeAnalyzer.name == "fake_one"


def test_double_register_raises(isolated_registry: None) -> None:
    @analyzer("dup")
    class _A(BaseAnalyzer):
        async def analyze(self, context: AnalysisContext) -> BaseReport:  # pragma: no cover
            raise NotImplementedError

    with pytest.raises(ValueError, match="already registered"):

        @analyzer("dup")
        class _B(BaseAnalyzer):
            async def analyze(self, context: AnalysisContext) -> BaseReport:  # pragma: no cover
                raise NotImplementedError


def test_get_unknown_raises() -> None:
    with pytest.raises(KeyError):
        get_analyzer("does_not_exist_xyz")


def test_built_in_analyzers_present() -> None:
    names = set(all_analyzers().keys())
    assert {"dns_recon", "tls", "headers", "ports"} <= names


def test_legal_classes_well_formed() -> None:
    for reg in all_analyzers().values():
        assert reg.legal_class in ("passive", "active", "intrusive")
