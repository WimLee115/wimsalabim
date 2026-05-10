"""Plugin registry for analyzers.

Analyzers register themselves via the ``@analyzer(...)`` decorator and are
discovered through ``all_analyzers()``. No magic entry-points — explicit
import in ``analyzers/__init__.py`` keeps the dependency graph readable.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeVar

from wimsalabim.core.schema import LegalClass

if TYPE_CHECKING:
    from wimsalabim.analyzers.base import BaseAnalyzer

T = TypeVar("T", bound="type[BaseAnalyzer]")


@dataclass(frozen=True)
class Capabilities:
    """What does an analyzer need to do its job?"""

    network: tuple[str, ...] = field(default_factory=tuple)
    """Network protocols used: 'dns', 'http', 'https', 'tcp', 'udp', 'tls'."""

    rate_limit_per_second: int = 10
    """Maximum outbound requests/sec this analyzer will issue."""

    timeout_seconds: float = 10.0
    """Soft per-call timeout; the orchestrator may enforce a budget."""


@dataclass(frozen=True)
class AnalyzerRegistration:
    name: str
    cls: type
    legal_class: LegalClass
    capabilities: Capabilities
    description: str


_REGISTRY: dict[str, AnalyzerRegistration] = {}


def analyzer(
    name: str,
    *,
    legal_class: LegalClass = "passive",
    capabilities: Capabilities | None = None,
    description: str = "",
) -> Callable[[T], T]:
    """Decorator — register an analyzer class."""

    def decorate(cls: T) -> T:
        if name in _REGISTRY:
            raise ValueError(f"Analyzer {name!r} is already registered")
        _REGISTRY[name] = AnalyzerRegistration(
            name=name,
            cls=cls,
            legal_class=legal_class,
            capabilities=capabilities or Capabilities(),
            description=description,
        )
        # Imprint the metadata onto the class so instances can see it.
        cls.name = name
        cls.legal_class = legal_class
        cls.capabilities = capabilities or Capabilities()
        return cls

    return decorate


def get_analyzer(name: str) -> AnalyzerRegistration:
    if name not in _REGISTRY:
        raise KeyError(f"Unknown analyzer: {name!r} (known: {sorted(_REGISTRY)})")
    return _REGISTRY[name]


def all_analyzers() -> dict[str, AnalyzerRegistration]:
    return dict(_REGISTRY)


def reset_registry_for_tests() -> None:
    """Test-only — never call from production code."""
    _REGISTRY.clear()


__all__ = [
    "AnalyzerRegistration",
    "Capabilities",
    "all_analyzers",
    "analyzer",
    "get_analyzer",
    "reset_registry_for_tests",
]
