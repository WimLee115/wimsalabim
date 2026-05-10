"""Base class & types for analyzers.

Every analyzer implements ``analyze(target, context) -> BaseReport``.
Concrete subclasses are registered via the ``@analyzer(...)`` decorator
in ``core.registry``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from wimsalabim.core.registry import Capabilities
from wimsalabim.core.schema import BaseReport, LegalClass


@dataclass(frozen=True)
class AnalysisContext:
    """Per-scan, per-analyzer environment.

    The orchestrator builds one of these and hands it to each analyzer.
    Analyzers MUST NOT instantiate ``httpx.AsyncClient`` themselves —
    they receive one (already privacy-guarded) here.
    """

    target: str
    """Normalized target (host/domain/IP) — lowercase, no scheme, no path."""

    http: httpx.AsyncClient
    """Shared async HTTP client. Outlives the analyzer, do not close."""

    via_tor: bool = False
    offline: bool = False
    show_pii: bool = False


class BaseAnalyzer(ABC):
    """Subclass and decorate with ``@analyzer(...)``.

    Class attributes set by the decorator:
        * name           — registry key (str)
        * legal_class    — LegalClass
        * capabilities   — Capabilities
    """

    # Set by ``@analyzer(...)`` decorator; declared here so mypy --strict
    # is happy with subclass instances accessing them.
    name: str = ""
    legal_class: LegalClass = "passive"
    capabilities: Capabilities = Capabilities()

    @abstractmethod
    async def analyze(self, context: AnalysisContext) -> BaseReport:
        """Run analysis. Must not raise; on failure return a minimal
        ``BaseReport`` and let findings convey the issue, OR raise
        ``AnalyzerError`` for the orchestrator to wrap.
        """


__all__ = ["AnalysisContext", "BaseAnalyzer"]
