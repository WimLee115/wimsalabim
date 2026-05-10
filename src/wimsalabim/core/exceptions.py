"""Typed exception hierarchy.

Replaces the old ``except Exception:`` swamp. Every failure mode has a name,
so callers can branch on intent instead of pattern-matching strings.
"""

from __future__ import annotations


class WimsalabimError(Exception):
    """Base for every error raised by this package."""


class AnalyzerError(WimsalabimError):
    """An analyzer hit a fatal, in-scope problem (bad input, parse failure)."""

    def __init__(self, analyzer: str, message: str) -> None:
        super().__init__(f"[{analyzer}] {message}")
        self.analyzer = analyzer
        self.message = message


class AnalyzerTimeout(AnalyzerError):
    """Analyzer exceeded its time budget."""


class NetworkError(WimsalabimError):
    """A networking primitive (DNS, TCP, TLS, HTTP) failed.

    Caller decides whether to retry, downgrade, or skip — never silently
    swallow.
    """

    def __init__(self, kind: str, target: str, message: str) -> None:
        super().__init__(f"[{kind}] {target}: {message}")
        self.kind = kind
        self.target = target
        self.message = message


class ConfigError(WimsalabimError):
    """User-supplied configuration is invalid (bad target, port list, etc.)."""


__all__ = [
    "AnalyzerError",
    "AnalyzerTimeout",
    "ConfigError",
    "NetworkError",
    "WimsalabimError",
]
