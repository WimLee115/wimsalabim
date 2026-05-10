"""Logging configuration — idempotent, no telemetry shippers."""

from __future__ import annotations

from wimsalabim.core import logging as wl_logging


def test_get_logger_returns_bound_logger() -> None:
    log = wl_logging.get_logger("test")
    # structlog stdlib BoundLogger has .bind / .info / .warning
    assert hasattr(log, "bind")
    assert hasattr(log, "info")


def test_configure_logging_idempotent(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(wl_logging, "_CONFIGURED", False)
    wl_logging.configure_logging(verbose=True)
    assert wl_logging._CONFIGURED is True
    # Second call must not blow up.
    wl_logging.configure_logging(verbose=False)


def test_configure_logging_supports_json(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(wl_logging, "_CONFIGURED", False)
    wl_logging.configure_logging(json_output=True)


def test_configure_logging_quiet(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(wl_logging, "_CONFIGURED", False)
    wl_logging.configure_logging(quiet=True)
