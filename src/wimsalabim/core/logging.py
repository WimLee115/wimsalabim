"""Structured logging — JSON for machines, console for humans.

Honors the privacy doctrine: nothing leaves the machine via logging.
No log shipper, no sentry, no telemetry. Period.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, cast

import structlog

_CONFIGURED = False


def configure_logging(
    *,
    json_output: bool = False,
    verbose: bool = False,
    quiet: bool = False,
) -> None:
    """Idempotent. Safe to call from CLI entrypoint."""
    global _CONFIGURED  # noqa: PLW0603
    if _CONFIGURED:
        return

    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]

    if json_output:
        renderer: Any = structlog.processors.JSONRenderer(sort_keys=True)
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )

    # Quieten common chatty libs
    for noisy in ("httpx", "httpcore", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str = "wimsalabim") -> structlog.stdlib.BoundLogger:
    """Return a bound logger. Call ``configure_logging`` first."""
    return cast("structlog.stdlib.BoundLogger", structlog.get_logger(name))


__all__ = ["configure_logging", "get_logger"]
