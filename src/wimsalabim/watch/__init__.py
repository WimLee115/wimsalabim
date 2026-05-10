"""Watchlist daemon — baseline scans, detect drift over time."""

from __future__ import annotations

from wimsalabim.watch.baseline import BaselineStore, Diff

__all__ = ["BaselineStore", "Diff"]
