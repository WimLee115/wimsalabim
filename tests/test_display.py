"""Tests for Wimsalabim display module. rootmap:WimLee115"""

from __future__ import annotations

import pytest


class TestDisplay:
    def test_watermark_present(self):
        from wimsalabim.display import WATERMARK
        assert WATERMARK == "rootmap:WimLee115"

    def test_banner_defined(self):
        from wimsalabim.display import BANNER
        assert "___" in BANNER  # ASCII art contains underscores

    def test_grade_colors_complete(self):
        from wimsalabim.display import GRADE_COLORS
        for grade in ("A", "B", "C", "D", "F", "N/A"):
            assert grade in GRADE_COLORS

    def test_risk_colors_complete(self):
        from wimsalabim.display import RISK_COLORS
        for risk in ("critical", "high", "medium", "low", "info"):
            assert risk in RISK_COLORS

    def test_bool_icon(self):
        from wimsalabim.display import _bool_icon
        assert "OK" in _bool_icon(True)
        assert "FAIL" in _bool_icon(False)
        assert "FAIL" in _bool_icon(True, invert=True)

    def test_days_style(self):
        from wimsalabim.display import _days_style
        assert "EXPIRED" in _days_style(-5)
        assert "yellow" in _days_style(15)
        assert "green" in _days_style(100)

    def test_mini_bar(self):
        from wimsalabim.display import _mini_bar
        bar = _mini_bar(0.5)
        assert "50%" in bar

    def test_mini_bar_boundaries(self):
        from wimsalabim.display import _mini_bar
        assert "0%" in _mini_bar(0.0)
        assert "100%" in _mini_bar(1.0)
        assert "100%" in _mini_bar(1.5)  # clamped

    def test_render_risk_bar(self):
        from wimsalabim.display import _render_risk_bar
        bar = _render_risk_bar(0.85)
        assert "85%" in bar

    def test_render_score_badge(self):
        from wimsalabim.display import _render_score_badge
        badge = _render_score_badge(85.0, "A")
        assert "85" in badge.plain
        assert "A" in badge.plain


class TestCLI:
    def test_version_import(self):
        from wimsalabim import __version__
        assert __version__ == "0.1.0"

    def test_cli_import(self):
        from wimsalabim.cli import main
        assert callable(main)

    def test_noop_context(self):
        from wimsalabim.cli import _noop_context
        with _noop_context():
            pass

    def test_grade_to_float(self):
        from wimsalabim.cli import _grade_to_float
        assert _grade_to_float("A") == 0.95
        assert _grade_to_float("F") == 0.15
        assert _grade_to_float("N/A") == 0.5
        assert _grade_to_float("unknown") == 0.5
