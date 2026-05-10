"""Display renderers — smoke + structural assertions."""

from __future__ import annotations

import json
from io import StringIO

from rich.console import Console

from wimsalabim.display import render_markdown, render_rich, render_sarif


def test_render_rich_runs(example_scan) -> None:  # type: ignore[no-untyped-def]
    out = StringIO()
    console = Console(file=out, width=120, force_terminal=False, no_color=True)
    render_rich(example_scan, console)
    text = out.getvalue()
    assert "wimsalabim" in text
    assert "example.com" in text
    assert "tls" in text


def test_render_markdown_structure(example_scan) -> None:  # type: ignore[no-untyped-def]
    md = render_markdown(example_scan)
    assert md.startswith("# wimsalabim scan ·")
    assert "## Analyzers" in md
    assert "`tls`" in md
    assert "schema" in md.lower()


def test_render_sarif_validates_minimum_shape(example_scan) -> None:  # type: ignore[no-untyped-def]
    sarif = render_sarif(example_scan)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].startswith("https://")
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "wimsalabim"
    assert run["properties"]["target"] == "example.com"


def test_render_sarif_serializable(example_scan) -> None:  # type: ignore[no-untyped-def]
    sarif = render_sarif(example_scan)
    serialized = json.dumps(sarif)
    assert "wimsalabim" in serialized


def test_render_markdown_empty_analyzers() -> None:
    from datetime import datetime, timezone

    from wimsalabim.core.schema import AnalyzerResult, ScanReport

    empty = ScanReport(
        tool_version="0.2.0",
        target="x.com",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        duration_ms=0.0,
        config_hash="0" * 64,
        analyzers={
            "skipped": AnalyzerResult(
                name="skipped",
                legal_class="passive",
                status="skipped",
                skip_reason="user disabled",
            ),
        },
    )
    md = render_markdown(empty)
    assert "skipped" in md
    assert "user disabled" in md


def test_render_sarif_with_findings_emits_rules_and_results(example_scan) -> None:  # type: ignore[no-untyped-def]
    sarif = render_sarif(example_scan)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    results = sarif["runs"][0]["results"]
    assert len(rules) >= 1
    assert len(results) >= 1
    # Critical TLS expiry → SARIF level "error"
    assert any(r["level"] == "error" for r in results)
