"""Rich-based terminal renderer.

Stylistic, but not chatty. Emits headers, finding tables, and a final
risk-assessment panel. Color is opt-out via ``--no-color`` upstream.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from wimsalabim.core.schema import (
    AnalyzerResult,
    Finding,
    RiskAssessment,
    ScanReport,
    Severity,
)

_GRADE_STYLE = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "bold yellow",
    "F": "bold red",
    "N/A": "dim",
}
_SEV_STYLE: dict[Severity, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def render_rich(report: ScanReport, console: Console | None = None) -> None:
    console = console or Console()
    console.print()
    console.rule(f"[bold cyan]wimsalabim · {report.target}", style="cyan")
    console.print(
        f"[dim]target[/dim] [bold]{report.target}[/bold]   "
        f"[dim]started[/dim] {report.started_at.isoformat()}   "
        f"[dim]duration[/dim] {report.duration_ms:.0f} ms"
    )
    if report.authorization:
        console.print(
            f"[dim]authorization[/dim] [green]✓[/green] {report.authorization.mode} "
            f"({report.authorization.evidence[:60]}…)"
        )
    console.print()

    for name, result in sorted(report.analyzers.items()):
        _render_analyzer(console, name, result)

    if report.risk:
        _render_risk(console, report.risk)


def _render_analyzer(console: Console, name: str, result: AnalyzerResult) -> None:
    rep = result.report
    if result.status != "ok" or rep is None:
        console.print(
            f"[bold]{name}[/bold] "
            f"[{_status_color(result.status)}]· {result.status}[/{_status_color(result.status)}]"
            + (
                f"  [dim]({result.skip_reason or result.error_message})[/dim]"
                if result.skip_reason or result.error_message
                else ""
            )
        )
        return

    style = _GRADE_STYLE.get(rep.grade, "white")
    header = Text.assemble(
        (f"{name}", "bold"),
        ("  grade ", "dim"),
        (rep.grade, style),
        (f"   {len(rep.findings)} finding(s)", "dim"),
        (f"   {rep.duration_ms:.0f} ms", "dim"),
    )
    console.print(header)

    if rep.findings:
        table = Table(show_header=True, header_style="bold", expand=False, padding=(0, 1))
        table.add_column("sev", width=8)
        table.add_column("id", style="cyan")
        table.add_column("title")
        for f in rep.findings:
            table.add_row(
                Text(f.severity, style=_SEV_STYLE.get(f.severity, "white")),
                f.id,
                f.title,
            )
        console.print(table)
    console.print()


def _render_risk(console: Console, risk: RiskAssessment) -> None:
    style = _GRADE_STYLE.get(risk.grade, "white")
    title = Text.assemble(
        ("RISK ", "bold"),
        (risk.grade, style),
        (f"   {risk.overall_score:.1f}/100", "dim"),
        (f"   engine={risk.engine}", "dim"),
    )
    body_lines = [risk.summary, ""]
    for hit in risk.rules_fired:
        body_lines.append(
            f"  [{_SEV_STYLE.get(hit.severity, 'white')}]●[/]  "
            f"[bold]{hit.rule_id}[/bold] [dim]+{hit.points:.0f}[/dim]  {hit.rule_name}"
        )
        body_lines.append(f"      [dim]→ {hit.rationale}[/dim]")

    console.print(Panel.fit("\n".join(body_lines), title=title, border_style=style))


def _status_color(status: str) -> str:
    return {
        "ok": "green",
        "skipped": "dim",
        "denied": "yellow",
        "error": "red",
    }.get(status, "white")


def _finding_one_liner(f: Finding) -> str:
    return f"{f.severity:8s} {f.id}  {f.title}"


__all__ = ["render_rich"]
