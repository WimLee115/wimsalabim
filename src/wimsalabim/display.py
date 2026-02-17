"""Rich-powered beautiful terminal output for Wimsalabim. rootmap:WimLee115"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.tree import Tree
from rich import box

console = Console()

BANNER = r"""
 __        ___                       _       _     _
 \ \      / (_)_ __ ___  ___  __ _| | __ _| |__ (_)_ __ ___
  \ \ /\ / /| | '_ ` _ \/ __|/ _` | |/ _` | '_ \| | '_ ` _ \
   \ V  V / | | | | | | \__ \ (_| | | (_| | |_) | | | | | | |
    \_/\_/  |_|_| |_| |_|___/\__,_|_|\__,_|_.__/|_|_| |_| |_|
"""

GRADE_COLORS = {
    "A": "bold green", "B": "bold blue", "C": "bold yellow",
    "D": "bold dark_orange", "F": "bold red", "N/A": "dim",
}

RISK_COLORS = {
    "critical": "bold red", "high": "bold dark_orange",
    "medium": "bold yellow", "low": "bold green", "info": "dim",
    "CRITICAL": "bold red", "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow", "LOW": "bold green", "MINIMAL": "bold green",
}

WATERMARK = "rootmap:WimLee115"


def print_banner(target: str) -> None:
    banner_text = Text(BANNER, style="bold cyan")
    console.print(banner_text)
    console.print(
        f"  [dim]{WATERMARK}[/dim]  [bold white]Target:[/bold white] [bold cyan]{target}[/bold cyan]"
    )
    console.print()


def print_ports(report) -> None:
    if not report.ip_address:
        console.print(Panel("[red]Could not resolve target[/red]", title="Port Scan", border_style="red"))
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Port", style="bold white", width=8)
    table.add_column("State", width=8)
    table.add_column("Service", style="bold", width=16)
    table.add_column("Risk", width=10)
    table.add_column("Banner", style="dim", max_width=40)

    for p in report.open_ports:
        risk_style = RISK_COLORS.get(p.risk, "white")
        table.add_row(
            str(p.port),
            "[green]open[/green]",
            p.service,
            f"[{risk_style}]{p.risk.upper()}[/{risk_style}]",
            p.banner[:40] if p.banner else "",
        )

    summary = (
        f"[bold white]IP:[/bold white] {report.ip_address}  "
        f"[bold green]Open:[/bold green] {report.open_count}  "
        f"[bold red]Risky:[/bold red] {len(report.risky_ports)}  "
        f"[dim]Closed:[/dim] {report.closed_count}  "
        f"[dim]Scan: {report.scan_time}s[/dim]"
    )

    panel = Panel(
        table if report.open_ports else "[green]No open ports found[/green]",
        title="[bold white]Port Scan[/bold white]",
        subtitle=summary,
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_tls(report) -> None:
    grade_style = GRADE_COLORS.get(report.grade, "white")

    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold white", width=22)
    table.add_column("Value")

    if not report.available:
        console.print(Panel("[yellow]TLS/SSL not available[/yellow]", title="TLS/SSL", border_style="yellow"))
        return

    table.add_row("Protocol", report.protocol_version)
    table.add_row("Cipher Suite", report.cipher_suite)
    table.add_row("Key Bits", str(report.cipher_bits))
    table.add_row("TLS 1.3 Support", _bool_icon(report.supports_tls13))
    table.add_row("Subject CN", report.subject.get("commonName", "N/A"))
    table.add_row("Issuer", report.issuer.get("organizationName", report.issuer.get("commonName", "N/A")))
    table.add_row("Valid Until", report.not_after)
    table.add_row("Days Until Expiry", _days_style(report.days_until_expiry))
    table.add_row("Self-Signed", _bool_icon(not report.self_signed, invert=True))
    table.add_row("SAN Domains", str(len(report.san_domains)))

    if report.issues:
        table.add_row("", "")
        for issue in report.issues:
            table.add_row("[red]Issue[/red]", f"[yellow]{issue}[/yellow]")

    panel = Panel(
        table,
        title=f"[bold white]TLS/SSL Analysis[/bold white]  [{grade_style}]Grade: {report.grade}[/{grade_style}]",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_headers(report) -> None:
    if not report.available:
        console.print(Panel("[yellow]HTTP not reachable[/yellow]", title="HTTP Headers", border_style="yellow"))
        return

    grade_style = GRADE_COLORS.get(report.grade, "white")

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Header", style="bold white", width=32)
    table.add_column("Status", width=8)
    table.add_column("Value", max_width=50, style="dim")

    for h in report.headers_present:
        table.add_row(h.name, "[green]Present[/green]", h.value[:50])
    for h in report.headers_missing:
        table.add_row(h.name, "[red]Missing[/red]", h.description)

    extras = []
    if report.info_leaks:
        leak_parts = [f"[yellow]{k}: {v}[/yellow]" for k, v in report.info_leaks.items()]
        extras.append(Text.from_markup(f"\n[bold red]Info Leaks:[/bold red] {', '.join(leak_parts)}"))

    from rich.console import Group
    content = Group(table, *extras) if extras else table

    panel = Panel(
        content,
        title=f"[bold white]HTTP Security Headers[/bold white]  [{grade_style}]Grade: {report.grade}[/{grade_style}]",
        subtitle=f"[bold]{report.present_count}[/bold] present / [bold]{report.missing_count}[/bold] missing  |  HTTPS redirect: {_bool_icon(report.https_redirect)}",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_dns(report) -> None:
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Type", style="bold white", width=8)
    table.add_column("Value", max_width=60)
    table.add_column("TTL", style="dim", width=8)

    for rtype, records in report.records.items():
        for i, rec in enumerate(records):
            table.add_row(
                rtype if i == 0 else "",
                rec.value[:60],
                str(rec.ttl),
            )

    extras = []
    if report.zone_transfer_possible:
        extras.append(f"[bold red]ZONE TRANSFER POSSIBLE via: {', '.join(report.zone_transfer_ns)}[/bold red]")
    extras.append(f"DNSSEC: {_bool_icon(report.dnssec_enabled)}")

    if report.interesting_txt:
        extras.append(f"\n[bold]Interesting TXT:[/bold] {len(report.interesting_txt)} found")

    from rich.console import Group
    content = Group(table, Text.from_markup("\n".join(extras))) if extras else table

    panel = Panel(
        content,
        title=f"[bold white]DNS Reconnaissance[/bold white]",
        subtitle=f"[bold]{report.total_records}[/bold] records | [bold]{len(report.record_types_found)}[/bold] types",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_email(report) -> None:
    grade_style = GRADE_COLORS.get(report.grade, "white")

    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold white", width=22)
    table.add_column("Value")

    table.add_row("MX Records", _bool_icon(report.has_mx))
    table.add_row("SPF", f"{_bool_icon(report.spf.found)}  [{GRADE_COLORS.get(report.spf.grade, 'white')}]{report.spf.grade}[/{GRADE_COLORS.get(report.spf.grade, 'white')}]")
    if report.spf.found:
        table.add_row("  Qualifier", report.spf.all_qualifier or "N/A")
    table.add_row("DMARC", f"{_bool_icon(report.dmarc.found)}  [{GRADE_COLORS.get(report.dmarc.grade, 'white')}]{report.dmarc.grade}[/{GRADE_COLORS.get(report.dmarc.grade, 'white')}]")
    if report.dmarc.found:
        table.add_row("  Policy", report.dmarc.policy or "N/A")
    table.add_row("DKIM", f"{_bool_icon(report.dkim.found)}  [{GRADE_COLORS.get(report.dkim.grade, 'white')}]{report.dkim.grade}[/{GRADE_COLORS.get(report.dkim.grade, 'white')}]")
    if report.dkim.selectors_found:
        table.add_row("  Selectors", ", ".join(report.dkim.selectors_found))

    if report.issues:
        table.add_row("", "")
        for issue in report.issues:
            table.add_row("[yellow]Issue[/yellow]", f"[yellow]{issue}[/yellow]")

    panel = Panel(
        table,
        title=f"[bold white]Email Security[/bold white]  [{grade_style}]Grade: {report.grade}[/{grade_style}]",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_tech(report) -> None:
    if not report.available:
        console.print(Panel("[yellow]Could not reach target[/yellow]", title="Technology", border_style="yellow"))
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Technology", style="bold white", width=24)
    table.add_column("Category", width=16)
    table.add_column("Version", style="dim", width=12)
    table.add_column("Confidence", width=12)

    for tech in report.technologies:
        conf_style = "green" if tech.confidence >= 0.8 else "yellow"
        table.add_row(
            tech.name,
            tech.category,
            tech.version or "-",
            f"[{conf_style}]{tech.confidence:.0%}[/{conf_style}]",
        )

    panel = Panel(
        table,
        title=f"[bold white]Technology Fingerprint[/bold white]",
        subtitle=f"[bold]{report.tech_count}[/bold] technologies detected",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_whois(report) -> None:
    if not report.available:
        console.print(Panel("[yellow]WHOIS data unavailable[/yellow]", title="WHOIS", border_style="yellow"))
        return

    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold white", width=22)
    table.add_column("Value")

    table.add_row("Domain", report.domain_name)
    table.add_row("Registrar", report.registrar)
    table.add_row("Created", report.creation_date)
    table.add_row("Expires", report.expiration_date)
    table.add_row("Domain Age", f"{report.domain_age_days} days")
    table.add_row("Name Servers", ", ".join(report.name_servers[:4]))
    table.add_row("Privacy Protected", _bool_icon(report.privacy_protected))
    if report.registrant_country:
        table.add_row("Country", report.registrant_country)
    if report.dnssec:
        table.add_row("DNSSEC", report.dnssec)

    panel = Panel(
        table,
        title="[bold white]WHOIS Information[/bold white]",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_subdomains(report) -> None:
    if report.found_count == 0:
        console.print(Panel("[dim]No subdomains discovered[/dim]", title="Subdomains", border_style="dim"))
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Hostname", style="bold white", width=35)
    table.add_column("IP", width=16)
    table.add_column("HTTPS", width=6)
    table.add_column("HTTP", style="dim", width=6)

    for sub in report.subdomains_found[:25]:
        table.add_row(
            sub.hostname,
            sub.ip_address,
            _bool_icon(sub.https_available),
            str(sub.http_status) if sub.http_status else "-",
        )

    panel = Panel(
        table,
        title="[bold white]Subdomain Discovery[/bold white]",
        subtitle=f"[bold]{report.found_count}[/bold] found | {report.subdomains_checked} checked | crt.sh: {len(report.crt_sh_results)}",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)

    if report.issues:
        for issue in report.issues:
            console.print(f"  [bold yellow]![/bold yellow] {issue}")


def print_waf(report) -> None:
    if report.detected:
        content = (
            f"[bold green]WAF Detected:[/bold green] [bold]{report.waf_name}[/bold]\n"
            f"[dim]Confidence:[/dim] {report.confidence:.0%}\n"
            f"[dim]Evidence:[/dim] {', '.join(report.evidence[:3])}"
        )
        style = "green"
    else:
        content = "[bold yellow]No WAF detected[/bold yellow]\n[dim]Target may be directly exposed to web attacks[/dim]"
        style = "yellow"

    panel = Panel(content, title="[bold white]WAF Detection[/bold white]", border_style=style, box=box.ROUNDED)
    console.print(panel)


def print_directories(report) -> None:
    if report.found_count == 0:
        console.print(Panel("[dim]No interesting paths found[/dim]", title="Directory Scan", border_style="dim"))
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Path", style="bold white", width=35)
    table.add_column("Status", width=8)
    table.add_column("Risk", width=10)
    table.add_column("Description", style="dim", max_width=30)

    for p in report.found_paths:
        risk_style = RISK_COLORS.get(p.risk, "white")
        status_style = "green" if p.status_code == 200 else "yellow" if p.status_code in (301, 302) else "red"
        table.add_row(
            p.path,
            f"[{status_style}]{p.status_code}[/{status_style}]",
            f"[{risk_style}]{p.risk.upper()}[/{risk_style}]",
            p.description,
        )

    panel = Panel(
        table,
        title="[bold white]Directory & Path Scan[/bold white]",
        subtitle=f"[bold]{report.found_count}[/bold] found | [bold red]{report.sensitive_count}[/bold red] sensitive | {report.paths_checked} checked",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_cors(report) -> None:
    if not report.available:
        console.print(Panel("[dim]CORS check unavailable[/dim]", title="CORS", border_style="dim"))
        return

    grade_style = GRADE_COLORS.get(report.grade, "white")

    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold white", width=22)
    table.add_column("Value")

    table.add_row("CORS Enabled", _bool_icon(report.cors_enabled))
    table.add_row("Allow-Origin", report.allow_origin or "Not set")
    table.add_row("Wildcard Origin", _bool_icon(not report.wildcard_origin, invert=True))
    table.add_row("Reflects Origin", _bool_icon(not report.reflects_origin, invert=True))
    table.add_row("Null Origin", _bool_icon(not report.null_origin_allowed, invert=True))
    table.add_row("Credentials", _bool_icon(not report.allow_credentials, invert=True))

    if report.issues:
        table.add_row("", "")
        for issue in report.issues:
            table.add_row("[red]Issue[/red]", f"[yellow]{issue}[/yellow]")

    panel = Panel(
        table,
        title=f"[bold white]CORS Analysis[/bold white]  [{grade_style}]Grade: {report.grade}[/{grade_style}]",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_cookies(report) -> None:
    if not report.available or report.total_cookies == 0:
        console.print(Panel("[dim]No cookies found[/dim]", title="Cookies", border_style="dim"))
        return

    grade_style = GRADE_COLORS.get(report.grade, "white")

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Cookie", style="bold white", width=24)
    table.add_column("Secure", width=8)
    table.add_column("HttpOnly", width=10)
    table.add_column("SameSite", width=10)
    table.add_column("Issues", style="dim", max_width=30)

    for c in report.cookies[:15]:
        table.add_row(
            c.name[:24],
            _bool_icon(c.secure),
            _bool_icon(c.httponly),
            c.samesite or "[red]None[/red]",
            str(len(c.issues)) + " issues" if c.issues else "[green]OK[/green]",
        )

    panel = Panel(
        table,
        title=f"[bold white]Cookie Security[/bold white]  [{grade_style}]Grade: {report.grade}[/{grade_style}]",
        subtitle=f"[bold]{report.total_cookies}[/bold] cookies | Session: {len(report.session_cookies)} | Tracking: {len(report.tracking_cookies)}",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_cloud(report) -> None:
    if not report.is_cloud_hosted and not report.services_detected:
        console.print(Panel("[dim]No cloud services detected[/dim]", title="Cloud", border_style="dim"))
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Provider", style="bold white", width=16)
    table.add_column("Service", width=20)
    table.add_column("Evidence", style="dim", max_width=40)

    for svc in report.services_detected:
        table.add_row(svc.provider, svc.service, svc.evidence)

    extras = []
    if report.storage_exposed:
        for s in report.storage_exposed:
            extras.append(f"  [bold yellow]![/bold yellow] {s}")

    from rich.console import Group
    parts = [table]
    if extras:
        parts.append(Text.from_markup("\n".join(extras)))
    content = Group(*parts) if len(parts) > 1 else table

    panel = Panel(
        content,
        title=f"[bold white]Cloud Infrastructure[/bold white]",
        subtitle=f"Provider: [bold]{report.cloud_provider or 'Unknown'}[/bold] | {report.service_count} services",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_cve(report) -> None:
    if report.total_cves == 0:
        console.print(Panel("[green]No known CVEs found for detected services[/green]", title="CVE Lookup", border_style="green"))
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("CVE ID", style="bold white", width=18)
    table.add_column("Severity", width=10)
    table.add_column("Score", width=6)
    table.add_column("Product", width=14)
    table.add_column("Description", style="dim", max_width=40)

    for cve in report.vulnerabilities[:15]:
        sev_style = RISK_COLORS.get(cve.severity, "white")
        table.add_row(
            cve.cve_id,
            f"[{sev_style}]{cve.severity}[/{sev_style}]",
            f"{cve.score:.1f}",
            cve.affected_product,
            cve.description[:40],
        )

    panel = Panel(
        table,
        title="[bold white]CVE Vulnerabilities[/bold white]",
        subtitle=(
            f"[bold red]{report.critical_count}[/bold red] critical | "
            f"[bold dark_orange]{report.high_count}[/bold dark_orange] high | "
            f"[bold yellow]{report.medium_count}[/bold yellow] medium | "
            f"{report.low_count} low"
        ),
        border_style="red" if report.critical_count > 0 else "cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_anomalies(report) -> None:
    if report.anomaly_count == 0:
        console.print(Panel("[green]No anomalies detected[/green]", title="ML Anomaly Detection", border_style="green"))
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
    table.add_column("Category", style="bold white", width=22)
    table.add_column("Severity", width=10)
    table.add_column("Score", width=8)
    table.add_column("Description", max_width=45)

    for a in report.anomalies:
        sev_style = RISK_COLORS.get(a.severity, "white")
        table.add_row(
            a.category,
            f"[{sev_style}]{a.severity.upper()}[/{sev_style}]",
            f"{a.score:.2f}",
            a.description,
        )

    panel = Panel(
        table,
        title=f"[bold white]ML Anomaly Detection[/bold white]  [bold magenta]Score: {report.anomaly_score:.2f}[/bold magenta]",
        subtitle=f"{report.total_features_analyzed} features analyzed | {report.anomaly_count} anomalies",
        border_style="magenta",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_threats(report) -> None:
    if report.threat_count == 0:
        console.print(Panel("[green]No significant threats identified[/green]", title="Threat Classification", border_style="green"))
        return

    tree = Tree("[bold white]Threat Vectors[/bold white]")

    for threat in report.threats:
        impact_style = RISK_COLORS.get(threat.impact, "white")
        branch = tree.add(
            f"[{impact_style}]{threat.impact.upper()}[/{impact_style}] "
            f"[bold]{threat.name}[/bold] [dim]({threat.category})[/dim] "
            f"[cyan]likelihood: {threat.likelihood:.0%}[/cyan]"
        )
        branch.add(f"[dim]{threat.description}[/dim]")
        if threat.mitigations:
            mit_branch = branch.add("[bold green]Mitigations:[/bold green]")
            for mit in threat.mitigations[:3]:
                mit_branch.add(f"[green]{mit}[/green]")

    panel = Panel(
        tree,
        title=f"[bold white]AI Threat Classification[/bold white]  [dim]Model: {report.threat_model}[/dim]",
        subtitle=f"Attack Surface: [bold]{report.attack_surface_score:.0%}[/bold] | Primary Risk: [bold]{report.primary_risk_category}[/bold]",
        border_style="magenta",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_risk_assessment(assessment) -> None:
    risk_style = RISK_COLORS.get(assessment.risk_label, "white")

    score_bar = _render_risk_bar(assessment.overall_risk)

    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold white", width=22)
    table.add_column("Value")

    table.add_row("Risk Score", score_bar)
    table.add_row("Risk Level", f"[{risk_style}]{assessment.risk_label}[/{risk_style}]")
    table.add_row("Confidence", f"{assessment.confidence:.0%}")
    table.add_row("Model", assessment.model_info.get("ensemble", "N/A"))
    table.add_row("", "")

    for category, score in assessment.risk_breakdown.items():
        bar = _mini_bar(score)
        table.add_row(category, bar)

    from rich.console import Group
    parts = [table]

    if assessment.executive_summary:
        parts.append(Text(""))
        parts.append(Text.from_markup(f"[bold]Executive Summary:[/bold] {assessment.executive_summary}"))

    if assessment.recommendations:
        parts.append(Text(""))
        rec_table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        rec_table.add_column("#", width=3)
        rec_table.add_column("Recommendation", style="bold", width=30)
        rec_table.add_column("Impact", width=10)
        rec_table.add_column("Effort", width=10)

        for rec in assessment.recommendations[:8]:
            impact_style = RISK_COLORS.get(rec.impact, "white")
            rec_table.add_row(
                str(rec.priority),
                rec.title,
                f"[{impact_style}]{rec.impact.upper()}[/{impact_style}]",
                rec.effort,
            )
        parts.append(rec_table)

    content = Group(*parts)

    panel = Panel(
        content,
        title=f"[bold white]AI Risk Assessment[/bold white]  [{risk_style}]{assessment.risk_label} ({assessment.overall_risk:.0%})[/{risk_style}]",
        border_style="magenta",
        box=box.DOUBLE,
    )
    console.print(panel)


def print_scoring(report) -> None:
    grade_style = GRADE_COLORS.get(report.overall_grade, "white")

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Category", style="bold white", width=18)
    table.add_column("Score", width=8)
    table.add_column("Grade", width=8)
    table.add_column("Bar", width=22)
    table.add_column("Issues", style="dim", width=8)

    for cat in report.categories:
        cat_grade_style = GRADE_COLORS.get(cat.grade, "white")
        bar = _mini_bar(cat.percentage / 100)
        table.add_row(
            cat.name,
            f"{cat.score}%",
            f"[{cat_grade_style}]{cat.grade}[/{cat_grade_style}]",
            bar,
            str(len(cat.issues)) if cat.issues else "-",
        )

    score_display = _render_score_badge(report.overall_score, report.overall_grade)

    from rich.console import Group
    content = Group(score_display, Text(""), table)

    panel = Panel(
        content,
        title=f"[bold white]Overall Security Score[/bold white]",
        subtitle=f"Risk Level: [{RISK_COLORS.get(report.risk_level.lower(), 'white')}]{report.risk_level}[/{RISK_COLORS.get(report.risk_level.lower(), 'white')}] | {report.total_issues} issues ({report.critical_issues} critical)",
        border_style=grade_style.replace("bold ", ""),
        box=box.DOUBLE,
    )
    console.print(panel)


def print_network(report) -> None:
    if not report.available:
        console.print(Panel("[yellow]Network analysis unavailable[/yellow]", title="Network", border_style="yellow"))
        return

    grade_style = GRADE_COLORS.get(report.grade, "white")
    lat = report.latency

    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold white", width=28)
    table.add_column("Value")

    quality_colors = {"excellent": "green", "good": "blue", "fair": "yellow", "poor": "red"}
    q_color = quality_colors.get(lat.quality, "white")

    table.add_row("Latency (avg/min/max)", f"{lat.avg_ms}ms / {lat.min_ms}ms / {lat.max_ms}ms")
    table.add_row("Median Latency", f"{lat.median_ms}ms")
    table.add_row("Jitter", f"{lat.jitter_ms}ms")
    table.add_row("Packet Loss", f"{lat.packet_loss_pct}%" if lat.packet_loss_pct > 0 else "[green]0%[/green]")
    table.add_row("Connection Quality", f"[{q_color}]{lat.quality.upper()}[/{q_color}]")
    table.add_row("", "")

    bw = report.bandwidth
    if bw.download_estimate_mbps > 0:
        table.add_row("Bandwidth Estimate", f"{bw.download_estimate_mbps} Mbps")
        table.add_row("Transfer Time", f"{bw.transfer_time_ms}ms")

    stab = report.stability
    stab_color = "green" if stab.stable else "yellow"
    table.add_row("Stability Score", f"[{stab_color}]{stab.score:.0%}[/{stab_color}]")
    table.add_row("Stability Trend", stab.trend)
    table.add_row("", "")

    cong = report.congestion
    cong_color = RISK_COLORS.get(cong.risk_level, "white")
    table.add_row("Congestion Risk", f"[{cong_color}]{cong.risk_level.upper()}[/{cong_color}]")
    table.add_row("Congestion Score", f"{cong.congestion_score:.0%}")
    if cong.predicted_degradation_pct > 0:
        table.add_row("Predicted Degradation", f"{cong.predicted_degradation_pct}%")

    if report.issues:
        table.add_row("", "")
        for issue in report.issues:
            table.add_row("[yellow]Issue[/yellow]", f"[yellow]{issue}[/yellow]")

    panel = Panel(
        table,
        title=f"[bold white]Network Analysis[/bold white]  [{grade_style}]Grade: {report.grade}[/{grade_style}]",
        subtitle=f"Latency: {lat.avg_ms}ms | Jitter: {lat.jitter_ms}ms | Loss: {lat.packet_loss_pct}% | Quality: [{q_color}]{lat.quality}[/{q_color}]",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_leaks(report) -> None:
    grade_style = GRADE_COLORS.get(report.grade, "white")

    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold white", width=28)
    table.add_column("Value")

    dns = report.dns_leak
    dns_style = GRADE_COLORS.get(dns.grade, "white")
    table.add_row("DNS Leak Detection", f"[{dns_style}]{dns.grade}[/{dns_style}]  {'[red]LEAK[/red]' if dns.leak_detected else '[green]CLEAN[/green]'}")

    ip = report.ip_leak
    ip_style = GRADE_COLORS.get(ip.grade, "white")
    table.add_row("IP Leak Prevention", f"[{ip_style}]{ip.grade}[/{ip_style}]  {'[red]EXPOSED[/red]' if ip.headers_expose_ip else '[green]PROTECTED[/green]'}")
    if ip.exposed_ips:
        table.add_row("  Exposed IPs", ", ".join(ip.exposed_ips[:5]))

    webrtc = report.webrtc_leak
    webrtc_style = GRADE_COLORS.get(webrtc.grade, "white")
    table.add_row("WebRTC Leak Guard", f"[{webrtc_style}]{webrtc.grade}[/{webrtc_style}]  CSP: {_bool_icon(webrtc.csp_blocks_webrtc)} | PermPolicy: {_bool_icon(webrtc.permissions_policy_blocks)}")

    fw = report.firewall_audit
    fw_style = GRADE_COLORS.get(fw.grade, "white")
    table.add_row("Firewall Audit", f"[{fw_style}]{fw.grade}[/{fw_style}]  Rate Limit: {_bool_icon(fw.rate_limiting_detected)}")
    if fw.unnecessary_services:
        table.add_row("  Exposed Services", ", ".join(fw.unnecessary_services[:5]))

    if report.issues:
        table.add_row("", "")
        for issue in report.issues[:5]:
            table.add_row("[yellow]Issue[/yellow]", f"[yellow]{issue}[/yellow]")

    panel = Panel(
        table,
        title=f"[bold white]Leak Detection & Firewall Audit[/bold white]  [{grade_style}]Grade: {report.grade}[/{grade_style}]",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_performance(report) -> None:
    if not report.available:
        console.print(Panel("[yellow]Performance analysis unavailable[/yellow]", title="Performance", border_style="yellow"))
        return

    grade_style = GRADE_COLORS.get(report.grade, "white")

    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold white", width=28)
    table.add_column("Value")

    enc = report.encryption
    enc_style = GRADE_COLORS.get(enc.grade, "white")
    table.add_row("Encryption Performance", f"[{enc_style}]{enc.grade}[/{enc_style}]")
    table.add_row("  TLS Handshake", f"{enc.tls_handshake_ms}ms")
    table.add_row("  Key Exchange", f"{enc.key_exchange_ms}ms")
    table.add_row("  Cert Verification", f"{enc.certificate_verify_ms}ms")
    table.add_row("  Total Setup", f"{enc.total_setup_ms}ms")
    if enc.symmetric_throughput_mbps > 0:
        table.add_row("  Throughput", f"{enc.symmetric_throughput_mbps} Mbps")
    table.add_row("  Protocol", enc.protocol)
    table.add_row("  Cipher", enc.cipher_suite)
    table.add_row("", "")

    rt = report.route
    rt_style = GRADE_COLORS.get(rt.grade, "white")
    table.add_row("Route Analysis", f"[{rt_style}]{rt.grade}[/{rt_style}]")
    table.add_row("  Hop Count", str(rt.hop_count))
    table.add_row("  Total RTT", f"{rt.total_rtt_ms}ms")
    if rt.bottleneck_hop:
        table.add_row("  Bottleneck", f"Hop {rt.bottleneck_hop} ({rt.bottleneck_rtt_ms}ms)")
    table.add_row("  Route Efficiency", f"{rt.route_efficiency:.0%}")

    if report.route.issues:
        table.add_row("", "")
        for issue in report.route.issues:
            table.add_row("[yellow]Issue[/yellow]", f"[yellow]{issue}[/yellow]")

    panel = Panel(
        table,
        title=f"[bold white]Performance Analysis[/bold white]  [{grade_style}]Grade: {report.grade}[/{grade_style}]",
        border_style="cyan",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_traffic_analysis(report) -> None:
    from rich.console import Group

    parts = []

    info_table = Table(box=None, show_header=False, padding=(0, 2))
    info_table.add_column("Key", style="bold white", width=28)
    info_table.add_column("Value")

    info_table.add_row("Cluster Profile", f"[bold cyan]{report.cluster_label}[/bold cyan]")
    info_table.add_row("Behavioral Risk", _render_risk_bar(report.behavioral_risk))
    info_table.add_row("Intelligence Score", f"{report.intelligence_score:.0%}")
    parts.append(info_table)

    if report.patterns:
        parts.append(Text(""))
        pat_table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
        pat_table.add_column("Pattern", style="bold white", width=24)
        pat_table.add_column("Risk", width=10)
        pat_table.add_column("Conf.", width=8)
        pat_table.add_column("Description", style="dim", max_width=35)

        for pat in report.patterns:
            risk_style = RISK_COLORS.get(pat.risk, "white")
            pat_table.add_row(
                pat.name,
                f"[{risk_style}]{pat.risk.upper()}[/{risk_style}]",
                f"{pat.confidence:.0%}",
                pat.description[:35],
            )
        parts.append(pat_table)

    if report.threat_intel:
        parts.append(Text(""))
        ti_table = Table(box=box.SIMPLE, show_header=True, header_style="bold red")
        ti_table.add_column("Category", style="bold white", width=22)
        ti_table.add_column("Severity", width=10)
        ti_table.add_column("Confidence", width=10)
        ti_table.add_column("Description", style="dim", max_width=35)

        for ti in report.threat_intel:
            sev_style = RISK_COLORS.get(ti.severity, "white")
            ti_table.add_row(
                ti.category,
                f"[{sev_style}]{ti.severity.upper()}[/{sev_style}]",
                f"{ti.confidence:.0%}",
                ti.description[:35],
            )
        parts.append(ti_table)

    content = Group(*parts) if len(parts) > 1 else parts[0]

    clustering = report.model_info.get("clustering", {})
    intel = report.model_info.get("threat_intel", {})
    model_desc = f"KMeans + RandomForest | Profile: {clustering.get('profile', 'N/A')}"

    panel = Panel(
        content,
        title=f"[bold white]AI Traffic Analysis & Threat Intelligence[/bold white]",
        subtitle=f"{model_desc} | {report.pattern_count} patterns | {report.threat_count} threats",
        border_style="magenta",
        box=box.ROUNDED,
    )
    console.print(panel)


def print_footer(scan_time: float) -> None:
    console.print()
    console.print(
        f"  [dim]Scanned in {scan_time:.2f}s | {WATERMARK} | "
        f"Wimsalabim v0.1.0 | github.com/WimLee115/wimsalabim[/dim]"
    )
    console.print()


def _bool_icon(val: bool, invert: bool = False) -> str:
    if invert:
        val = not val
    return "[green]OK[/green]" if val else "[red]FAIL[/red]"


def _days_style(days: int) -> str:
    if days < 0:
        return f"[bold red]EXPIRED ({days}d)[/bold red]"
    if days < 30:
        return f"[bold yellow]{days}d[/bold yellow]"
    return f"[green]{days}d[/green]"


def _mini_bar(ratio: float, width: int = 20) -> str:
    ratio = max(0.0, min(1.0, ratio))
    filled = int(ratio * width)
    empty = width - filled
    if ratio >= 0.7:
        color = "red"
    elif ratio >= 0.4:
        color = "yellow"
    else:
        color = "green"
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim] {ratio:.0%}"


def _render_risk_bar(risk: float) -> str:
    width = 30
    filled = int(risk * width)
    empty = width - filled
    if risk >= 0.8:
        color = "red"
    elif risk >= 0.6:
        color = "dark_orange"
    elif risk >= 0.4:
        color = "yellow"
    else:
        color = "green"
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim] [{color}]{risk:.0%}[/{color}]"


def _render_score_badge(score: float, grade: str) -> Text:
    grade_style = GRADE_COLORS.get(grade, "white")
    text = Text()
    text.append("  Score: ", style="bold white")
    text.append(f"{score:.0f}/100 ", style=grade_style)
    text.append(f"  Grade: ", style="bold white")
    text.append(grade, style=grade_style)
    return text
