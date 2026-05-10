"""Command-line entrypoint.

The CLI is intentionally slim: parsing, configuration, hand-off to
``Orchestrator``. All real work lives in ``core/`` and ``analyzers/``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import signal
import sys
from pathlib import Path

import click
from rich.console import Console

# Importing this module triggers analyzer registration via decorators.
import wimsalabim.analyzers  # noqa: F401
from wimsalabim import __version__
from wimsalabim.core import logging as wl_logging
from wimsalabim.core.authorization import (
    AuthorizationGate,
    authorize_self_owned,
    verify_dns_txt,
    verify_well_known,
)
from wimsalabim.core.canonical import canonicalize, hash_obj
from wimsalabim.core.crypto import (
    SigningKeyPair,
    generate_keypair,
    load_keypair,
    save_keypair,
    sign,
)
from wimsalabim.core.crypto import verify as verify_signature
from wimsalabim.core.orchestrator import Orchestrator, OrchestratorConfig
from wimsalabim.core.registry import all_analyzers
from wimsalabim.core.schema import Authorization, ScanReport
from wimsalabim.display import render_markdown, render_rich, render_sarif
from wimsalabim.risk.heuristic import HeuristicRiskEngine
from wimsalabim.watch import BaselineStore, Diff, watch_loop
from wimsalabim.watch.loop import OnIteration, ScanFn


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="wimsalabim")
def main() -> None:
    """wimsalabim — eerlijke website-security & privacy-reconnaissance.

    Onder PVNL-vlag · Captain WimLee115.
    """


# ─── scan ────────────────────────────────────────────────────────────────
@main.command()
@click.argument("target")
@click.option("--enable", "-e", multiple=True, help="Enable only these analyzers (repeatable).")
@click.option("--disable", "-d", multiple=True, help="Disable these analyzers (repeatable).")
@click.option("--via-tor", is_flag=True, help="Route HTTP via local Tor SOCKS5.")
@click.option("--offline", is_flag=True, help="Disable all outbound network.")
@click.option("--show-pii", is_flag=True, help="Do not redact PII (use only on data you own).")
@click.option(
    "--allow-intrusive", is_flag=True, help="Permit intrusive analyzers (extra confirmation)."
)
@click.option(
    "--auth-self-owned",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to self-owned domains manifest (one host per line).",
)
@click.option(
    "--auth-dns-txt",
    "auth_dns_pubkey",
    default=None,
    help="Verify _wimsalabim-auth.<target> TXT contains this base64 pubkey.",
)
@click.option(
    "--auth-well-known",
    "auth_well_known_pubkey",
    default=None,
    help="Verify /.well-known/wimsalabim-auth.txt declares this pubkey.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["rich", "json", "markdown", "sarif"], case_sensitive=False),
    default="rich",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the report to file (also rendered to stdout).",
)
@click.option("--sign", is_flag=True, help="Sign the report (Ed25519).")
@click.option(
    "--keys-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.home() / ".wimsalabim" / "keys",
)
@click.option("--verbose/--quiet", default=False)
def scan(
    target: str,
    enable: tuple[str, ...],
    disable: tuple[str, ...],
    via_tor: bool,
    offline: bool,
    show_pii: bool,
    allow_intrusive: bool,
    auth_self_owned: Path | None,
    auth_dns_pubkey: str | None,
    auth_well_known_pubkey: str | None,
    fmt: str,
    output: Path | None,
    sign: bool,
    keys_dir: Path,
    verbose: bool,
) -> None:
    """Scan TARGET for security and privacy issues."""
    wl_logging.configure_logging(verbose=verbose, json_output=(fmt == "json"))
    target = _normalize_target(target)
    available = sorted(all_analyzers().keys())
    enabled = _resolve_enabled(available, enable, disable)

    authorization = None
    if auth_self_owned:
        authorization = authorize_self_owned(target, auth_self_owned)
    elif auth_dns_pubkey:
        authorization = asyncio.run(verify_dns_txt(target, auth_dns_pubkey))
    elif auth_well_known_pubkey:
        authorization = asyncio.run(verify_well_known(target, auth_well_known_pubkey))

    gate = AuthorizationGate(authorization=authorization, allow_intrusive=allow_intrusive)

    config = OrchestratorConfig(
        target=target,
        enabled=tuple(enabled),
        via_tor=via_tor,
        offline=offline,
        show_pii=show_pii,
        allow_intrusive=allow_intrusive,
    )

    orch = Orchestrator(
        config=config,
        registrations=[reg for name, reg in all_analyzers().items() if name in enabled],
        gate=gate,
        authorization=authorization,
    )
    report = asyncio.run(orch.run())
    risk = HeuristicRiskEngine().assess(report.analyzers)

    final = report.model_copy(update={"risk": risk})

    if sign:
        kp = _load_or_init_keys(keys_dir)
        digest_payload = canonicalize(_unsigned_view(final))
        signature = _sign_bytes(kp, digest_payload)
        final = final.model_copy(
            update={
                "signature": signature,
                "signing_pubkey": kp.public_key_b64,
            }
        )

    _render(final, fmt, output)


def _sign_bytes(kp: SigningKeyPair, data: bytes) -> str:
    return sign(kp, data)


# ─── watch ───────────────────────────────────────────────────────────────
@main.command()
@click.argument("targets", nargs=-1, required=True)
@click.option(
    "--interval",
    "interval_s",
    default=3600.0,
    show_default=True,
    type=click.FloatRange(min=1.0),
    help="Seconds between scan rounds.",
)
@click.option(
    "--db",
    "db_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path.home() / ".wimsalabim" / "watch.sqlite",
    show_default=True,
    help="SQLite file used as baseline store.",
)
@click.option("--once", is_flag=True, help="Run a single round and exit.")
@click.option("--diff-only", is_flag=True, help="Only print rounds with a meaningful diff.")
@click.option("--enable", "-e", multiple=True, help="Enable only these analyzers (repeatable).")
@click.option("--disable", "-d", multiple=True, help="Disable these analyzers (repeatable).")
@click.option("--via-tor", is_flag=True, help="Route HTTP via local Tor SOCKS5.")
@click.option("--offline", is_flag=True, help="Disable all outbound network.")
@click.option("--show-pii", is_flag=True, help="Do not redact PII (use only on data you own).")
@click.option(
    "--allow-intrusive", is_flag=True, help="Permit intrusive analyzers (extra confirmation)."
)
@click.option(
    "--auth-self-owned",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to self-owned domains manifest (one host per line).",
)
@click.option(
    "--auth-dns-txt",
    "auth_dns_pubkey",
    default=None,
    help="Verify _wimsalabim-auth.<target> TXT contains this base64 pubkey.",
)
@click.option(
    "--auth-well-known",
    "auth_well_known_pubkey",
    default=None,
    help="Verify /.well-known/wimsalabim-auth.txt declares this pubkey.",
)
@click.option("--verbose/--quiet", default=False)
def watch(
    targets: tuple[str, ...],
    interval_s: float,
    db_path: Path,
    once: bool,
    diff_only: bool,
    enable: tuple[str, ...],
    disable: tuple[str, ...],
    via_tor: bool,
    offline: bool,
    show_pii: bool,
    allow_intrusive: bool,
    auth_self_owned: Path | None,
    auth_dns_pubkey: str | None,
    auth_well_known_pubkey: str | None,
    verbose: bool,
) -> None:
    """Periodically rescan TARGETS and report drift against a baseline."""
    wl_logging.configure_logging(verbose=verbose, json_output=False)
    normalized = [_normalize_target(t) for t in targets]
    available = sorted(all_analyzers().keys())
    enabled = _resolve_enabled(available, enable, disable)

    authorizations = {
        target: _resolve_authorization(
            target,
            auth_self_owned=auth_self_owned,
            auth_dns_pubkey=auth_dns_pubkey,
            auth_well_known_pubkey=auth_well_known_pubkey,
        )
        for target in normalized
    }
    store = BaselineStore(db_path)
    console = Console()

    async def _scan_one(target: str) -> ScanReport:
        config = OrchestratorConfig(
            target=target,
            enabled=tuple(enabled),
            via_tor=via_tor,
            offline=offline,
            show_pii=show_pii,
            allow_intrusive=allow_intrusive,
        )
        target_gate = AuthorizationGate(
            authorization=authorizations[target], allow_intrusive=allow_intrusive
        )
        orch = Orchestrator(
            config=config,
            registrations=[reg for name, reg in all_analyzers().items() if name in enabled],
            gate=target_gate,
            authorization=authorizations[target],
        )
        report = await orch.run()
        risk = HeuristicRiskEngine().assess(report.analyzers)
        return report.model_copy(update={"risk": risk})

    def _on_iteration(target: str, report: ScanReport, diff: Diff | None) -> None:
        meaningful = diff is not None and diff.is_meaningful
        if diff_only and not meaningful:
            return
        _render_watch_round(console, target, report, diff)

    asyncio.run(
        _run_watch(
            targets=normalized,
            interval_s=interval_s,
            scan=_scan_one,
            store=store,
            on_iteration=_on_iteration,
            max_iterations=1 if once else None,
            console=console,
        )
    )


async def _run_watch(
    *,
    targets: list[str],
    interval_s: float,
    scan: ScanFn,
    store: BaselineStore,
    on_iteration: OnIteration,
    max_iterations: int | None,
    console: Console,
) -> None:
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed: list[signal.Signals] = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError):
            # Windows / non-main thread — fall back to default Ctrl+C handling.
            continue
        installed.append(sig)
    try:
        outcome = await watch_loop(
            targets=targets,
            interval_s=interval_s,
            scan=scan,
            store=store,
            on_iteration=on_iteration,
            stop_event=stop_event,
            max_iterations=max_iterations,
        )
    finally:
        for sig in installed:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.remove_signal_handler(sig)
    console.print(
        f"[dim]watch finished — {outcome.iterations} round(s), "
        f"{outcome.rounds_with_diff} with diff.[/dim]"
    )


def _render_watch_round(
    console: Console, target: str, report: ScanReport, diff: Diff | None
) -> None:
    header = (
        f"[bold]watch[/bold] · target=[cyan]{target}[/cyan] · "
        f"started={report.started_at.isoformat(timespec='seconds')}"
    )
    console.print(header)
    if diff is None:
        console.print("  [dim](no baseline yet — recorded as first snapshot)[/dim]")
        return
    if not diff.is_meaningful:
        console.print(
            f"  [green]no change[/green] since {diff.previous_at.isoformat(timespec='seconds')}"
        )
        return
    console.print(
        f"  [yellow]diff[/yellow] vs {diff.previous_at.isoformat(timespec='seconds')}: "
        f"+{len(diff.added)} -{len(diff.removed)} ~{len(diff.changed)}"
    )
    for entry in diff.added:
        console.print(f"    [green]+[/green] {entry}")
    for entry in diff.removed:
        console.print(f"    [red]-[/red] {entry}")
    for entry in diff.changed:
        console.print(f"    [yellow]~[/yellow] {entry}")


def _resolve_authorization(
    target: str,
    *,
    auth_self_owned: Path | None,
    auth_dns_pubkey: str | None,
    auth_well_known_pubkey: str | None,
) -> Authorization | None:
    if auth_self_owned:
        return authorize_self_owned(target, auth_self_owned)
    if auth_dns_pubkey:
        return asyncio.run(verify_dns_txt(target, auth_dns_pubkey))
    if auth_well_known_pubkey:
        return asyncio.run(verify_well_known(target, auth_well_known_pubkey))
    return None


# ─── verify ──────────────────────────────────────────────────────────────
@main.command()
@click.argument("report_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def verify(report_path: Path) -> None:
    """Verify the Ed25519 signature on a JSON scan report."""
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    pubkey = payload.get("signing_pubkey")
    sig = payload.get("signature")
    if not pubkey or not sig:
        raise click.ClickException("Report has no signature/pubkey fields.")

    unsigned = {
        k: v
        for k, v in payload.items()
        if k not in {"signature", "signing_pubkey", "ots_proof_path"}
    }
    canonical = canonicalize(unsigned)
    ok = _verify_bytes(pubkey, canonical, sig)
    console = Console()
    if ok:
        console.print(
            f"[bold green]✓ valid[/bold green]   "
            f"pubkey {pubkey[:16]}…   digest {hash_obj(unsigned)[:16]}…"
        )
        sys.exit(0)
    else:
        console.print("[bold red]✗ INVALID signature[/bold red]")
        sys.exit(2)


def _verify_bytes(public_key_b64: str, data: bytes, signature_b64: str) -> bool:
    return verify_signature(public_key_b64, data, signature_b64)


# ─── keys ────────────────────────────────────────────────────────────────
@main.group()
def keys() -> None:
    """Manage Ed25519 signing keys."""


@keys.command("init")
@click.option(
    "--keys-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.home() / ".wimsalabim" / "keys",
)
def keys_init(keys_dir: Path) -> None:
    """Generate a new keypair under KEYS_DIR (default ~/.wimsalabim/keys)."""
    if (keys_dir / "signing.key").exists():
        raise click.ClickException(f"Keypair already exists in {keys_dir}.")
    kp = generate_keypair()
    priv, pub = save_keypair(kp, directory=keys_dir)
    Console().print(
        f"[green]✓[/green] keypair created\n"
        f"  private: [bold]{priv}[/bold]\n"
        f"  public : [bold]{pub}[/bold]\n"
        f"  pubkey : {kp.public_key_b64}\n"
        f"  fp     : {kp.fingerprint}"
    )


@keys.command("show")
@click.option(
    "--keys-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.home() / ".wimsalabim" / "keys",
)
def keys_show(keys_dir: Path) -> None:
    """Print the public key + fingerprint."""
    kp = load_keypair(keys_dir)
    Console().print(
        f"pubkey   : {kp.public_key_b64}\nfp       : {kp.fingerprint}\nkeys_dir : {keys_dir}"
    )


# ─── analyzers ───────────────────────────────────────────────────────────
@main.command(name="analyzers")
def list_analyzers() -> None:
    """List all registered analyzers."""
    console = Console()
    for name, reg in sorted(all_analyzers().items()):
        console.print(f"[bold]{name}[/bold]  [dim]({reg.legal_class})[/dim]   {reg.description}")


# ─── helpers ─────────────────────────────────────────────────────────────
def _normalize_target(target: str) -> str:
    target = target.strip().lower()
    for scheme in ("https://", "http://"):
        if target.startswith(scheme):
            target = target[len(scheme) :]
    return target.split("/", 1)[0].rstrip(".")


def _resolve_enabled(
    available: list[str], enable: tuple[str, ...], disable: tuple[str, ...]
) -> list[str]:
    if enable:
        unknown = set(enable) - set(available)
        if unknown:
            raise click.ClickException(f"Unknown analyzer(s): {sorted(unknown)}")
        return [a for a in available if a in set(enable)]
    return [a for a in available if a not in set(disable)]


def _unsigned_view(report: ScanReport) -> dict[str, object]:
    data = report.model_dump(mode="json")
    data.pop("signature", None)
    data.pop("signing_pubkey", None)
    data.pop("ots_proof_path", None)
    return data


def _render(report: ScanReport, fmt: str, output: Path | None) -> None:
    fmt = fmt.lower()
    console = Console()
    payload: str | bytes
    if fmt == "rich":
        render_rich(report, console)
        if output:
            output.write_text(
                json.dumps(report.model_dump(mode="json"), indent=2), encoding="utf-8"
            )
        return
    if fmt == "json":
        payload = json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True)
        click.echo(payload)
    elif fmt == "markdown":
        payload = render_markdown(report)
        click.echo(payload)
    elif fmt == "sarif":
        payload = json.dumps(render_sarif(report), indent=2)
        click.echo(payload)
    else:
        raise click.ClickException(f"unknown format: {fmt}")
    if output:
        output.write_text(
            payload if isinstance(payload, str) else payload.decode(), encoding="utf-8"
        )


def _load_or_init_keys(keys_dir: Path) -> SigningKeyPair:
    try:
        return load_keypair(keys_dir)
    except FileNotFoundError:
        kp = generate_keypair()
        save_keypair(kp, directory=keys_dir)
        return kp


if __name__ == "__main__":
    main()
