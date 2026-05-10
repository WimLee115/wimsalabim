"""CLI smoke tests via Click's CliRunner."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from wimsalabim.cli import _normalize_target, _resolve_enabled, main


def test_normalize_target_strips_scheme_and_path() -> None:
    assert _normalize_target("HTTPS://Example.COM/foo/bar") == "example.com"
    assert _normalize_target("http://x.y/") == "x.y"
    assert _normalize_target("plain.example.com") == "plain.example.com"


def test_resolve_enabled_with_explicit_enable() -> None:
    out = _resolve_enabled(["a", "b", "c"], enable=("a", "c"), disable=())
    assert out == ["a", "c"]


def test_resolve_enabled_with_disable() -> None:
    out = _resolve_enabled(["a", "b", "c"], enable=(), disable=("b",))
    assert out == ["a", "c"]


def test_main_help_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "verify" in result.output
    assert "keys" in result.output


def test_analyzers_subcommand_lists_all() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["analyzers"])
    assert result.exit_code == 0
    for name in ("dns_recon", "tls", "headers", "ports"):
        assert name in result.output


def test_keys_init_creates_files(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["keys", "init", "--keys-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / "signing.key").is_file()
    assert (tmp_path / "signing.pub").is_file()


def test_keys_init_refuses_overwrite(tmp_path: Path) -> None:
    runner = CliRunner()
    runner.invoke(main, ["keys", "init", "--keys-dir", str(tmp_path)])
    result = runner.invoke(main, ["keys", "init", "--keys-dir", str(tmp_path)])
    assert result.exit_code != 0
    assert "already exists" in result.output.lower()


def test_keys_show_after_init(tmp_path: Path) -> None:
    runner = CliRunner()
    runner.invoke(main, ["keys", "init", "--keys-dir", str(tmp_path)])
    result = runner.invoke(main, ["keys", "show", "--keys-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "pubkey" in result.output
    assert "fp" in result.output
