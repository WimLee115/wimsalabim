"""OpenTimestamps wrapper — tests around the optional ``ots`` CLI dependency."""

from __future__ import annotations

from pathlib import Path

import pytest

from wimsalabim.core import timestamps


def test_is_available_returns_bool() -> None:
    assert isinstance(timestamps.is_available(), bool)


def test_stamp_raises_when_ots_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(timestamps, "is_available", lambda: False)
    digest_file = tmp_path / "digest.txt"
    digest_file.write_text("deadbeef" * 8)
    with pytest.raises(timestamps.OpenTimestampsUnavailable):
        timestamps.stamp(digest_file)


def test_verify_raises_when_ots_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(timestamps, "is_available", lambda: False)
    proof = tmp_path / "x.ots"
    proof.write_bytes(b"")
    with pytest.raises(timestamps.OpenTimestampsUnavailable):
        timestamps.verify(proof)


def test_stamp_raises_for_missing_input(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(timestamps, "is_available", lambda: True)
    with pytest.raises(FileNotFoundError):
        timestamps.stamp(tmp_path / "nonexistent.txt")
