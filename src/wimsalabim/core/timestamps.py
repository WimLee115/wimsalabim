"""OpenTimestamps integration.

We shell out to the upstream ``ots`` CLI (https://github.com/opentimestamps/opentimestamps-client).
Bundling a Python OTS library is overkill; the CLI is well-tested and
re-runnable for upgrade verification later.

Calling ``ots stamp`` over a digest produces a ``.ots`` proof file. Calling
``ots verify`` later confirms the timestamp against Bitcoin block-headers
once the proof has been upgraded (typically a few hours after creation).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class OpenTimestampsUnavailable(RuntimeError):
    """The ``ots`` CLI is not installed or not on PATH."""


@dataclass(frozen=True)
class TimestampProof:
    proof_path: Path
    digest_hex: str


def is_available() -> bool:
    return shutil.which("ots") is not None


def stamp(digest_file: Path) -> TimestampProof:
    """Create a ``.ots`` proof for the given file (which contains the digest).

    The proof is written next to the input as ``<file>.ots``.
    """
    if not is_available():
        raise OpenTimestampsUnavailable(
            "ots CLI not found. Install with: pipx install opentimestamps-client"
        )
    if not digest_file.is_file():
        raise FileNotFoundError(digest_file)

    result = subprocess.run(
        ["ots", "stamp", str(digest_file)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"ots stamp failed: {result.stderr.strip()}")

    proof = digest_file.with_name(digest_file.name + ".ots")
    if not proof.is_file():
        raise RuntimeError(f"Expected proof at {proof} but it does not exist")

    digest_hex = digest_file.read_text(encoding="utf-8").strip()
    return TimestampProof(proof_path=proof, digest_hex=digest_hex)


def verify(proof_path: Path) -> bool:
    if not is_available():
        raise OpenTimestampsUnavailable(
            "ots CLI not found. Install with: pipx install opentimestamps-client"
        )
    result = subprocess.run(
        ["ots", "verify", str(proof_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


__all__ = [
    "OpenTimestampsUnavailable",
    "TimestampProof",
    "is_available",
    "stamp",
    "verify",
]
