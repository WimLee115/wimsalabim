"""Canonical JSON serialization (RFC 8785 / JCS).

Used for: hashing scan output deterministically, signing it, and
OpenTimestamps-anchoring the resulting digest.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def canonicalize(obj: Any) -> bytes:
    """Produce RFC 8785-compatible canonical JSON bytes.

    Rules:
    - keys sorted lexicographically;
    - no insignificant whitespace;
    - UTF-8 output;
    - datetimes serialized as ISO-8601 UTC strings;
    - ``None`` collapses to JSON ``null``.
    """
    return json.dumps(
        obj,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_default,
    ).encode("utf-8")


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if hasattr(value, "model_dump"):  # pydantic v2
        return value.model_dump(mode="json")
    if isinstance(value, set | frozenset):
        return sorted(value)
    raise TypeError(f"Cannot canonicalize value of type {type(value).__name__}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    """Convenience: SHA-256 hex digest of canonical-JSON of ``obj``."""
    return sha256_hex(canonicalize(obj))


__all__ = ["canonicalize", "hash_obj", "sha256_hex"]
