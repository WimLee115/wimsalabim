"""Canonical JSON & hashing — must be deterministic."""

from __future__ import annotations

from datetime import datetime, timezone

from wimsalabim.core.canonical import canonicalize, hash_obj, sha256_hex


def test_canonical_keys_sorted() -> None:
    a = canonicalize({"b": 1, "a": 2})
    b = canonicalize({"a": 2, "b": 1})
    assert a == b
    assert a == b'{"a":2,"b":1}'


def test_canonical_no_whitespace() -> None:
    out = canonicalize({"k": "v"})
    assert b" " not in out


def test_canonical_datetime_iso_utc() -> None:
    naive = datetime(2026, 5, 10, 12, 0, 0)
    out = canonicalize({"t": naive})
    assert b'"2026-05-10T12:00:00Z"' in out


def test_canonical_datetime_zone_normalized() -> None:
    from datetime import timedelta

    cet = timezone(timedelta(hours=1))
    out = canonicalize({"t": datetime(2026, 5, 10, 13, 0, 0, tzinfo=cet)})
    assert b'"2026-05-10T12:00:00Z"' in out


def test_hash_obj_stable() -> None:
    assert hash_obj({"a": 1, "b": 2}) == hash_obj({"b": 2, "a": 1})


def test_sha256_hex_length() -> None:
    assert len(sha256_hex(b"")) == 64
