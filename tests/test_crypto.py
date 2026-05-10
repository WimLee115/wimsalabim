"""Ed25519 sign / verify round-trip."""

from __future__ import annotations

from pathlib import Path

import pytest

from wimsalabim.core.crypto import (
    generate_keypair,
    load_keypair,
    save_keypair,
    sign,
    verify,
)


def test_roundtrip_sign_verify() -> None:
    kp = generate_keypair()
    payload = b"wimsalabim test payload"
    sig = sign(kp, payload)
    assert verify(kp.public_key_b64, payload, sig)


def test_tampered_payload_fails_verify() -> None:
    kp = generate_keypair()
    sig = sign(kp, b"original")
    assert not verify(kp.public_key_b64, b"tampered", sig)


def test_wrong_pubkey_fails_verify() -> None:
    kp = generate_keypair()
    other = generate_keypair()
    sig = sign(kp, b"x")
    assert not verify(other.public_key_b64, b"x", sig)


def test_persist_and_reload(tmp_path: Path) -> None:
    kp = generate_keypair()
    save_keypair(kp, directory=tmp_path)
    reloaded = load_keypair(tmp_path)
    payload = b"hello"
    sig = sign(reloaded, payload)
    assert verify(kp.public_key_b64, payload, sig)


def test_load_missing_keys_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_keypair(tmp_path)


def test_fingerprint_short() -> None:
    kp = generate_keypair()
    assert len(kp.fingerprint) == 16
