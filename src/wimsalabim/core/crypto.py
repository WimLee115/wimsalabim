"""Ed25519 signing for scan reports.

We use ``cryptography``'s Ed25519 primitives. Keys are persisted as
PEM-encoded files (PKCS#8 for the private key, SubjectPublicKeyInfo for
the public key) under ``~/.wimsalabim/keys/`` by default.
"""

from __future__ import annotations

import base64
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True)
class SigningKeyPair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @property
    def public_key_b64(self) -> str:
        raw = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")

    @property
    def fingerprint(self) -> str:
        """Short, human-friendly fingerprint of the public key."""
        return self.public_key_b64[:16]


def generate_keypair() -> SigningKeyPair:
    private = Ed25519PrivateKey.generate()
    return SigningKeyPair(private_key=private, public_key=private.public_key())


def save_keypair(kp: SigningKeyPair, *, directory: Path) -> tuple[Path, Path]:
    """Persist keypair to ``directory``. Returns (priv_path, pub_path).

    Private key is written with mode 0600.
    """
    directory.mkdir(parents=True, exist_ok=True)
    priv_path = directory / "signing.key"
    pub_path = directory / "signing.pub"

    priv_pem = kp.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = kp.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    # 0600 on the private key
    if os.name == "posix":
        priv_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    return priv_path, pub_path


def load_keypair(directory: Path) -> SigningKeyPair:
    priv_path = directory / "signing.key"
    pub_path = directory / "signing.pub"
    if not priv_path.is_file() or not pub_path.is_file():
        raise FileNotFoundError(f"Keypair not found in {directory}. Run `wimsalabim keys init`.")
    private = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    public = serialization.load_pem_public_key(pub_path.read_bytes())
    if not isinstance(private, Ed25519PrivateKey):
        raise TypeError(f"{priv_path}: not an Ed25519 private key")
    if not isinstance(public, Ed25519PublicKey):
        raise TypeError(f"{pub_path}: not an Ed25519 public key")
    return SigningKeyPair(private_key=private, public_key=public)


def sign(kp: SigningKeyPair, data: bytes) -> str:
    """Return base64 Ed25519 signature over ``data``."""
    sig = kp.private_key.sign(data)
    return base64.b64encode(sig).decode("ascii")


def verify(public_key_b64: str, data: bytes, signature_b64: str) -> bool:
    raw_pubkey = base64.b64decode(public_key_b64)
    pub = Ed25519PublicKey.from_public_bytes(raw_pubkey)
    sig = base64.b64decode(signature_b64)
    try:
        pub.verify(sig, data)
    except InvalidSignature:
        return False
    return True


__all__ = [
    "SigningKeyPair",
    "generate_keypair",
    "load_keypair",
    "save_keypair",
    "sign",
    "verify",
]
