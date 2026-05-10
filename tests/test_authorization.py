"""Authorization Gate — wet als code."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from wimsalabim.core.authorization import (
    AuthorizationDenied,
    AuthorizationGate,
    AuthorizationProofInvalid,
    authorize_self_owned,
)
from wimsalabim.core.schema import Authorization


def test_passive_always_allowed() -> None:
    gate = AuthorizationGate()
    gate.check(target="any.example.com", legal_class="passive")  # no raise


def test_active_denied_without_authz() -> None:
    gate = AuthorizationGate()
    with pytest.raises(AuthorizationDenied):
        gate.check(target="any.example.com", legal_class="active")


def test_active_allowed_with_matching_authz() -> None:
    authz = Authorization(
        target="example.com",
        mode="self_owned",
        evidence="local manifest",
        verified_at=datetime.now(tz=timezone.utc),
    )
    gate = AuthorizationGate(authorization=authz)
    gate.check(target="example.com", legal_class="active")


def test_active_denied_for_different_target() -> None:
    authz = Authorization(
        target="example.com",
        mode="self_owned",
        evidence="local manifest",
        verified_at=datetime.now(tz=timezone.utc),
    )
    gate = AuthorizationGate(authorization=authz)
    with pytest.raises(AuthorizationDenied):
        gate.check(target="other.com", legal_class="active")


def test_subdomain_match_allowed() -> None:
    authz = Authorization(
        target="example.com",
        mode="self_owned",
        evidence="manifest",
        verified_at=datetime.now(tz=timezone.utc),
    )
    gate = AuthorizationGate(authorization=authz)
    gate.check(target="api.example.com", legal_class="active")


def test_intrusive_requires_extra_flag() -> None:
    authz = Authorization(
        target="example.com",
        mode="self_owned",
        evidence="manifest",
        verified_at=datetime.now(tz=timezone.utc),
    )
    gate = AuthorizationGate(authorization=authz, allow_intrusive=False)
    with pytest.raises(AuthorizationDenied):
        gate.check(target="example.com", legal_class="intrusive")


def test_intrusive_with_flag_allowed() -> None:
    authz = Authorization(
        target="example.com",
        mode="self_owned",
        evidence="manifest",
        verified_at=datetime.now(tz=timezone.utc),
    )
    gate = AuthorizationGate(authorization=authz, allow_intrusive=True)
    gate.check(target="example.com", legal_class="intrusive")


def test_self_owned_manifest(tmp_path):  # type: ignore[no-untyped-def]
    manifest = tmp_path / "owned.txt"
    manifest.write_text("# my domains\nexample.com\nfoo.com\n")
    authz = authorize_self_owned("example.com", manifest)
    assert authz.mode == "self_owned"


def test_self_owned_manifest_rejects_unknown(tmp_path):  # type: ignore[no-untyped-def]
    manifest = tmp_path / "owned.txt"
    manifest.write_text("example.com\n")
    with pytest.raises(AuthorizationProofInvalid):
        authorize_self_owned("attacker.com", manifest)


def test_self_owned_manifest_missing_file(tmp_path):  # type: ignore[no-untyped-def]
    with pytest.raises(AuthorizationProofInvalid):
        authorize_self_owned("example.com", tmp_path / "nope.txt")
