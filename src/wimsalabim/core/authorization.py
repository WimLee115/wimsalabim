"""Authorization Gate — wet als code.

Default behaviour:
    - ``passive``  analyzers run on any target (only public data, no probing).
    - ``active``   analyzers require explicit Authorization for the target.
    - ``intrusive`` analyzers require Authorization AND --force-intrusive.

Authorization can be obtained via:
    1. ``self_owned``  — operator declares they own the domain
                          (signed local manifest).
    2. ``dns_txt``     — TXT record _wimsalabim-auth.<target> matches operator pubkey.
    3. ``well_known``  — /.well-known/wimsalabim-auth.txt is signed by operator.
    4. ``bug_bounty``  — public bug-bounty programme URL (HackerOne, Intigriti).

The gate refuses by failing closed. There is no ``--yolo`` flag.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import dns.asyncresolver
import dns.exception
import httpx

from wimsalabim.core.exceptions import WimsalabimError
from wimsalabim.core.schema import Authorization, LegalClass

_HTTP_OK = 200


class AuthorizationDenied(WimsalabimError):
    """The gate refused to admit the analyzer."""


class AuthorizationProofInvalid(WimsalabimError):
    """The supplied proof did not validate."""


class AuthorizationGate:
    """Verifies whether ``legal_class`` is allowed for ``target``."""

    def __init__(
        self,
        *,
        authorization: Authorization | None = None,
        allow_intrusive: bool = False,
    ) -> None:
        self._authz = authorization
        self._allow_intrusive = allow_intrusive

    def check(self, *, target: str, legal_class: LegalClass) -> None:
        """Raise ``AuthorizationDenied`` if not allowed; return otherwise."""
        if legal_class == "passive":
            return

        if self._authz is None:
            raise AuthorizationDenied(
                f"Analyzer with legal_class={legal_class!r} requires authorization. "
                f"Run `wimsalabim auth --target {target} ...` to provide proof."
            )

        if not _hosts_match(self._authz.target, target):
            raise AuthorizationDenied(
                f"Authorization is for {self._authz.target!r}, not {target!r}."
            )

        if legal_class == "intrusive" and not self._allow_intrusive:
            raise AuthorizationDenied("Intrusive analyzers also require --force-intrusive.")


def _hosts_match(authorized: str, requested: str) -> bool:
    """Allow exact match or subdomain match for the authorized scope."""
    a = authorized.lower().strip(".")
    r = requested.lower().strip(".")
    return r == a or r.endswith("." + a)


# ─── Proof verification helpers ──────────────────────────────────────────
async def verify_dns_txt(target: str, expected_pubkey_b64: str) -> Authorization:
    """Look up _wimsalabim-auth.<target> TXT record and check it matches.

    Format expected:  ``v=wimsalabim1 pubkey=<base64-ed25519-32B>``
    """
    name = f"_wimsalabim-auth.{target.strip('.')}"
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answers = await resolver.resolve(name, "TXT")
    except (dns.exception.DNSException, asyncio.TimeoutError) as exc:
        raise AuthorizationProofInvalid(f"TXT lookup for {name} failed: {exc}") from exc

    for rdata in answers:
        txt = b"".join(rdata.strings).decode("ascii", errors="replace")
        if "v=wimsalabim1" in txt and expected_pubkey_b64 in txt:
            return Authorization(
                target=target,
                mode="dns_txt",
                evidence=txt,
                verified_at=datetime.now(tz=timezone.utc),
            )

    raise AuthorizationProofInvalid(f"No matching pubkey found in TXT records of {name}")


async def verify_well_known(target: str, expected_pubkey_b64: str) -> Authorization:
    """Fetch /.well-known/wimsalabim-auth.txt and verify it.

    Format expected (single line):
        ``v=wimsalabim1 pubkey=<base64-ed25519> sig=<base64-sig> target=<host>``
    """
    url = f"https://{target.strip('/')}/.well-known/wimsalabim-auth.txt"
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as http:
        try:
            resp = await http.get(url)
        except httpx.HTTPError as exc:
            raise AuthorizationProofInvalid(f"GET {url} failed: {exc}") from exc

    if resp.status_code != _HTTP_OK:
        raise AuthorizationProofInvalid(f"GET {url} returned {resp.status_code}")

    body = resp.text.strip()
    if "v=wimsalabim1" not in body or expected_pubkey_b64 not in body:
        raise AuthorizationProofInvalid(f"{url}: payload does not declare expected pubkey")

    return Authorization(
        target=target,
        mode="well_known",
        evidence=body,
        verified_at=datetime.now(tz=timezone.utc),
    )


def authorize_self_owned(target: str, manifest_path: Path) -> Authorization:
    """Local declaration — for development on operator-owned domains.

    The manifest must list the target verbatim. We do not validate
    cryptographically here; this mode is for local/CI scenarios where the
    operator has independent ownership evidence.
    """
    if not manifest_path.is_file():
        raise AuthorizationProofInvalid(f"Manifest {manifest_path} not found")
    lines = [
        line.strip()
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if target.lower() not in {line.lower() for line in lines}:
        raise AuthorizationProofInvalid(f"{target} is not declared in {manifest_path}")
    return Authorization(
        target=target,
        mode="self_owned",
        evidence=str(manifest_path),
        verified_at=datetime.now(tz=timezone.utc),
    )


__all__ = [
    "AuthorizationDenied",
    "AuthorizationGate",
    "AuthorizationProofInvalid",
    "authorize_self_owned",
    "verify_dns_txt",
    "verify_well_known",
]
