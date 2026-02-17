"""RFC 9116 security.txt validation and analysis. rootmap:WimLee115"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

import requests


@dataclass
class SecurityTxtField:
    name: str
    value: str
    valid: bool = True
    issue: str = ""


@dataclass
class SecurityTxtReport:
    target: str
    found: bool = False
    url: str = ""
    signed: bool = False
    fields: list[SecurityTxtField] = field(default_factory=list)
    has_contact: bool = False
    has_expires: bool = False
    has_encryption: bool = False
    has_preferred_languages: bool = False
    has_canonical: bool = False
    has_policy: bool = False
    has_acknowledgments: bool = False
    has_hiring: bool = False
    expired: bool = False
    expires_date: str = ""
    issues: list[str] = field(default_factory=list)
    raw_content: str = ""
    grade: str = "N/A"

    @property
    def field_count(self) -> int:
        return len(self.fields)

    @property
    def required_fields_present(self) -> bool:
        return self.has_contact and self.has_expires


REQUIRED_FIELDS = {"Contact", "Expires"}
RECOMMENDED_FIELDS = {"Encryption", "Preferred-Languages", "Canonical"}
OPTIONAL_FIELDS = {"Policy", "Acknowledgments", "Hiring"}
ALL_KNOWN_FIELDS = REQUIRED_FIELDS | RECOMMENDED_FIELDS | OPTIONAL_FIELDS


def analyze_security_txt(target: str) -> SecurityTxtReport:
    report = SecurityTxtReport(target=target)

    content = _fetch_security_txt(target, report)
    if not content:
        report.grade = "F"
        return report

    report.found = True
    report.raw_content = content

    _check_pgp_signature(content, report)
    _parse_fields(content, report)
    _validate_fields(report)
    _calculate_grade(report)

    return report


def _fetch_security_txt(target: str, report: SecurityTxtReport) -> str:
    urls = [
        f"https://{target}/.well-known/security.txt",
        f"https://{target}/security.txt",
    ]

    for url in urls:
        try:
            resp = requests.get(
                url, timeout=10, allow_redirects=True, verify=False,
                headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
            )
            if resp.status_code == 200 and _looks_like_security_txt(resp.text):
                report.url = url
                return resp.text
        except requests.RequestException:
            continue

    report.issues.append("security.txt not found at /.well-known/security.txt or /security.txt")
    return ""


def _looks_like_security_txt(text: str) -> bool:
    lower = text.lower()
    return any(kw in lower for kw in ("contact:", "expires:", "encryption:", "policy:"))


def _check_pgp_signature(content: str, report: SecurityTxtReport) -> None:
    if "-----BEGIN PGP SIGNED MESSAGE-----" in content:
        report.signed = True
    elif "-----BEGIN PGP SIGNATURE-----" in content:
        report.signed = True


def _parse_fields(content: str, report: SecurityTxtReport) -> None:
    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue
        if line.startswith("-----"):
            continue

        match = re.match(r"^([A-Za-z-]+):\s*(.+)$", line)
        if not match:
            continue

        name = match.group(1).strip()
        value = match.group(2).strip()

        report.fields.append(SecurityTxtField(name=name, value=value))

        name_lower = name.lower()
        if name_lower == "contact":
            report.has_contact = True
        elif name_lower == "expires":
            report.has_expires = True
            report.expires_date = value
            _check_expiry(value, report)
        elif name_lower == "encryption":
            report.has_encryption = True
        elif name_lower == "preferred-languages":
            report.has_preferred_languages = True
        elif name_lower == "canonical":
            report.has_canonical = True
        elif name_lower == "policy":
            report.has_policy = True
        elif name_lower == "acknowledgments":
            report.has_acknowledgments = True
        elif name_lower == "hiring":
            report.has_hiring = True


def _check_expiry(expires_str: str, report: SecurityTxtReport) -> None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(expires_str.strip(), fmt)
            if dt.tzinfo:
                dt = dt.replace(tzinfo=None)
            if dt < datetime.now(tz=None):
                report.expired = True
                report.issues.append(f"security.txt has expired: {expires_str}")
            return
        except ValueError:
            continue


def _validate_fields(report: SecurityTxtReport) -> None:
    if not report.has_contact:
        report.issues.append("Missing required field: Contact (RFC 9116)")

    if not report.has_expires:
        report.issues.append("Missing required field: Expires (RFC 9116)")

    if not report.has_canonical:
        report.issues.append("Missing recommended field: Canonical")

    if not report.signed:
        report.issues.append("security.txt is not PGP signed (recommended by RFC 9116)")

    for f in report.fields:
        if f.name.lower() == "contact":
            if not any(f.value.startswith(p) for p in ("mailto:", "https://", "tel:")):
                f.valid = False
                f.issue = "Contact should use mailto:, https://, or tel: URI"
                report.issues.append(f"Invalid Contact format: {f.value}")

        if f.name.lower() == "encryption":
            if not f.value.startswith(("https://", "dns:", "openpgp4fpr:")):
                f.valid = False
                f.issue = "Encryption should use https://, dns:, or openpgp4fpr: URI"

        if f.name.lower() == "canonical":
            if not f.value.startswith("https://"):
                f.valid = False
                f.issue = "Canonical must use https:// URI"

    known = {f.lower() for f in ALL_KNOWN_FIELDS}
    for f in report.fields:
        if f.name.lower() not in known and f.name.lower() != "hash":
            report.issues.append(f"Unknown field: {f.name}")


def _calculate_grade(report: SecurityTxtReport) -> None:
    if not report.found:
        report.grade = "F"
        return

    score = 50

    if report.has_contact:
        score += 15
    if report.has_expires and not report.expired:
        score += 15
    if report.has_encryption:
        score += 5
    if report.has_canonical:
        score += 5
    if report.signed:
        score += 10

    if report.expired:
        score -= 20
    if not report.has_contact:
        score -= 15

    invalid_count = sum(1 for f in report.fields if not f.valid)
    score -= invalid_count * 5

    if score >= 90:
        report.grade = "A"
    elif score >= 75:
        report.grade = "B"
    elif score >= 60:
        report.grade = "C"
    elif score >= 40:
        report.grade = "D"
    else:
        report.grade = "F"
