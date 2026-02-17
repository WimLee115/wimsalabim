"""WHOIS information analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import whois


@dataclass
class WhoisReport:
    target: str
    available: bool = False
    domain_name: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    registrant_country: str = ""
    registrant_org: str = ""
    dnssec: str = ""
    privacy_protected: bool = False
    domain_age_days: int = 0
    days_until_expiry: int = 0
    issues: list[str] = field(default_factory=list)


def analyze_whois(target: str) -> WhoisReport:
    report = WhoisReport(target=target)

    try:
        w = whois.whois(target)
    except Exception:
        return report

    if not w or not w.domain_name:
        return report

    report.available = True

    if isinstance(w.domain_name, list):
        report.domain_name = w.domain_name[0]
    else:
        report.domain_name = str(w.domain_name or "")

    report.registrar = str(w.registrar or "")

    creation = _parse_date(w.creation_date)
    expiration = _parse_date(w.expiration_date)
    updated = _parse_date(w.updated_date)

    if creation:
        report.creation_date = creation.strftime("%Y-%m-%d")
        now = datetime.now(timezone.utc)
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        report.domain_age_days = (now - creation).days

    if expiration:
        report.expiration_date = expiration.strftime("%Y-%m-%d")
        now = datetime.now(timezone.utc)
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)
        report.days_until_expiry = (expiration - now).days
        if report.days_until_expiry < 30:
            report.issues.append(f"Domain expires in {report.days_until_expiry} days")
        if report.days_until_expiry < 0:
            report.issues.append("Domain has EXPIRED")

    if updated:
        report.updated_date = updated.strftime("%Y-%m-%d")

    if w.name_servers:
        ns = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
        report.name_servers = [str(n).lower().rstrip(".") for n in ns]

    if w.status:
        statuses = w.status if isinstance(w.status, list) else [w.status]
        report.status = [str(s).split()[0] for s in statuses]

    report.registrant_country = str(w.get("country", "") or "")
    report.registrant_org = str(w.get("org", "") or "")
    report.dnssec = str(getattr(w, "dnssec", "") or "")

    org_lower = report.registrant_org.lower()
    privacy_keywords = ["privacy", "proxy", "redacted", "withheld", "gdpr", "protected"]
    report.privacy_protected = any(kw in org_lower for kw in privacy_keywords)

    if report.domain_age_days < 30:
        report.issues.append("Domain is less than 30 days old - potentially suspicious")

    return report


def _parse_date(date_val) -> datetime | None:
    if date_val is None:
        return None
    if isinstance(date_val, list):
        date_val = date_val[0]
    if isinstance(date_val, datetime):
        return date_val
    if isinstance(date_val, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y"):
            try:
                return datetime.strptime(date_val, fmt)
            except ValueError:
                continue
    return None
