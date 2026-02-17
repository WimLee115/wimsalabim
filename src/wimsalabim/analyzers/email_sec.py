"""Email security analyzer - SPF, DKIM, DMARC."""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.resolver


@dataclass
class SPFResult:
    found: bool = False
    record: str = ""
    mechanism: str = ""
    includes: list[str] = field(default_factory=list)
    all_qualifier: str = ""
    issues: list[str] = field(default_factory=list)
    grade: str = "F"


@dataclass
class DMARCResult:
    found: bool = False
    record: str = ""
    policy: str = ""
    subdomain_policy: str = ""
    percentage: int = 100
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    grade: str = "F"


@dataclass
class DKIMResult:
    found: bool = False
    selectors_checked: list[str] = field(default_factory=list)
    selectors_found: list[str] = field(default_factory=list)
    records: dict[str, str] = field(default_factory=dict)
    grade: str = "F"


@dataclass
class EmailSecReport:
    target: str
    spf: SPFResult = field(default_factory=SPFResult)
    dmarc: DMARCResult = field(default_factory=DMARCResult)
    dkim: DKIMResult = field(default_factory=DKIMResult)
    has_mx: bool = False
    grade: str = "F"
    issues: list[str] = field(default_factory=list)


COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3",
    "mail", "email", "dkim", "s1", "s2", "mx", "smtp", "mandrill",
    "everlytickey1", "everlytickey2", "protonmail", "protonmail2",
    "protonmail3", "cm", "postmark", "zendesk1", "zendesk2",
    "mxvault", "ses", "amazonses",
]


def analyze_email_security(target: str) -> EmailSecReport:
    report = EmailSecReport(target=target)
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    try:
        resolver.resolve(target, "MX")
        report.has_mx = True
    except Exception:
        report.has_mx = False

    _analyze_spf(target, resolver, report)
    _analyze_dmarc(target, resolver, report)
    _analyze_dkim(target, resolver, report)

    scores = []
    if report.spf.found:
        scores.append({"A": 100, "B": 75, "C": 50, "D": 25, "F": 0}[report.spf.grade])
    if report.dmarc.found:
        scores.append({"A": 100, "B": 75, "C": 50, "D": 25, "F": 0}[report.dmarc.grade])
    if report.dkim.found:
        scores.append({"A": 100, "B": 75, "C": 50, "D": 25, "F": 0}[report.dkim.grade])

    if not scores:
        report.grade = "F"
        report.issues.append("No email security records found")
    else:
        avg = sum(scores) / len(scores)
        if avg >= 85:
            report.grade = "A"
        elif avg >= 70:
            report.grade = "B"
        elif avg >= 50:
            report.grade = "C"
        elif avg >= 30:
            report.grade = "D"
        else:
            report.grade = "F"

    return report


def _analyze_spf(target: str, resolver: dns.resolver.Resolver, report: EmailSecReport) -> None:
    try:
        answers = resolver.resolve(target, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                report.spf.found = True
                report.spf.record = txt
                _parse_spf(txt, report.spf)
                return
    except Exception:
        pass
    report.spf.issues.append("No SPF record found")
    report.issues.append("Missing SPF record")


def _parse_spf(record: str, spf: SPFResult) -> None:
    parts = record.split()
    for part in parts:
        p = part.lower()
        if p.startswith("include:"):
            spf.includes.append(part[8:])
        elif p in ("+all", "~all", "-all", "?all"):
            spf.all_qualifier = p

    if spf.all_qualifier == "-all":
        spf.grade = "A"
    elif spf.all_qualifier == "~all":
        spf.grade = "B"
        spf.issues.append("SPF uses softfail (~all) instead of hardfail (-all)")
    elif spf.all_qualifier == "?all":
        spf.grade = "D"
        spf.issues.append("SPF uses neutral (?all) - provides no protection")
    elif spf.all_qualifier == "+all":
        spf.grade = "F"
        spf.issues.append("SPF allows ALL senders (+all) - DANGEROUS")
    else:
        spf.grade = "C"
        spf.issues.append("No 'all' mechanism found in SPF")


def _analyze_dmarc(target: str, resolver: dns.resolver.Resolver, report: EmailSecReport) -> None:
    try:
        answers = resolver.resolve(f"_dmarc.{target}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=dmarc1"):
                report.dmarc.found = True
                report.dmarc.record = txt
                _parse_dmarc(txt, report.dmarc)
                return
    except Exception:
        pass
    report.dmarc.issues.append("No DMARC record found")
    report.issues.append("Missing DMARC record")


def _parse_dmarc(record: str, dmarc: DMARCResult) -> None:
    parts = record.split(";")
    for part in parts:
        kv = part.strip().lower().split("=", 1)
        if len(kv) != 2:
            continue
        key, value = kv[0].strip(), kv[1].strip()

        if key == "p":
            dmarc.policy = value
        elif key == "sp":
            dmarc.subdomain_policy = value
        elif key == "pct":
            try:
                dmarc.percentage = int(value)
            except ValueError:
                pass
        elif key == "rua":
            dmarc.rua = [v.strip() for v in value.split(",")]
        elif key == "ruf":
            dmarc.ruf = [v.strip() for v in value.split(",")]

    if dmarc.policy == "reject":
        dmarc.grade = "A"
    elif dmarc.policy == "quarantine":
        dmarc.grade = "B"
    elif dmarc.policy == "none":
        dmarc.grade = "D"
        dmarc.issues.append("DMARC policy is 'none' - only monitoring, no enforcement")
    else:
        dmarc.grade = "F"

    if dmarc.percentage < 100:
        dmarc.issues.append(f"DMARC only applies to {dmarc.percentage}% of messages")
    if not dmarc.rua:
        dmarc.issues.append("No aggregate reporting (rua) configured")


def _analyze_dkim(target: str, resolver: dns.resolver.Resolver, report: EmailSecReport) -> None:
    report.dkim.selectors_checked = COMMON_DKIM_SELECTORS[:]

    for selector in COMMON_DKIM_SELECTORS:
        try:
            answers = resolver.resolve(f"{selector}._domainkey.{target}", "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if "v=dkim1" in txt.lower() or "p=" in txt.lower():
                    report.dkim.found = True
                    report.dkim.selectors_found.append(selector)
                    report.dkim.records[selector] = txt
        except Exception:
            continue

    if report.dkim.found:
        if len(report.dkim.selectors_found) >= 2:
            report.dkim.grade = "A"
        else:
            report.dkim.grade = "B"
    else:
        report.dkim.grade = "F"
        report.dkim.issues = ["No DKIM records found for common selectors"]
        report.issues.append("No DKIM records found")
