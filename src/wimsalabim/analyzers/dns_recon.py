"""DNS reconnaissance and enumeration analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype


@dataclass
class DNSRecord:
    record_type: str
    value: str
    ttl: int = 0


@dataclass
class DNSReport:
    target: str
    records: dict[str, list[DNSRecord]] = field(default_factory=dict)
    nameservers: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    zone_transfer_possible: bool = False
    zone_transfer_ns: list[str] = field(default_factory=list)
    dnssec_enabled: bool = False
    interesting_txt: list[str] = field(default_factory=list)
    total_records: int = 0
    issues: list[str] = field(default_factory=list)

    @property
    def record_types_found(self) -> list[str]:
        return list(self.records.keys())


RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV", "CAA", "PTR"]

INTERESTING_TXT_PATTERNS = [
    "v=spf", "v=dkim", "v=dmarc", "google-site-verification",
    "facebook-domain-verification", "ms=", "docusign", "atlassian",
    "apple-domain-verification", "amazonses", "_github", "stripe",
    "mailchimp", "hubspot", "salesforce",
]


def analyze_dns(target: str) -> DNSReport:
    report = DNSReport(target=target)
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(target, rtype)
            records = []
            for rdata in answers:
                value = rdata.to_text()
                records.append(DNSRecord(
                    record_type=rtype,
                    value=value,
                    ttl=answers.rrset.ttl if answers.rrset else 0,
                ))

                if rtype == "NS":
                    report.nameservers.append(value.rstrip("."))
                elif rtype == "MX":
                    report.mx_records.append(value)
                elif rtype == "TXT":
                    report.txt_records.append(value)
                    _check_interesting_txt(value, report)

            if records:
                report.records[rtype] = records
                report.total_records += len(records)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                Exception):
            continue

    _check_dnssec(target, resolver, report)
    _check_zone_transfer(target, report)

    return report


def _check_interesting_txt(value: str, report: DNSReport) -> None:
    value_lower = value.lower()
    for pattern in INTERESTING_TXT_PATTERNS:
        if pattern in value_lower:
            report.interesting_txt.append(value)
            break


def _check_dnssec(target: str, resolver: dns.resolver.Resolver, report: DNSReport) -> None:
    try:
        resolver.resolve(target, "DNSKEY")
        report.dnssec_enabled = True
    except Exception:
        report.dnssec_enabled = False
        report.issues.append("DNSSEC not enabled")


def _check_zone_transfer(target: str, report: DNSReport) -> None:
    for ns in report.nameservers:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, target, timeout=5))
            if zone:
                report.zone_transfer_possible = True
                report.zone_transfer_ns.append(ns)
                report.issues.append(f"Zone transfer possible via {ns}")
        except Exception:
            continue
