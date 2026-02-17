"""Subdomain takeover vulnerability detection. rootmap:WimLee115"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

import dns.resolver
import requests


@dataclass
class TakeoverCandidate:
    subdomain: str
    cname: str = ""
    provider: str = ""
    status: str = "unknown"
    vulnerable: bool = False
    confidence: float = 0.0
    evidence: str = ""


@dataclass
class SubdomainTakeoverReport:
    target: str
    subdomains_checked: int = 0
    candidates: list[TakeoverCandidate] = field(default_factory=list)
    vulnerable: list[TakeoverCandidate] = field(default_factory=list)
    dangling_cnames: list[TakeoverCandidate] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"

    @property
    def vulnerable_count(self) -> int:
        return len(self.vulnerable)

    @property
    def dangling_count(self) -> int:
        return len(self.dangling_cnames)


TAKEOVER_SIGNATURES = {
    "github.io": {
        "provider": "GitHub Pages",
        "cname_match": ["github.io"],
        "fingerprint": ["There isn't a GitHub Pages site here", "For root URLs"],
        "nxdomain": False,
    },
    "herokuapp.com": {
        "provider": "Heroku",
        "cname_match": ["herokuapp.com", "herokussl.com"],
        "fingerprint": ["No such app", "no-such-app"],
        "nxdomain": True,
    },
    "s3.amazonaws.com": {
        "provider": "AWS S3",
        "cname_match": ["s3.amazonaws.com", "s3-website"],
        "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"],
        "nxdomain": True,
    },
    "cloudfront.net": {
        "provider": "AWS CloudFront",
        "cname_match": ["cloudfront.net"],
        "fingerprint": ["Bad request", "ERROR: The request could not be satisfied"],
        "nxdomain": False,
    },
    "azurewebsites.net": {
        "provider": "Azure",
        "cname_match": ["azurewebsites.net", "cloudapp.azure.com", "azure-api.net",
                         "azurefd.net", "blob.core.windows.net", "trafficmanager.net"],
        "fingerprint": ["404 Web Site not found", "Web App - Pair With App Service"],
        "nxdomain": True,
    },
    "pantheonsite.io": {
        "provider": "Pantheon",
        "cname_match": ["pantheonsite.io"],
        "fingerprint": ["404 error unknown site", "The gods are wise"],
        "nxdomain": False,
    },
    "shopify.com": {
        "provider": "Shopify",
        "cname_match": ["myshopify.com", "shopify.com"],
        "fingerprint": ["Sorry, this shop is currently unavailable", "Only one step left"],
        "nxdomain": False,
    },
    "ghost.io": {
        "provider": "Ghost",
        "cname_match": ["ghost.io"],
        "fingerprint": ["The thing you were looking for is no longer here"],
        "nxdomain": True,
    },
    "surge.sh": {
        "provider": "Surge.sh",
        "cname_match": ["surge.sh"],
        "fingerprint": ["project not found"],
        "nxdomain": True,
    },
    "netlify.app": {
        "provider": "Netlify",
        "cname_match": ["netlify.app", "netlify.com"],
        "fingerprint": ["Not Found - Request ID"],
        "nxdomain": False,
    },
    "fly.dev": {
        "provider": "Fly.io",
        "cname_match": ["fly.dev", "edgeapp.net"],
        "fingerprint": ["404 Not Found"],
        "nxdomain": True,
    },
    "unbouncepages.com": {
        "provider": "Unbounce",
        "cname_match": ["unbouncepages.com"],
        "fingerprint": ["The requested URL was not found on this server"],
        "nxdomain": True,
    },
    "zendesk.com": {
        "provider": "Zendesk",
        "cname_match": ["zendesk.com"],
        "fingerprint": ["Help Center Closed"],
        "nxdomain": False,
    },
    "readme.io": {
        "provider": "ReadMe",
        "cname_match": ["readme.io"],
        "fingerprint": ["Project doesnt exist"],
        "nxdomain": True,
    },
    "bitbucket.io": {
        "provider": "Bitbucket",
        "cname_match": ["bitbucket.io"],
        "fingerprint": ["Repository not found"],
        "nxdomain": False,
    },
}


def check_subdomain_takeover(
    target: str,
    subdomains: list[str] | None = None,
) -> SubdomainTakeoverReport:
    report = SubdomainTakeoverReport(target=target)

    if subdomains is None:
        subdomains = _get_default_subdomains(target)

    report.subdomains_checked = len(subdomains)

    for subdomain in subdomains:
        _check_subdomain(subdomain, report)

    report.vulnerable = [c for c in report.candidates if c.vulnerable]
    report.dangling_cnames = [c for c in report.candidates if c.status == "dangling"]

    if report.vulnerable:
        report.issues.append(
            f"{report.vulnerable_count} subdomain(s) vulnerable to takeover"
        )

    if report.dangling_cnames:
        report.issues.append(
            f"{report.dangling_count} dangling CNAME record(s) detected"
        )

    _calculate_grade(report)

    return report


def _get_default_subdomains(target: str) -> list[str]:
    common = [
        "www", "mail", "blog", "shop", "store", "api", "dev", "staging",
        "test", "beta", "demo", "docs", "help", "support", "status",
        "cdn", "media", "assets", "static", "img", "images", "app",
        "portal", "admin", "dashboard", "go", "link", "links",
    ]
    return [f"{sub}.{target}" for sub in common]


def _check_subdomain(subdomain: str, report: SubdomainTakeoverReport) -> None:
    cname = _resolve_cname(subdomain)
    if not cname:
        return

    candidate = TakeoverCandidate(subdomain=subdomain, cname=cname)

    for _sig_key, sig in TAKEOVER_SIGNATURES.items():
        if any(match in cname.lower() for match in sig["cname_match"]):
            candidate.provider = sig["provider"]

            resolves = _resolves_to_ip(cname)

            if not resolves and sig["nxdomain"]:
                candidate.vulnerable = True
                candidate.status = "dangling"
                candidate.confidence = 0.9
                candidate.evidence = f"CNAME {cname} does not resolve (NXDOMAIN)"
            elif resolves:
                body = _fetch_body(subdomain)
                if body and any(fp.lower() in body.lower() for fp in sig["fingerprint"]):
                    candidate.vulnerable = True
                    candidate.status = "takeover_possible"
                    candidate.confidence = 0.85
                    candidate.evidence = f"Fingerprint match for {sig['provider']}"
                else:
                    candidate.status = "active"
            else:
                candidate.status = "dangling"
                candidate.confidence = 0.6
                candidate.evidence = f"CNAME to {sig['provider']} but unresolvable"

            report.candidates.append(candidate)
            return

    resolves = _resolves_to_ip(cname)
    if not resolves:
        candidate.status = "dangling"
        candidate.confidence = 0.5
        candidate.evidence = f"Dangling CNAME: {cname} does not resolve"
        report.candidates.append(candidate)


def _resolve_cname(hostname: str) -> str:
    try:
        answers = dns.resolver.resolve(hostname, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.Timeout,
            Exception):
        pass
    return ""


def _resolves_to_ip(hostname: str) -> bool:
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False


def _fetch_body(hostname: str) -> str:
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{hostname}", timeout=5,
                allow_redirects=True, verify=False,
                headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
            )
            return resp.text[:10000]
        except requests.RequestException:
            continue
    return ""


def _calculate_grade(report: SubdomainTakeoverReport) -> None:
    if report.subdomains_checked == 0:
        report.grade = "N/A"
        return

    if report.vulnerable_count == 0 and report.dangling_count == 0:
        report.grade = "A"
    elif report.vulnerable_count == 0 and report.dangling_count <= 2:
        report.grade = "B"
    elif report.vulnerable_count <= 1:
        report.grade = "C"
    elif report.vulnerable_count <= 3:
        report.grade = "D"
    else:
        report.grade = "F"
