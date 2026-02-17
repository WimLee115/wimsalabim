"""Subdomain discovery analyzer."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

import dns.resolver
import requests


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "imap", "cpanel", "whm", "webdisk", "autodiscover",
    "autoconfig", "m", "mobile", "blog", "shop", "store", "api", "dev",
    "staging", "test", "beta", "admin", "portal", "vpn", "remote", "git",
    "gitlab", "jenkins", "ci", "cd", "jira", "confluence", "wiki",
    "docs", "doc", "help", "support", "status", "monitor", "grafana",
    "prometheus", "kibana", "elastic", "db", "database", "mysql", "postgres",
    "redis", "mongo", "cdn", "static", "assets", "media", "img", "images",
    "video", "files", "download", "upload", "app", "apps", "web", "www2",
    "old", "new", "legacy", "backup", "bak", "temp", "demo", "sandbox",
    "proxy", "gateway", "lb", "load", "edge", "node", "worker", "queue",
    "mq", "rabbitmq", "kafka", "cache", "memcached", "search", "solr",
    "elk", "log", "logs", "syslog", "auth", "oauth", "sso", "login",
    "signup", "register", "account", "accounts", "billing", "pay",
    "payment", "checkout", "cart", "crm", "erp", "hr", "intranet",
    "internal", "corp", "office", "exchange", "owa", "mx", "relay",
    "smtp2", "imap2", "pop3", "ns", "dns", "dns1", "dns2", "ntp",
    "time", "cloud", "aws", "azure", "gcp", "s3", "storage",
]


@dataclass
class Subdomain:
    hostname: str
    ip_address: str = ""
    cname: str = ""
    http_status: int = 0
    https_available: bool = False
    title: str = ""


@dataclass
class SubdomainReport:
    target: str
    subdomains_found: list[Subdomain] = field(default_factory=list)
    subdomains_checked: int = 0
    crt_sh_results: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

    @property
    def found_count(self) -> int:
        return len(self.subdomains_found)


def discover_subdomains(
    target: str,
    wordlist: list[str] | None = None,
    use_crtsh: bool = True,
    check_http: bool = True,
) -> SubdomainReport:
    report = SubdomainReport(target=target)
    words = wordlist or COMMON_SUBDOMAINS
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    found_hosts: set[str] = set()

    if use_crtsh:
        _query_crtsh(target, report, found_hosts)

    for sub in words:
        hostname = f"{sub}.{target}"
        report.subdomains_checked += 1

        if hostname in found_hosts:
            continue

        try:
            answers = resolver.resolve(hostname, "A")
            ip = answers[0].to_text()
            subdomain = Subdomain(hostname=hostname, ip_address=ip)

            try:
                cname_answers = resolver.resolve(hostname, "CNAME")
                subdomain.cname = cname_answers[0].to_text().rstrip(".")
            except Exception:
                pass

            if check_http:
                _check_http(subdomain)

            report.subdomains_found.append(subdomain)
            found_hosts.add(hostname)
        except Exception:
            continue

    _analyze_findings(report)
    return report


def _query_crtsh(target: str, report: SubdomainReport, found_hosts: set[str]) -> None:
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{target}&output=json",
            timeout=10,
            headers={"User-Agent": "Wimsalabim/0.1"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for hostname in name.split("\n"):
                    hostname = hostname.strip().lower()
                    if hostname and "*" not in hostname and hostname not in found_hosts:
                        report.crt_sh_results.append(hostname)
                        found_hosts.add(hostname)

                        try:
                            ip = socket.gethostbyname(hostname)
                            subdomain = Subdomain(hostname=hostname, ip_address=ip)
                            report.subdomains_found.append(subdomain)
                        except socket.gaierror:
                            pass
    except Exception:
        pass


def _check_http(subdomain: Subdomain) -> None:
    for scheme in ("https", "http"):
        try:
            resp = requests.head(
                f"{scheme}://{subdomain.hostname}",
                timeout=3, allow_redirects=False, verify=False,
            )
            subdomain.http_status = resp.status_code
            if scheme == "https":
                subdomain.https_available = True
            break
        except Exception:
            continue


def _analyze_findings(report: SubdomainReport) -> None:
    sensitive_names = {"admin", "jenkins", "gitlab", "jira", "vpn", "internal",
                       "staging", "dev", "test", "backup", "db", "database"}

    for sub in report.subdomains_found:
        parts = sub.hostname.split(".")
        if parts[0] in sensitive_names:
            report.issues.append(
                f"Sensitive subdomain exposed: {sub.hostname} ({sub.ip_address})"
            )
