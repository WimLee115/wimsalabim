"""Sitemap.xml and robots.txt deep crawler and analyzer. rootmap:WimLee115"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests


@dataclass
class SitemapEntry:
    url: str
    lastmod: str = ""
    changefreq: str = ""
    priority: str = ""


@dataclass
class RobotsRule:
    user_agent: str
    directive: str
    path: str


@dataclass
class SitemapReport:
    target: str
    available: bool = False
    sitemap_found: bool = False
    sitemap_url: str = ""
    sitemap_count: int = 0
    entries: list[SitemapEntry] = field(default_factory=list)
    robots_found: bool = False
    robots_rules: list[RobotsRule] = field(default_factory=list)
    disallowed_paths: list[str] = field(default_factory=list)
    sensitive_disallowed: list[str] = field(default_factory=list)
    sitemap_references: list[str] = field(default_factory=list)
    exposed_paths: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    grade: str = "N/A"

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    @property
    def disallowed_count(self) -> int:
        return len(self.disallowed_paths)


SENSITIVE_PATH_PATTERNS = [
    r"/admin", r"/login", r"/dashboard", r"/api", r"/internal",
    r"/backup", r"/config", r"/database", r"/db", r"/debug",
    r"/staging", r"/test", r"/dev", r"/private", r"/secret",
    r"/\.env", r"/\.git", r"/wp-admin", r"/phpmy", r"/server-status",
    r"/cgi-bin", r"/console", r"/manager", r"/portal", r"/panel",
]


def analyze_sitemap(target: str) -> SitemapReport:
    report = SitemapReport(target=target)

    _check_robots_txt(target, report)
    _check_sitemap(target, report)
    _analyze_findings(report)

    if report.sitemap_found or report.robots_found:
        report.available = True

    _calculate_grade(report)

    return report


def _check_robots_txt(target: str, report: SitemapReport) -> None:
    url = f"https://{target}/robots.txt"
    try:
        resp = requests.get(
            url, timeout=10, verify=False,
            headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
        )

        if resp.status_code != 200 or not resp.text.strip():
            return

        report.robots_found = True
        _parse_robots(resp.text, report)

    except requests.RequestException:
        pass


def _parse_robots(content: str, report: SitemapReport) -> None:
    current_ua = "*"

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(":", 1)
        if len(parts) != 2:
            continue

        directive = parts[0].strip().lower()
        value = parts[1].strip()

        if directive == "user-agent":
            current_ua = value
        elif directive == "disallow" and value:
            report.robots_rules.append(RobotsRule(
                user_agent=current_ua,
                directive="Disallow",
                path=value,
            ))
            report.disallowed_paths.append(value)
        elif directive == "allow" and value:
            report.robots_rules.append(RobotsRule(
                user_agent=current_ua,
                directive="Allow",
                path=value,
            ))
        elif directive == "sitemap":
            report.sitemap_references.append(value)


def _check_sitemap(target: str, report: SitemapReport) -> None:
    sitemap_urls = list(report.sitemap_references)
    if not sitemap_urls:
        sitemap_urls = [
            f"https://{target}/sitemap.xml",
            f"https://{target}/sitemap_index.xml",
            f"https://{target}/sitemap.xml.gz",
        ]

    for url in sitemap_urls[:5]:
        try:
            resp = requests.get(
                url, timeout=10, verify=False,
                headers={"User-Agent": "Wimsalabim/0.1 Security Scanner"},
            )

            if resp.status_code == 200 and ("<?xml" in resp.text[:100] or "<urlset" in resp.text[:500]):
                report.sitemap_found = True
                report.sitemap_url = url
                _parse_sitemap(resp.text, report)
                break

        except requests.RequestException:
            continue


def _parse_sitemap(content: str, report: SitemapReport) -> None:
    try:
        content = re.sub(r'xmlns=["\'][^"\']*["\']', '', content)
        root = ET.fromstring(content)

        if root.tag.endswith("sitemapindex") or "sitemapindex" in root.tag:
            for sitemap in root.findall(".//sitemap") + root.findall(".//{*}sitemap"):
                loc = sitemap.find("loc")
                if loc is None:
                    loc = sitemap.find("{*}loc")
                if loc is not None and loc.text:
                    report.sitemap_references.append(loc.text)
            report.sitemap_count = len(report.sitemap_references)
            return

        for url_elem in (root.findall(".//url") + root.findall(".//{*}url"))[:200]:
            loc = url_elem.find("loc")
            if loc is None:
                loc = url_elem.find("{*}loc")
            if loc is None or not loc.text:
                continue

            entry = SitemapEntry(url=loc.text)

            lastmod = url_elem.find("lastmod") or url_elem.find("{*}lastmod")
            if lastmod is not None and lastmod.text:
                entry.lastmod = lastmod.text

            changefreq = url_elem.find("changefreq") or url_elem.find("{*}changefreq")
            if changefreq is not None and changefreq.text:
                entry.changefreq = changefreq.text

            priority = url_elem.find("priority") or url_elem.find("{*}priority")
            if priority is not None and priority.text:
                entry.priority = priority.text

            report.entries.append(entry)

        report.sitemap_count = len(report.entries)

    except ET.ParseError:
        pass


def _analyze_findings(report: SitemapReport) -> None:
    for path in report.disallowed_paths:
        for pattern in SENSITIVE_PATH_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                report.sensitive_disallowed.append(path)
                break

    if report.sensitive_disallowed:
        report.issues.append(
            f"robots.txt reveals {len(report.sensitive_disallowed)} sensitive paths"
        )

    for entry in report.entries:
        parsed = urlparse(entry.url)
        path = parsed.path.lower()
        for pattern in SENSITIVE_PATH_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                report.exposed_paths.append(entry.url)
                break

    if report.exposed_paths:
        report.issues.append(
            f"Sitemap exposes {len(report.exposed_paths)} potentially sensitive URLs"
        )

    if not report.robots_found:
        report.issues.append("No robots.txt found")
    if not report.sitemap_found:
        report.issues.append("No sitemap.xml found")

    all_paths = set(report.disallowed_paths)
    if all_paths == {"/"}:
        report.issues.append("robots.txt blocks all crawlers - may hide content")


def _calculate_grade(report: SitemapReport) -> None:
    if not report.available:
        report.grade = "N/A"
        return

    score = 70

    if report.robots_found:
        score += 10
    if report.sitemap_found:
        score += 10

    score -= len(report.sensitive_disallowed) * 3
    score -= len(report.exposed_paths) * 2

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
